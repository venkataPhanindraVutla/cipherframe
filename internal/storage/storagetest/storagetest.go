// Package storagetest is the conformance suite for storage.Store implementations (ADR 0014). It
// proves that an adapter and the store behind it agree on the behaviour Cipherframe depends on.
// Run it against a local SeaweedFS in CI and, opt-in, against real S3 or R2.
package storagetest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
)

const opTimeout = 2 * time.Minute

// Run executes the suite. newStore returns a store on an existing, empty-enough bucket; it is called
// once per subtest. Each subtest works under its own random prefix and deletes it afterwards.
func Run(t *testing.T, newStore func(t *testing.T) storage.Store) {
	t.Helper()
	cases := []struct {
		name string
		fn   func(t *testing.T, s storage.Store, p string)
	}{
		{"PutGetHead", testPutGetHead},
		{"PutStreamWithoutSeek", testPutStream},
		{"GetRange", testGetRange},
		{"NotFoundMapping", testNotFound},
		{"ListPagination", testListPagination},
		{"DeleteBatch1005", testDeleteBatchLarge},
		{"PresignedGet", testPresignedGet},
		{"PresignedPut", testPresignedPut},
		{"PresignedGetExpires", testPresignedExpiry},
		{"MultipartViaPresignedParts", testMultipart},
		{"MultipartAbort", testMultipartAbort},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newStore(t)
			p := uniquePrefix(t)
			t.Cleanup(func() { cleanup(t, s, p) })
			c.fn(t, s, p)
		})
	}
}

func ctxFor(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	t.Cleanup(cancel)
	return ctx
}

func uniquePrefix(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "conformance/" + hex.EncodeToString(b[:]) + "/"
}

func cleanup(t *testing.T, s storage.Store, prefix string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	var keys []string
	for o, err := range storage.ListAll(ctx, s, prefix) {
		if err != nil {
			t.Logf("cleanup list: %v", err)
			return
		}
		keys = append(keys, o.Key)
	}
	if err := s.DeleteBatch(ctx, keys); err != nil {
		t.Logf("cleanup delete: %v", err)
	}
}

func payload(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func readAll(t *testing.T, rc io.ReadCloser) []byte {
	t.Helper()
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return b
}

func mustPut(t *testing.T, s storage.Store, key string, data []byte, ct string) {
	t.Helper()
	if err := s.Put(ctxFor(t), key, bytes.NewReader(data), int64(len(data)), ct); err != nil {
		t.Fatalf("put: %v", err)
	}
}

func mustGetAll(t *testing.T, s storage.Store, key string) []byte {
	t.Helper()
	rc, _, err := s.Get(ctxFor(t), key, nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	return readAll(t, rc)
}

// roundTrip sends a presigned request with a plain net/http client: no SDK, no credentials.
func roundTrip(t *testing.T, p storage.PresignedRequest, body []byte) (int, []byte, http.Header) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctxFor(t), p.Method, p.URL, rdr)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	for k, vs := range p.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		// The URL is a bearer token: report the failure without it.
		t.Fatalf("presigned %s failed: %v", p.Method, errors.Unwrap(err))
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp.StatusCode, b, resp.Header
}

func testPutGetHead(t *testing.T, s storage.Store, p string) {
	key := p + "a.txt"
	data := []byte("hello, conformance")
	mustPut(t, s, key, data, "text/plain")

	rc, info, err := s.Get(ctxFor(t), key, nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got := readAll(t, rc); !bytes.Equal(got, data) {
		t.Fatalf("body = %q", got)
	}
	if info.Size != int64(len(data)) || info.ContentType != "text/plain" || info.ETag == "" || info.Key != key {
		t.Fatalf("get info = %+v", info)
	}
	h, err := s.Head(ctxFor(t), key)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if h.Size != int64(len(data)) || h.ContentType != "text/plain" || h.ETag != info.ETag || h.LastModified.IsZero() {
		t.Fatalf("head info = %+v", h)
	}

	mustPut(t, s, p+"empty", nil, "")
	if got := mustGetAll(t, s, p+"empty"); len(got) != 0 {
		t.Fatalf("empty object body = %d bytes", len(got))
	}
	// Overwrite.
	mustPut(t, s, key, []byte("v2"), "text/plain")
	if got := mustGetAll(t, s, key); string(got) != "v2" {
		t.Fatalf("overwrite = %q", got)
	}
}

func testPutStream(t *testing.T, s storage.Store, p string) {
	data := payload(t, 300*1024)
	// io.MultiReader is not an io.Seeker: the adapter must stream it.
	body := io.MultiReader(bytes.NewReader(data))
	if err := s.Put(ctxFor(t), p+"stream", body, int64(len(data)), "application/octet-stream"); err != nil {
		t.Fatalf("put from one-way stream: %v", err)
	}
	if got := mustGetAll(t, s, p+"stream"); sha256.Sum256(got) != sha256.Sum256(data) {
		t.Fatal("streamed body differs")
	}
}

func testGetRange(t *testing.T, s storage.Store, p string) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	key := p + "range"
	mustPut(t, s, key, data, "application/octet-stream")
	for _, tc := range []struct {
		name string
		r    storage.Range
		want []byte
	}{
		{"middle", storage.Range{Offset: 10, Length: 5}, data[10:15]},
		{"first byte", storage.Range{Offset: 0, Length: 1}, data[0:1]},
		{"to end", storage.Range{Offset: 250}, data[250:]},
		{"past end is clamped", storage.Range{Offset: 250, Length: 100}, data[250:]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.r
			rc, info, err := s.Get(ctxFor(t), key, &r)
			if err != nil {
				t.Fatalf("ranged get: %v", err)
			}
			if got := readAll(t, rc); !bytes.Equal(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
			if info.Size != int64(len(data)) {
				t.Fatalf("info.Size = %d, want the whole object size %d", info.Size, len(data))
			}
		})
	}
	t.Run("unsatisfiable", func(t *testing.T) {
		_, _, err := s.Get(ctxFor(t), key, &storage.Range{Offset: 1000, Length: 5})
		if err == nil {
			t.Fatal("range beyond the object must fail")
		}
		if errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("an unsatisfiable range must not look like a missing object: %v", err)
		}
	})
}

func testNotFound(t *testing.T, s storage.Store, p string) {
	key := p + "does-not-exist"
	_, _, err := s.Get(ctxFor(t), key, nil)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	_, err = s.Head(ctxFor(t), key)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("head missing: %v", err)
	}
	if errors.Is(err, storage.ErrOther) {
		t.Fatal("a not-found error must not also match Other")
	}
	// Deleting a missing key is not an error.
	if err := s.DeleteBatch(ctxFor(t), []string{key}); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
}

func testListPagination(t *testing.T, s storage.Store, p string) {
	const n = 25
	var want []string
	for i := 0; i < n; i++ {
		k := fmt.Sprintf("%sl/%03d", p, i)
		want = append(want, k)
		mustPut(t, s, k, []byte{byte(i)}, "")
	}
	mustPut(t, s, p+"other/x", []byte("x"), "")

	var got []string
	cursor, pages := "", 0
	for {
		page, err := s.List(ctxFor(t), p+"l/", cursor, 10)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		pages++
		if len(page.Objects) > 10 {
			t.Fatalf("page has %d objects, limit was 10", len(page.Objects))
		}
		for _, o := range page.Objects {
			if o.Size != 1 || o.ETag == "" {
				t.Fatalf("list entry lacks size or ETag: %+v", o)
			}
			got = append(got, o.Key)
		}
		if page.NextCursor == "" {
			break
		}
		if pages > 10 {
			t.Fatal("pagination does not terminate")
		}
		cursor = page.NextCursor
	}
	if pages < 3 {
		t.Fatalf("want at least 3 pages for 25 objects at limit 10, got %d", pages)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("listed keys differ:\n got %v\nwant %v", got, want)
	}

	var viaIter []string
	for o, err := range storage.ListAll(ctxFor(t), s, p+"l/") {
		if err != nil {
			t.Fatalf("ListAll: %v", err)
		}
		viaIter = append(viaIter, o.Key)
	}
	if fmt.Sprint(viaIter) != fmt.Sprint(want) {
		t.Fatalf("ListAll differs from paging")
	}

	// Stopping early must not leak or error.
	for _, err := range storage.ListAll(ctxFor(t), s, p) {
		if err != nil {
			t.Fatalf("ListAll (early stop): %v", err)
		}
		break
	}

	empty, err := s.List(ctxFor(t), p+"nothing-here/", "", 10)
	if err != nil || len(empty.Objects) != 0 || empty.NextCursor != "" {
		t.Fatalf("empty listing: %+v %v", empty, err)
	}
}

// putMany writes n one-byte objects under prefix with bounded concurrency.
func putMany(t *testing.T, s storage.Store, prefix string, n int) []string {
	t.Helper()
	keys := make([]string, n)
	for i := range keys {
		keys[i] = prefix + strconv.Itoa(i)
	}
	ctx := ctxFor(t)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	errc := make(chan error, n)
	for _, k := range keys {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if err := s.Put(ctx, k, bytes.NewReader([]byte("x")), 1, ""); err != nil {
				errc <- err
			}
		}()
	}
	wg.Wait()
	close(errc)
	if err := <-errc; err != nil {
		t.Fatalf("put many: %v", err)
	}
	return keys
}

func testDeleteBatchLarge(t *testing.T, s storage.Store, p string) {
	const n = 1005 // more than one DeleteObjects request
	keys := putMany(t, s, p+"d/", n)
	keep := p + "keep"
	mustPut(t, s, keep, []byte("k"), "")

	// A key that never existed in the middle of the batch is not an error.
	batch := append(append([]string{}, keys[:500]...), p+"d/never-existed")
	batch = append(batch, keys[500:]...)
	if err := s.DeleteBatch(ctxFor(t), batch); err != nil {
		t.Fatalf("delete batch: %v", err)
	}
	var left []string
	for o, err := range storage.ListAll(ctxFor(t), s, p+"d/") {
		if err != nil {
			t.Fatalf("list after delete: %v", err)
		}
		left = append(left, o.Key)
	}
	if len(left) != 0 {
		sort.Strings(left)
		t.Fatalf("%d objects survived the batch delete", len(left))
	}
	if _, err := s.Head(ctxFor(t), keep); err != nil {
		t.Fatalf("an unrelated object was deleted: %v", err)
	}
	if err := s.DeleteBatch(ctxFor(t), nil); err != nil {
		t.Fatalf("empty delete: %v", err)
	}
}

func testPresignedGet(t *testing.T, s storage.Store, p string) {
	key := p + "presigned-get"
	data := payload(t, 4096)
	mustPut(t, s, key, data, "application/octet-stream")
	req, err := s.PresignGet(ctxFor(t), key, time.Minute)
	if err != nil {
		t.Fatalf("presign get: %v", err)
	}
	status, body, _ := roundTrip(t, req, nil)
	if status != http.StatusOK || !bytes.Equal(body, data) {
		t.Fatalf("plain HTTP GET: status %d, %d bytes", status, len(body))
	}
	// The signature covers the key: another object must not be readable with this URL's signature.
	missing, err := s.PresignGet(ctxFor(t), p+"presigned-missing", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if status, _, _ := roundTrip(t, missing, nil); status != http.StatusNotFound {
		t.Fatalf("presigned GET of a missing key: status %d, want 404", status)
	}
}

func testPresignedPut(t *testing.T, s storage.Store, p string) {
	key := p + "presigned-put"
	data := payload(t, 8192)
	req, err := s.PresignPut(ctxFor(t), key, time.Minute, "image/png")
	if err != nil {
		t.Fatalf("presign put: %v", err)
	}
	if req.Method != http.MethodPut {
		t.Fatalf("method = %s", req.Method)
	}
	status, _, _ := roundTrip(t, req, data)
	if status != http.StatusOK {
		t.Fatalf("plain HTTP PUT: status %d", status)
	}
	got, info, err := s.Get(ctxFor(t), key, nil)
	if err != nil {
		t.Fatalf("get after presigned put: %v", err)
	}
	if body := readAll(t, got); !bytes.Equal(body, data) {
		t.Fatal("uploaded body differs")
	}
	if info.ContentType != "image/png" {
		t.Fatalf("content type = %q", info.ContentType)
	}
}

func testPresignedExpiry(t *testing.T, s storage.Store, p string) {
	key := p + "presigned-expiry"
	mustPut(t, s, key, []byte("soon gone"), "")
	req, err := s.PresignGet(ctxFor(t), key, time.Second)
	if err != nil {
		t.Fatalf("presign: %v", err)
	}
	time.Sleep(3 * time.Second)
	status, _, _ := roundTrip(t, req, nil)
	if status != http.StatusForbidden {
		t.Fatalf("expired URL: status %d, want 403", status)
	}
}

func etagOf(h http.Header) string { return h.Get("ETag") }

func testMultipart(t *testing.T, s storage.Store, p string) {
	key := p + "multipart"
	const partSize = 5 * 1024 * 1024 // the S3 minimum for every part but the last
	parts := [][]byte{payload(t, partSize), payload(t, partSize), payload(t, 1234)}

	uploadID, err := s.CreateMultipart(ctxFor(t), key, "video/mp4")
	if err != nil {
		t.Fatalf("create multipart: %v", err)
	}
	var done []storage.CompletedPart
	for i, data := range parts {
		num := int32(i + 1)
		req, err := s.PresignPart(ctxFor(t), key, uploadID, num, 5*time.Minute)
		if err != nil {
			t.Fatalf("presign part %d: %v", num, err)
		}
		status, _, h := roundTrip(t, req, data)
		if status != http.StatusOK || etagOf(h) == "" {
			t.Fatalf("upload part %d: status %d, etag %q", num, status, etagOf(h))
		}
		done = append(done, storage.CompletedPart{PartNumber: num, ETag: etagOf(h)})
	}
	if err := s.CompleteMultipart(ctxFor(t), key, uploadID, done); err != nil {
		t.Fatalf("complete: %v", err)
	}
	want := bytes.Join(parts, nil)
	info, err := s.Head(ctxFor(t), key)
	if err != nil || info.Size != int64(len(want)) || info.ContentType != "video/mp4" {
		t.Fatalf("head after complete: %+v %v", info, err)
	}
	if got := mustGetAll(t, s, key); sha256.Sum256(got) != sha256.Sum256(want) {
		t.Fatal("assembled object differs from the uploaded parts")
	}
}

func testMultipartAbort(t *testing.T, s storage.Store, p string) {
	key := p + "aborted"
	uploadID, err := s.CreateMultipart(ctxFor(t), key, "")
	if err != nil {
		t.Fatalf("create multipart: %v", err)
	}
	req, err := s.PresignPart(ctxFor(t), key, uploadID, 1, time.Minute)
	if err != nil {
		t.Fatalf("presign part: %v", err)
	}
	status, _, h := roundTrip(t, req, payload(t, 1024))
	if status != http.StatusOK {
		t.Fatalf("upload part: status %d", status)
	}
	if err := s.AbortMultipart(ctxFor(t), key, uploadID); err != nil {
		t.Fatalf("abort: %v", err)
	}
	// An aborted upload cannot be completed, and no object appears.
	err = s.CompleteMultipart(ctxFor(t), key, uploadID, []storage.CompletedPart{{PartNumber: 1, ETag: etagOf(h)}})
	if err == nil {
		t.Fatal("completing an aborted upload succeeded")
	}
	if _, err := s.Head(ctxFor(t), key); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("aborted upload left an object: %v", err)
	}
}
