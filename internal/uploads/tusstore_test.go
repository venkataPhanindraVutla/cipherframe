package uploads

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/tus/tusd/v2/pkg/handler"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/httpx"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// A raw object-store error carries the bucket, the key and often a URL. tusd copies err.Error()
// into the response body and into its log, so the store must never hand one over.
func TestTusErrorsAreSanitised(t *testing.T) {
	var logs bytes.Buffer
	ctx := httpx.WithLogger(context.Background(), slog.New(slog.NewTextHandler(&logs, nil)))
	s := &TusStore{}

	raw := fmt.Errorf(`operation error S3: UploadPart, https response error StatusCode: 404, `+
		`Get "https://s3.internal/secret-bucket/t/ten_x/a/ast_y/source/abcdef?X-Amz-Signature=sig": %w`, io.ErrUnexpectedEOF)
	got := s.fail(ctx, "tus_write_chunk", raw)
	if got.Error() != "storage error" {
		t.Fatalf("the error text leaks: %q", got.Error())
	}
	if !errors.Is(got, io.ErrUnexpectedEOF) {
		t.Fatal("tusd's errors.Is checks no longer see the cause")
	}
	for _, banned := range []string{"secret-bucket", "ten_x", "abcdef", "X-Amz", "s3.internal"} {
		if strings.Contains(logs.String(), banned) {
			t.Fatalf("the log line leaks %q: %s", banned, logs.String())
		}
	}
	if logs.Len() == 0 {
		t.Fatal("the failure was not logged at all")
	}

	// tusd's own protocol errors pass through unchanged, so clients keep their status codes.
	if !errors.Is(s.fail(ctx, "x", handler.ErrNotFound), handler.ErrNotFound) {
		t.Fatal("a tusd protocol error was rewritten")
	}
	wrapped := fmt.Errorf("while reading: %w", handler.ErrUploadInterrupted)
	var he handler.Error
	if err := s.fail(ctx, "x", wrapped); !errors.As(err, &he) || he.ErrorCode != handler.ErrUploadInterrupted.ErrorCode {
		t.Fatalf("a wrapped protocol error became %v", err)
	}
	if s.fail(ctx, "x", nil) != nil {
		t.Fatal("nil must stay nil")
	}

	// Whatever tusError gets, only fixed texts reach a response.
	for _, in := range []error{raw, errs.New(errs.InternalError, "database error"), errors.New("pq: password for user bob")} {
		out := tusError(in).Error()
		for _, banned := range []string{"secret-bucket", "password", "bob", "database"} {
			if strings.Contains(out, banned) {
				t.Errorf("tusError leaks %q: %q", banned, out)
			}
		}
	}
	if !errors.Is(tusError(errs.New(errs.NotFound, "resource not found")), handler.ErrNotFound) {
		t.Error("not_found should become the tus not-found error")
	}
}

func TestTusPreCreate(t *testing.T) {
	s := &TusStore{limits: Limits{MaxSourceBytes: 1000, PartBytes: MinPartBytes}}
	asset := db.Asset{
		ID: id.New[id.AssetKind](), State: db.AssetCreated, UploadMethod: db.UploadTus, SizeBytes: 500,
		SourceKey: "t/ten/a/ast/source/0123", ContentType: "video/mp4",
	}
	hook := func(g *Grant, size int64, deferred bool) handler.HookEvent {
		ctx := context.Background()
		if g != nil {
			ctx = WithGrant(ctx, *g)
		}
		return handler.HookEvent{Context: ctx, Upload: handler.FileInfo{
			Size: size, SizeIsDeferred: deferred,
			MetaData: handler.MetaData{"filename": "holiday.mp4", "filetype": "text/html"},
		}}
	}
	status := func(err error) int {
		var he handler.Error
		if errors.As(err, &he) {
			return he.HTTPResponse.StatusCode
		}
		return 0
	}

	_, ch, err := s.PreCreate(hook(&Grant{Asset: asset}, 500, false))
	if err != nil {
		t.Fatal(err)
	}
	if ch.ID != asset.SourceKey {
		t.Fatalf("the upload ID is %q, want the asset's source key", ch.ID)
	}
	if len(ch.MetaData) != 1 || ch.MetaData["filetype"] != "video/mp4" {
		t.Fatalf("metadata %v: client metadata (file names, types) must be dropped", ch.MetaData)
	}
	if strings.HasPrefix(ch.ID, "/") || strings.HasSuffix(ch.ID, "/") || strings.ContainsAny(ch.ID, " ?#") {
		t.Fatalf("tusd would reject the ID %q", ch.ID)
	}

	noType := asset
	noType.ContentType = ""
	if _, ch, _ := s.PreCreate(hook(&Grant{Asset: noType}, 500, false)); len(ch.MetaData) != 0 {
		t.Fatalf("metadata %v without a content type", ch.MetaData)
	}

	multipart, started, withUpload, wrongState := asset, asset, asset, asset
	multipart.UploadMethod = db.UploadMultipart
	started.State = db.AssetUploading
	withUpload.S3UploadID = "mp"
	wrongState.State = db.AssetFailed
	for name, tc := range map[string]struct {
		g        *Grant
		size     int64
		deferred bool
		want     int
	}{
		"no grant":          {nil, 500, false, http.StatusUnauthorized},
		"multipart asset":   {&Grant{Asset: multipart}, 500, false, http.StatusConflict},
		"already uploading": {&Grant{Asset: started}, 500, false, http.StatusConflict},
		"has an upload ID":  {&Grant{Asset: withUpload}, 500, false, http.StatusConflict},
		"failed asset":      {&Grant{Asset: wrongState}, 500, false, http.StatusConflict},
		"smaller length":    {&Grant{Asset: asset}, 499, false, http.StatusBadRequest},
		"larger length":     {&Grant{Asset: asset}, 501, false, http.StatusBadRequest},
		"deferred length":   {&Grant{Asset: asset}, 0, true, http.StatusBadRequest},
	} {
		if _, _, err := s.PreCreate(hook(tc.g, tc.size, tc.deferred)); status(err) != tc.want {
			t.Errorf("%s: status %d (%v), want %d", name, status(err), err, tc.want)
		}
	}
	over := asset
	over.SizeBytes = 2000 // above the limit in force now
	if _, _, err := s.PreCreate(hook(&Grant{Asset: over}, 2000, false)); status(err) != http.StatusBadRequest {
		t.Errorf("over the limit: %v", err)
	}
}

// The key tusd is given must sit under the asset's source prefix, so deletion by prefix covers
// the upload object, its .info object and its .part object.
func TestTusKeyIsUnderTheSourcePrefix(t *testing.T) {
	tn, a := id.New[id.TenantKind](), id.New[id.AssetKind]()
	key := keys.NewSource(tn, a)
	for _, suffix := range []string{"", ".info", ".part"} {
		covered := false
		for _, p := range keys.AssetPrefixes(tn, a) {
			if p.Bucket == keys.Source && strings.HasPrefix(key+suffix, p.Prefix) {
				covered = true
			}
		}
		if !covered {
			t.Errorf("%q is not covered by keys.AssetPrefixes", key+suffix)
		}
	}
}
