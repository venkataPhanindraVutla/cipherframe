package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/apiclient"
)

const (
	tusVersion    = "1.0.0"
	tusChunkBytes = 8 << 20
	tusMaxRetries = 5 // consecutive failures without progress before giving up
)

// tusBackoff is the pause before retry n (0-based); a variable so tests can shorten it.
var tusBackoff = func(n int) time.Duration { return min(500*time.Millisecond<<n, 8*time.Second) }

// videoTypes covers the extensions the platform's MIME table often lacks.
var videoTypes = map[string]string{
	".mp4": "video/mp4", ".m4v": "video/mp4", ".mov": "video/quicktime",
	".mkv": "video/x-matroska", ".webm": "video/webm", ".avi": "video/x-msvideo",
}

var uploadCommand = command{
	name: "upload", synopsis: "upload FILE [--wait] [--mask-faces] [--ttl 720h] [flags]",
	help: "Create an asset and upload FILE to it with the resumable tus protocol through the edge, then\n" +
		"commit it, which queues processing. An interrupted transfer resumes from the server's offset\n" +
		"(a few retries with backoff). Only the size and a content type are sent, never the file name.\n" +
		"Prints the asset ID on stdout (the asset document with --json). With --wait, polls until the\n" +
		"asset is ready (exit 8 if it fails or the wait times out). The upload token is never shown.\n" +
		"If the commit is refused after the bytes arrived, fix the cause and run: cipherframe process ID.",
	setup: func(fs *flag.FlagSet) func(*cli, []string) error {
		w := addWaitFlags(fs)
		mask := fs.Bool("mask-faces", false, "also build a variant with every detected face blurred")
		ttl := fs.String("ttl", "", "delete the asset after this long, such as 24h or 30d (default: the tenant's setting)")
		ctype := fs.String("content-type", "", "media type to send (default: from the file extension)")
		return func(c *cli, pos []string) error {
			file, err := onePositional(pos, "file")
			if err != nil {
				return err
			}
			c.idOnly = true
			req := apiclient.CreateAssetRequest{UploadMethod: apiclient.UploadMethod("tus")}
			if *mask {
				req.MaskFaces = mask
			}
			if *ttl != "" {
				secs, err := parseTTL(*ttl)
				if err != nil {
					return err
				}
				req.TtlSeconds = &secs
			}
			if t := contentType(file, *ctype); t != "" {
				req.ContentType = &t
			}
			f, err := os.Open(file) //nolint:gosec // the user names the file to upload
			if err != nil {
				return usageErr("%v", errors.Unwrap(err))
			}
			defer func() { _ = f.Close() }()
			st, err := f.Stat()
			if err != nil || !st.Mode().IsRegular() || st.Size() == 0 {
				return usageErr("the upload source must be a non-empty regular file")
			}
			req.SizeBytes = st.Size()

			ctx, cancel := c.ctx(context.Background(), 1)
			resp, err := c.api.CreateAsset(ctx, req)
			var created apiclient.CreatedAsset
			_, err = c.finish(resp, err, &created)
			cancel()
			if err != nil {
				return err
			}
			c.secrets = append(c.secrets, created.Upload.Token)
			id := created.Asset.Id
			c.diag("created %s; uploading %d bytes", id, req.SizeBytes)
			if err := c.tusUpload(context.Background(), f, req.SizeBytes, created.Upload); err != nil {
				var ce *cliError
				if asCLIError(err, &ce) {
					ce.msg += " (asset " + id + " was created; abort it through the API or let it expire)"
				}
				return err
			}
			ctx, cancel = c.ctx(context.Background(), 1)
			resp, err = c.api.CommitAsset(ctx, id)
			var a apiclient.Asset
			raw, err := c.finish(resp, err, &a)
			cancel()
			if err != nil {
				var ce *cliError
				if asCLIError(err, &ce) {
					ce.msg += " (the bytes are uploaded: retry with cipherframe process " + id + ")"
				}
				return err
			}
			c.diag("committed %s", id)
			return c.finishAsset(a, raw, w)
		}
	},
}

func contentType(file, override string) string {
	t := override
	if t == "" {
		ext := strings.ToLower(filepath.Ext(file))
		if t = videoTypes[ext]; t == "" {
			t = mime.TypeByExtension(ext)
		}
	}
	if m, _, err := mime.ParseMediaType(t); err == nil {
		return strings.ToLower(m)
	}
	return ""
}

// parseTTL reads a duration such as 90m, 24h or 30d into whole seconds.
func parseTTL(s string) (int, error) {
	var d time.Duration
	var err error
	if days, ok := strings.CutSuffix(s, "d"); ok {
		var n int
		if n, err = strconv.Atoi(days); err == nil {
			d = time.Duration(n) * 24 * time.Hour
		}
	} else {
		d, err = time.ParseDuration(s)
	}
	if err != nil || d < time.Minute || d > 3650*24*time.Hour {
		return 0, usageErr("--ttl must be between 1m and 3650d, such as 24h or 30d")
	}
	return int(d / time.Second), nil
}

// tusUpload sends f (size bytes) to the tus endpoint in inst: create, then PATCH chunks from the
// server's offset, re-reading the offset with HEAD after any failure. It uses only the standard
// library (ADR 0051). The token goes to the creation host only: a Location on another host is refused.
func (c *cli) tusUpload(parent context.Context, f *os.File, size int64, inst apiclient.UploadInstructions) error {
	base, err := url.Parse(inst.Url)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return &cliError{code: exitAPI, kind: "bad_response", msg: "the server gave no usable upload URL"}
	}
	// send makes one tus request, reads and closes the answer and returns its headers, or the
	// problem when the status is not one of want.
	send := func(method, target string, mult int, body io.Reader, length int64, hdr map[string]string, want int) (http.Header, error) {
		ctx, cancel := c.ctx(parent, mult)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, method, target, body)
		if err != nil {
			return nil, c.netErr(err)
		}
		if body != nil {
			req.ContentLength = length
		}
		req.Header.Set("Authorization", "Bearer "+inst.Token)
		req.Header.Set("Tus-Resumable", tusVersion)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := c.hc.Do(req) //nolint:gosec // the target is the edge URL the API returned, checked above
		if err != nil {
			return nil, c.netErr(err)
		}
		defer func() { _ = resp.Body.Close() }()
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode != want {
			return nil, c.problemErr(resp.StatusCode, msg)
		}
		return resp.Header, nil
	}

	h, err := send(http.MethodPost, base.String(), 1, nil, 0, map[string]string{"Upload-Length": strconv.FormatInt(size, 10)}, http.StatusCreated)
	if err != nil {
		return err
	}
	loc, err := base.Parse(h.Get("Location"))
	if err != nil || h.Get("Location") == "" || loc.Host != base.Host || loc.Scheme != base.Scheme {
		return &cliError{code: exitAPI, kind: "bad_response", msg: "the server gave no usable upload location"}
	}
	target := loc.String()

	offset, failures, needSync := int64(0), 0, false
	for offset < size {
		var err error
		conflict := false
		if needSync {
			var h http.Header
			if h, err = send(http.MethodHead, target, 1, nil, 0, nil, http.StatusOK); err == nil {
				got, perr := strconv.ParseInt(h.Get("Upload-Offset"), 10, 64)
				if perr != nil || got < 0 || got > size {
					return &cliError{code: exitAPI, kind: "bad_response", msg: "the server reported an unusable upload offset"}
				}
				offset, needSync = got, false
				continue
			}
		} else {
			n := min(size-offset, tusChunkBytes)
			var h http.Header
			h, err = send(http.MethodPatch, target, 5, io.NewSectionReader(f, offset, n), n, map[string]string{
				"Content-Type": "application/offset+octet-stream", "Upload-Offset": strconv.FormatInt(offset, 10),
			}, http.StatusNoContent)
			if err == nil {
				next, perr := strconv.ParseInt(h.Get("Upload-Offset"), 10, 64)
				if perr != nil || next != offset+n {
					return &cliError{code: exitAPI, kind: "bad_response", msg: "the server acknowledged an unexpected upload offset"}
				}
				offset, failures = next, 0
				c.diag("uploaded %d of %d bytes", offset, size)
				continue
			}
			// A 409 means the offset moved (for example a chunk landed whose answer was lost): ask the server.
			var ce *cliError
			conflict = asCLIError(err, &ce) && ce.code == exitConflict
		}
		if !retryable(err) && !conflict {
			return err
		}
		if failures++; failures > tusMaxRetries {
			return err
		}
		if !needSync {
			c.diag("upload interrupted (%v); resuming from the server's offset", err)
			needSync = true
		}
		time.Sleep(tusBackoff(failures - 1))
	}
	return nil
}

// retryable is true for failures a retry can fix: no answer, or the server being unavailable.
func retryable(err error) bool {
	var ce *cliError
	return asCLIError(err, &ce) && ce.code == exitUnavailable
}
