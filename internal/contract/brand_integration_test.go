//go:build integration

package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/png"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/branding"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/storagetest"
)

// TestBrandLogoOperationsMatchSpec drives the four brand logo operations through the real handler
// chain, a real database and a real object store, and validates every request and response (200,
// 204 and the error statuses) against the spec.
func TestBrandLogoOperationsMatchSpec(t *testing.T) {
	doc := loadSpec(t)
	ctx := context.Background()
	pool := dbtest.NewMigrated(t)
	repos := db.New(pool)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	buckets, err := storage.New(ctx, storagetest.Shared(t).Config())
	if err != nil {
		t.Fatal(err)
	}
	svc, err := branding.New(branding.Deps{Pool: pool, Delivery: buckets.Delivery})
	if err != nil {
		t.Fatal(err)
	}
	am := auth.NewManager(pool, onePepper{}, nil)
	res, err := am.Bootstrap(ctx, "contract", "contract client")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.New(api.Deps{
		Log: log, Verifier: auth.NewVerifier(repos, onePepper{}, log, nil), Manager: am, Branding: svc,
	}).Handler())
	t.Cleanup(srv.Close)

	hdr := map[string]string{"Authorization": "Bearer " + res.Secret.Reveal()}
	covered := map[string]bool{}
	call := func(method, ctype string, body []byte, wantStatus int) []byte {
		t.Helper()
		h := map[string]string{"Authorization": hdr["Authorization"]}
		if ctype != "" {
			h["Content-Type"] = ctype
		}
		ex := doBody(t, srv.URL, method, "/v1/brand/logo", h, body)
		if ex.resp.StatusCode != wantStatus {
			t.Fatalf("%s /v1/brand/logo: status %d, want %d: %s", method, ex.resp.StatusCode, wantStatus, ex.body)
		}
		if op := validate(t, doc, ex); op != "" && wantStatus < 300 {
			covered[op] = true
		}
		return ex.body
	}
	form := func(file []byte, extra ...[2]string) (string, []byte) {
		const b = "contractboundary"
		var buf bytes.Buffer
		buf.WriteString("--" + b + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x.png\"\r\n\r\n")
		buf.Write(file)
		buf.WriteString("\r\n")
		for _, p := range extra {
			buf.WriteString("--" + b + "\r\nContent-Disposition: form-data; name=\"" + p[0] + "\"\r\n\r\n" + p[1] + "\r\n")
		}
		buf.WriteString("--" + b + "--\r\n")
		return "multipart/form-data; boundary=" + b, buf.Bytes()
	}
	logo := func(w, h int) []byte {
		img := image.NewNRGBA(image.Rect(0, 0, w, h))
		for i := range img.Pix {
			img.Pix[i] = 200
		}
		var b bytes.Buffer
		if err := png.Encode(&b, img); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	json1 := func(v any) []byte { b, _ := json.Marshal(v); return b }

	// No logo yet: valid 404 problems.
	call("GET", "", nil, 404)
	call("DELETE", "", nil, 404)
	call("PATCH", "application/json", json1(map[string]any{"enabled": false}), 404)

	ct, body := form(logo(80, 40), [2]string{"corner", "top_left"}, [2]string{"opacity", "55"}, [2]string{"enabled", "true"})
	var got struct {
		Version, Corner string
		OpacityPercent  int `json:"opacity_percent"`
	}
	if err := json.Unmarshal(call("PUT", ct, body, 200), &got); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got.Version, "lgo_") || got.Corner != "top_left" || got.OpacityPercent != 55 {
		t.Fatalf("put = %+v", got)
	}
	call("GET", "", nil, 200)
	call("PATCH", "application/json", json1(map[string]any{"corner": "bottom_right", "opacity_percent": 90, "enabled": false}), 200)

	// Error statuses are valid Problems.
	ct, body = form([]byte("not a png"))
	call("PUT", ct, body, 400)
	ct, body = form(logo(80, 40), [2]string{"opacity", "5"})
	call("PUT", ct, body, 400)
	ct, body = form(bytes.Repeat([]byte{1}, branding.MaxBytes+1))
	call("PUT", ct, body, 413)

	call("DELETE", "", nil, 204)
	call("GET", "", nil, 404)

	for _, op := range []string{"getBrandLogo", "putBrandLogo", "updateBrandLogo", "deleteBrandLogo"} {
		if !covered[op] {
			t.Errorf("%s was not exercised with a 2xx response", op)
		}
	}
}
