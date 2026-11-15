//go:build integration

package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/branding"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

type brandRig struct {
	*harness
	store *memStore
}

func newBrandRig(t *testing.T) *brandRig {
	t.Helper()
	store := &memStore{objs: map[string][]byte{}}
	h := newHarnessWith(t, func(d *api.Deps, h *harness) {
		svc, err := branding.New(branding.Deps{Pool: h.pool, Delivery: store, Now: h.clk.Now})
		if err != nil {
			t.Fatal(err)
		}
		d.Branding = svc
	})
	return &brandRig{harness: h, store: store}
}

func logoPNG(t *testing.T, w, h int, extra ...func([]byte) []byte) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = 10, 120, 200, 255
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	out := b.Bytes()
	for _, f := range extra {
		out = f(out)
	}
	return out
}

// withText inserts a ready-made chunk right after the header chunk.
func withText(chunk []byte) func([]byte) []byte {
	return func(p []byte) []byte {
		const afterIHDR = 8 + 12 + 13
		return append(append(append([]byte(nil), p[:afterIHDR]...), chunk...), p[afterIHDR:]...)
	}
}

// textChunk is a tEXt chunk with a valid CRC.
func textChunk(text string) []byte {
	data := []byte("Comment\x00" + text)
	var b bytes.Buffer
	n := uint32(len(data)) //nolint:gosec // small test data
	b.Write([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	body := append([]byte("tEXt"), data...)
	b.Write(body)
	crc := crc32IEEE(body)
	b.Write([]byte{byte(crc >> 24), byte(crc >> 16), byte(crc >> 8), byte(crc)})
	return b.Bytes()
}

func crc32IEEE(b []byte) uint32 {
	crc := ^uint32(0)
	for _, c := range b {
		crc ^= uint32(c)
		for range 8 {
			if crc&1 == 1 {
				crc = crc>>1 ^ 0xedb88320
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

// put sends the multipart form of PUT /v1/brand/logo.
func (r *brandRig) put(key string, parts ...formPart) resp {
	r.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, p := range parts {
		h := textproto.MIMEHeader{}
		disp := fmt.Sprintf(`form-data; name=%q`, p.name)
		if p.filename != "" {
			disp += fmt.Sprintf(`; filename=%q`, p.filename)
		}
		h.Set("Content-Disposition", disp)
		w, err := mw.CreatePart(h)
		if err != nil {
			r.t.Fatal(err)
		}
		_, _ = io.WriteString(w, p.value)
	}
	_ = mw.Close()
	return r.rawPut(key, mw.FormDataContentType(), buf.Bytes())
}

func (r *brandRig) rawPut(key, contentType string, body []byte) resp {
	r.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, r.srv.URL+"/v1/brand/logo", bytes.NewReader(body))
	if err != nil {
		r.t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rs, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = rs.Body.Close() }()
	raw, _ := io.ReadAll(rs.Body)
	return parseResp(rs, raw)
}

func parseResp(rs *http.Response, raw []byte) resp {
	out := resp{status: rs.StatusCode, hdr: rs.Header, raw: raw}
	_ = json.Unmarshal(raw, &out.m)
	return out
}

func logoForm(file []byte, extra ...formPart) []formPart {
	return append([]formPart{{"file", "secret-brand-name.png", string(file)}}, extra...)
}

func TestBrandLogoLifecycle(t *testing.T) {
	r := newBrandRig(t)
	admin, res := r.bootstrap("acme")

	r.wantStatus(r.do(admin, "GET", "/v1/brand/logo", nil), 404, "not_found")
	r.wantStatus(r.do(admin, "DELETE", "/v1/brand/logo", nil), 404, "not_found")
	r.wantStatus(r.do(admin, "PATCH", "/v1/brand/logo", map[string]any{"opacity_percent": 50}), 404, "not_found")

	// Upload with a text chunk and a client-chosen file name: both are gone from what is stored.
	up := logoPNG(t, 200, 100, withText(textChunk("test-fixture-secret-comment")))
	got := r.mustOK(r.put(admin, logoForm(up, formPart{"corner", "", "top_left"}, formPart{"opacity", "", "40"})...), 200)
	if got.m["corner"] != "top_left" || got.m["opacity_percent"] != float64(40) || got.m["enabled"] != true ||
		got.m["width"] != float64(200) || got.m["height"] != float64(100) {
		t.Fatalf("put = %s", got.raw)
	}
	version, err := id.Parse[id.LogoVersionKind](str(got.m, "version"))
	if err != nil {
		t.Fatal(err)
	}
	stored, ok := r.store.get(keys.BrandLogo(res.Tenant.ID, version))
	if !ok {
		t.Fatalf("the logo is not in the delivery bucket: %v", r.store.keys())
	}
	if sum := sha256.Sum256(stored); got.m["sha256"] != hex.EncodeToString(sum[:]) || got.m["size_bytes"] != float64(len(stored)) {
		t.Errorf("hash or size does not describe the stored file: %s", got.raw)
	}
	if bytes.Contains(stored, []byte("test-fixture-secret-comment")) || bytes.Contains(stored, []byte("tEXt")) {
		t.Error("the text chunk of the upload was stored")
	}
	for _, leak := range []string{"secret-brand-name", "t/ten_", "branding/"} {
		if strings.Contains(string(got.raw), leak) || strings.Contains(r.logs.String(), leak) {
			t.Errorf("%q leaked into a response or the log", leak)
		}
	}

	// Get returns the same, never the image.
	if cur := r.mustOK(r.do(admin, "GET", "/v1/brand/logo", nil), 200); cur.m["version"] != got.m["version"] || cur.m["sha256"] != got.m["sha256"] {
		t.Fatalf("get = %s", cur.raw)
	}

	// Placement changes keep the version.
	upd := r.mustOK(r.do(admin, "PATCH", "/v1/brand/logo", map[string]any{"corner": "bottom_left", "enabled": false}), 200)
	if upd.m["corner"] != "bottom_left" || upd.m["enabled"] != false || upd.m["opacity_percent"] != float64(40) || upd.m["version"] != got.m["version"] {
		t.Fatalf("patch = %s", upd.raw)
	}
	for _, bad := range []map[string]any{{"corner": "middle"}, {"opacity_percent": 9}, {"opacity_percent": 101}} {
		r.wantStatus(r.do(admin, "PATCH", "/v1/brand/logo", bad), 400, "invalid_request")
	}

	// A new upload is a new version; the old object is removed, and defaults apply.
	second := r.mustOK(r.put(admin, logoForm(logoPNG(t, 64, 64))...), 200)
	if second.m["version"] == got.m["version"] || second.m["corner"] != "bottom_right" || second.m["opacity_percent"] != float64(100) || second.m["enabled"] != true {
		t.Fatalf("second = %s", second.raw)
	}
	if _, still := r.store.get(keys.BrandLogo(res.Tenant.ID, version)); still || len(r.store.keys()) != 1 {
		t.Errorf("objects after the second upload: %v", r.store.keys())
	}

	// Delete.
	r.mustOK(r.do(admin, "DELETE", "/v1/brand/logo", nil), 204)
	r.wantStatus(r.do(admin, "GET", "/v1/brand/logo", nil), 404, "not_found")
	if len(r.store.keys()) != 0 {
		t.Errorf("objects left after the delete: %v", r.store.keys())
	}
}

func TestBrandLogoUploadIsValidatedBeforeAnythingIsStored(t *testing.T) {
	r := newBrandRig(t)
	admin, _ := r.bootstrap("acme")
	good := logoPNG(t, 64, 64)
	animated := withText([]byte{0, 0, 0, 8, 'a', 'c', 'T', 'L', 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0})(good)

	for name, tc := range map[string]struct {
		parts  []formPart
		status int
		code   string
	}{
		"text called .png":     {logoForm([]byte("hello"), formPart{"corner", "", "top_left"}), 400, "invalid_request"},
		"truncated":            {logoForm(good[:len(good)/2]), 400, "invalid_request"},
		"animated":             {logoForm(animated), 400, "invalid_request"},
		"1025 pixels":          {logoForm(logoPNG(t, 1025, 16)), 400, "invalid_request"},
		"too small":            {logoForm(logoPNG(t, 8, 8)), 400, "invalid_request"},
		"over 256 KB":          {logoForm(bytes.Repeat([]byte{7}, branding.MaxBytes+1)), 413, "payload_too_large"},
		"no file":              {[]formPart{{"corner", "", "top_left"}}, 400, "invalid_request"},
		"two files":            {append(logoForm(good), formPart{"file", "", string(good)}), 400, "invalid_request"},
		"unknown member":       {logoForm(good, formPart{"url", "", "http://example.com"}), 400, "invalid_request"},
		"bad corner":           {logoForm(good, formPart{"corner", "", "centre"}), 400, "invalid_request"},
		"opacity 9":            {logoForm(good, formPart{"opacity", "", "9"}), 400, "invalid_request"},
		"opacity 101":          {logoForm(good, formPart{"opacity", "", "101"}), 400, "invalid_request"},
		"opacity not a number": {logoForm(good, formPart{"opacity", "", "half"}), 400, "invalid_request"},
		"enabled not a bool":   {logoForm(good, formPart{"enabled", "", "yes"}), 400, "invalid_request"},
	} {
		t.Run(name, func(t *testing.T) {
			r.wantStatus(r.put(admin, tc.parts...), tc.status, tc.code)
		})
	}
	if len(r.store.keys()) != 0 {
		t.Errorf("refused uploads left objects: %v", r.store.keys())
	}
	r.wantStatus(r.do(admin, "GET", "/v1/brand/logo", nil), 404, "not_found")
	if strings.Contains(r.logs.String(), "secret-brand-name") {
		t.Error("an uploaded file name reached the log")
	}

	// A body far over the cap is cut off before it is read in full.
	huge := bytes.Repeat([]byte{1}, 4<<20)
	if rs := r.put(admin, logoForm(huge)...); rs.status != 413 {
		t.Errorf("a 4 MB body: status %d", rs.status)
	}

	// Not a multipart form at all.
	r.wantStatus(r.rawPut(admin, "application/json", []byte(`{}`)), 400, "invalid_request")
}

func TestBrandLogoNeedsTheAdminScope(t *testing.T) {
	r := newBrandRig(t)
	admin, res := r.bootstrap("acme")
	reader := str(r.newKey(admin, res.Client.ID.String(), "reader", []string{"assets:read"}).m, "key")
	writer := str(r.newKey(admin, res.Client.ID.String(), "writer", []string{"assets:write"}).m, "key")
	form := logoForm(logoPNG(t, 64, 64))
	r.wantStatus(r.put("", form...), 401, "unauthenticated")
	for _, k := range []string{reader, writer} {
		r.wantStatus(r.put(k, form...), 403, "forbidden")
		r.wantStatus(r.do(k, "GET", "/v1/brand/logo", nil), 403, "forbidden")
		r.wantStatus(r.do(k, "PATCH", "/v1/brand/logo", map[string]any{"enabled": false}), 403, "forbidden")
		r.wantStatus(r.do(k, "DELETE", "/v1/brand/logo", nil), 403, "forbidden")
	}
	if len(r.store.keys()) != 0 {
		t.Error("a forbidden upload stored something")
	}
}

func TestBrandLogoIsPerTenant(t *testing.T) {
	r := newBrandRig(t)
	acme, acmeRes := r.bootstrap("acme")
	other, otherRes := r.bootstrap("other")
	up := r.mustOK(r.put(acme, logoForm(logoPNG(t, 64, 64))...), 200)

	r.wantStatus(r.do(other, "GET", "/v1/brand/logo", nil), 404, "not_found")
	r.wantStatus(r.do(other, "PATCH", "/v1/brand/logo", map[string]any{"enabled": false}), 404, "not_found")
	r.wantStatus(r.do(other, "DELETE", "/v1/brand/logo", nil), 404, "not_found")
	if cur := r.mustOK(r.do(acme, "GET", "/v1/brand/logo", nil), 200); cur.m["enabled"] != true || cur.m["version"] != up.m["version"] {
		t.Fatalf("acme's logo changed: %s", cur.raw)
	}

	// The other tenant uploads the identical picture: a separate version in its own prefix.
	theirs := r.mustOK(r.put(other, logoForm(logoPNG(t, 64, 64))...), 200)
	if theirs.m["version"] == up.m["version"] {
		t.Error("two tenants share a version")
	}
	var prefixes [2]int
	for _, k := range r.store.keys() {
		switch {
		case strings.HasPrefix(k, keys.BrandLogoPrefix(acmeRes.Tenant.ID)):
			prefixes[0]++
		case strings.HasPrefix(k, keys.BrandLogoPrefix(otherRes.Tenant.ID)):
			prefixes[1]++
		}
	}
	if prefixes != [2]int{1, 1} {
		t.Errorf("objects per tenant prefix = %v, want 1 and 1", prefixes)
	}
	r.mustOK(r.do(other, "DELETE", "/v1/brand/logo", nil), 204)
	r.mustOK(r.do(acme, "GET", "/v1/brand/logo", nil), 200)
}

func TestBrandLogoIsUnavailableWithoutTheService(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.bootstrap("acme")
	h.wantStatus(h.do(admin, "GET", "/v1/brand/logo", nil), 503, "dependency_unavailable")
}
