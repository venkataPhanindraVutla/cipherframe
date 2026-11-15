//go:build integration

package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
	"github.com/venkataPhanindraVutla/cipherframe/internal/subtitles"
)

// memStore is an in-memory delivery bucket: just the calls the subtitle service makes.
type memStore struct {
	storage.Store
	mu   sync.Mutex
	objs map[string][]byte
	// failPut makes Put fail, to prove a failed change leaves nothing behind.
	failPut bool
}

func (m *memStore) Put(_ context.Context, key string, body io.Reader, _ int64, _ string) error {
	b, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failPut {
		return storage.Sanitize("put", keys.Delivery, io.ErrUnexpectedEOF)
	}
	m.objs[key] = b
	return nil
}

func (m *memStore) DeleteBatch(_ context.Context, ks []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range ks {
		delete(m.objs, k)
	}
	return nil
}

func (m *memStore) keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.objs {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func (m *memStore) get(key string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objs[key]
	return b, ok
}

type subtitleRig struct {
	*harness
	store *memStore
}

const readyDurationMS = 600_000 // ten minutes

func newSubtitleRig(t *testing.T) *subtitleRig {
	t.Helper()
	store := &memStore{objs: map[string][]byte{}}
	h := newHarnessWith(t, func(d *api.Deps, h *harness) {
		svc, err := subtitles.New(subtitles.Deps{Pool: h.pool, Delivery: store, Signer: h.signing, Now: h.clk.Now})
		if err != nil {
			t.Fatal(err)
		}
		d.Subtitles = svc
	})
	return &subtitleRig{harness: h, store: store}
}

// readyAsset is a ready asset with a manifest and a duration, as processing leaves it.
func (r *subtitleRig) readyAsset(res auth.BootstrapResult) db.Asset {
	r.t.Helper()
	a, _ := r.readyAssetWithManifest(res, false)
	if _, err := r.pool.Exec(context.Background(), `UPDATE assets SET duration_ms = $1 WHERE id = $2`, readyDurationMS, a.ID.UUID()); err != nil {
		r.t.Fatal(err)
	}
	return a
}

const goodVTT = "WEBVTT\n\n00:00:01.000 --> 00:00:03.000\nHello <i>world</i>\n\n00:00:04.000 --> 00:00:06.000\n<v Ann>Second cue</v>\n"

type formPart struct{ name, filename, value string }

// upload sends the multipart form of POST /v1/assets/{id}/subtitles.
func (r *subtitleRig) upload(key, assetID string, parts ...formPart) resp {
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
	return r.raw(key, "POST", "/v1/assets/"+assetID+"/subtitles", mw.FormDataContentType(), buf.Bytes())
}

func (r *subtitleRig) raw(key, method, path, contentType string, body []byte) resp {
	r.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, r.srv.URL+path, bytes.NewReader(body))
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
	out := resp{status: rs.StatusCode, hdr: rs.Header, raw: raw}
	_ = json.Unmarshal(raw, &out.m)
	return out
}

func vttForm(lang, label, file string, extra ...formPart) []formPart {
	return append([]formPart{{"file", "secret-name.vtt", file}, {"language", "", lang}, {"label", "", label}}, extra...)
}

// signedManifest fetches the manifest through the API and verifies it with the public keys.
func (r *subtitleRig) signedManifest(key string, a db.Asset) *offline.Signed {
	r.t.Helper()
	env := r.mustOK(r.do(key, "GET", "/v1/assets/"+a.ID.String()+"/manifest", nil), 200).raw
	pub, err := r.signing.PublicKeys(context.Background())
	if err != nil {
		r.t.Fatal(err)
	}
	ks := offline.KeySet{}
	for _, k := range pub {
		ks[k.KeyID] = k.PublicKey
	}
	s, err := offline.Open(env, ks)
	if err != nil {
		r.t.Fatalf("the manifest does not verify: %v", err)
	}
	return s
}

func (r *subtitleRig) count(query string, args ...any) int {
	r.t.Helper()
	var n int
	if err := r.pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func TestSubtitleLifecycle(t *testing.T) {
	r := newSubtitleRig(t)
	admin, res := r.bootstrap("acme")
	a := r.readyAsset(res)
	base := "/v1/assets/" + a.ID.String()
	reader := str(r.newKey(admin, res.Client.ID.String(), "reader", []string{"assets:read"}).m, "key")

	before := r.signedManifest(admin, a)
	if len(before.Manifest.Subtitles) != 0 {
		t.Fatal("the manifest has tracks before any was added")
	}

	// A WebVTT upload. The client's file name is not stored anywhere.
	up := r.mustOK(r.upload(admin, a.ID.String(), vttForm("EN", "  English  ", goodVTT, formPart{"default", "", "true"})...), 201)
	if up.m["language"] != "en" || up.m["label"] != "English" || up.m["default"] != true || up.m["origin"] != "upload" || up.m["cue_count"] != float64(2) {
		t.Fatalf("created = %s", up.raw)
	}
	first := str(up.m, "id")
	if strings.Contains(string(up.raw), "secret-name") || strings.Contains(r.logs.String(), "secret-name") {
		t.Error("the uploaded file name was kept")
	}
	trackID, err := id.Parse[id.SubtitleKind](first)
	if err != nil {
		t.Fatal(err)
	}
	stored, ok := r.store.get(keys.Subtitle(res.Tenant.ID, a.ID, trackID))
	if !ok {
		t.Fatalf("the track is not in the delivery bucket: %v", r.store.keys())
	}
	sum := sha256.Sum256(stored)
	if up.m["sha256"] != hex.EncodeToString(sum[:]) || up.m["size_bytes"] != float64(len(stored)) {
		t.Errorf("hash or size does not describe the stored file: %s", up.raw)
	}
	if !strings.HasPrefix(string(stored), "WEBVTT\n\n00:00:01.000 --> 00:00:03.000\nHello <i>world</i>\n") {
		t.Errorf("stored file = %q", stored)
	}
	// Registered with the purge registry (I6).
	arts, err := r.repos.ListArtifacts(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n := countKind(arts, db.ArtifactSubtitle); n != 1 {
		t.Fatalf("%d subtitle registry rows, want 1", n)
	}

	// An SRT upload becomes WebVTT; a second default replaces the first.
	srt := "1\r\n00:00:10,000 --> 00:00:12,500\r\nBonjour\r\n\r\n"
	second := r.mustOK(r.upload(admin, a.ID.String(), vttForm("fr-ca", "Français", srt, formPart{"default", "", "true"})...), 201)
	if second.m["language"] != "fr-CA" || second.m["default"] != true {
		t.Fatalf("second = %s", second.raw)
	}
	secondStored, _ := r.store.get(keys.Subtitle(res.Tenant.ID, a.ID, mustSubtitleID(t, str(second.m, "id"))))
	if string(secondStored) != "WEBVTT\n\n00:00:10.000 --> 00:00:12.500\nBonjour\n\n" {
		t.Errorf("converted = %q", secondStored)
	}

	// List and get.
	list := r.mustOK(r.do(reader, "GET", base+"/subtitles", nil), 200)
	items := list.m["items"].([]any)
	if len(items) != 2 || items[0].(map[string]any)["id"] != first || items[0].(map[string]any)["default"] != false || items[1].(map[string]any)["default"] != true {
		t.Fatalf("list = %s", list.raw)
	}
	got := r.mustOK(r.do(reader, "GET", base+"/subtitles/"+first, nil), 200)
	if got.m["id"] != first || got.m["asset_id"] != a.ID.String() {
		t.Fatalf("get = %s", got.raw)
	}
	if strings.Contains(string(list.raw), "t/ten_") || strings.Contains(string(got.raw), "subtitles/sub_") {
		t.Error("a storage key leaked into a response")
	}

	// The manifest was signed again and records both tracks with the stored hashes.
	after := r.signedManifest(admin, a)
	if len(after.Manifest.Subtitles) != 2 || after.Manifest.TopLevel.Root != before.Manifest.TopLevel.Root {
		t.Fatalf("manifest subtitles = %+v", after.Manifest.Subtitles)
	}
	path := "subtitles/" + first + ".vtt"
	if res := offline.VerifyArtifact(r.manifestEnvelope(admin, a), r.keySet(), path, sha256.Sum256(stored), "original"); res.Outcome != offline.Ours {
		t.Errorf("the stored track does not verify: %+v", res)
	}
	// POST /v1/verify answers for a track by its manifest path: ours for the stored bytes, modified
	// for anything else. There is no proof: tracks are signed by hash, outside the trees.
	v := r.mustOK(r.do(reader, "POST", "/v1/verify", map[string]any{"asset_id": a.ID.String(), "path": path, "sha256": hex.EncodeToString(sum[:])}), 200)
	if v.m["outcome"] != "ours" || v.m["proof"] != nil {
		t.Errorf("verify of the stored track = %s", v.raw)
	}
	v = r.mustOK(r.do(reader, "POST", "/v1/verify", map[string]any{"asset_id": a.ID.String(), "path": path, "sha256": strings.Repeat("0", 64)}), 200)
	if v.m["outcome"] != "modified" {
		t.Errorf("verify of a changed track = %s", v.raw)
	}
	defaults := 0
	for _, s := range after.Manifest.Subtitles {
		if s.Default {
			defaults++
		}
	}
	if defaults != 1 {
		t.Errorf("%d default tracks in the manifest, want 1", defaults)
	}

	// Delete: the object, both rows and the manifest entry go; deleting again is not_found.
	r.mustOK(r.do(admin, "DELETE", base+"/subtitles/"+first, nil), 204)
	if _, ok := r.store.get(keys.Subtitle(res.Tenant.ID, a.ID, trackID)); ok {
		t.Error("the deleted track is still in the delivery bucket")
	}
	r.wantStatus(r.do(reader, "GET", base+"/subtitles/"+first, nil), 404, "not_found")
	r.wantStatus(r.do(admin, "DELETE", base+"/subtitles/"+first, nil), 404, "not_found")
	if m := r.signedManifest(admin, a); len(m.Manifest.Subtitles) != 1 {
		t.Errorf("manifest after delete has %d tracks, want 1", len(m.Manifest.Subtitles))
	}
	if n := r.count(`SELECT count(*) FROM asset_artifacts WHERE asset_id = $1 AND kind = 'subtitle'`, a.ID.UUID()); n != 1 {
		t.Errorf("%d subtitle registry rows after delete, want 1", n)
	}
	r.mustOK(r.do(admin, "DELETE", base+"/subtitles/"+str(second.m, "id"), nil), 204)
	if m := r.signedManifest(admin, a); len(m.Manifest.Subtitles) != 0 {
		t.Errorf("manifest after deleting every track has %d", len(m.Manifest.Subtitles))
	}
	if len(r.store.keys()) != 0 {
		t.Errorf("objects left: %v", r.store.keys())
	}

	// Each change was audited, without content.
	events, _ := r.repos.ListAuditEvents(context.Background(), res.Tenant.ID, nil, 100)
	adds, dels := 0, 0
	for _, e := range events {
		switch e.Action {
		case subtitles.AuditSubtitleAdd:
			adds++
		case subtitles.AuditSubtitleDelete:
			dels++
		}
	}
	if adds != 2 || dels != 2 {
		t.Errorf("audit: %d adds and %d deletes, want 2 and 2", adds, dels)
	}
}

func countKind(arts []db.Artifact, kind db.ArtifactKind) int {
	n := 0
	for _, a := range arts {
		if a.Kind == kind {
			n++
		}
	}
	return n
}

func mustSubtitleID(t *testing.T, s string) id.SubtitleID {
	t.Helper()
	v, err := id.Parse[id.SubtitleKind](s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (r *subtitleRig) manifestEnvelope(key string, a db.Asset) []byte {
	return r.mustOK(r.do(key, "GET", "/v1/assets/"+a.ID.String()+"/manifest", nil), 200).raw
}

func (r *subtitleRig) keySet() offline.KeySet {
	pub, err := r.signing.PublicKeys(context.Background())
	if err != nil {
		r.t.Fatal(err)
	}
	ks := offline.KeySet{}
	for _, k := range pub {
		ks[k.KeyID] = k.PublicKey
	}
	return ks
}

func TestSubtitleScopesAndTenantIsolation(t *testing.T) {
	r := newSubtitleRig(t)
	admin, res := r.bootstrap("acme")
	otherAdmin, otherRes := r.bootstrap("other")
	a := r.readyAsset(res)
	base := "/v1/assets/" + a.ID.String()
	reader := str(r.newKey(admin, res.Client.ID.String(), "reader", []string{"assets:read"}).m, "key")
	writer := str(r.newKey(admin, res.Client.ID.String(), "writer", []string{"assets:write"}).m, "key")
	track := str(r.mustOK(r.upload(admin, a.ID.String(), vttForm("en", "English", goodVTT)...), 201).m, "id")

	// No key: 401. Wrong scope: 403. A body is never decoded before that.
	r.wantStatus(r.upload("", a.ID.String(), vttForm("en", "x", goodVTT)...), 401, "unauthenticated")
	r.wantStatus(r.upload(reader, a.ID.String(), vttForm("en", "x", goodVTT)...), 403, "forbidden")
	r.wantStatus(r.do(writer, "GET", base+"/subtitles", nil), 403, "forbidden")
	r.wantStatus(r.do(writer, "GET", base+"/subtitles/"+track, nil), 403, "forbidden")
	r.wantStatus(r.do(reader, "DELETE", base+"/subtitles/"+track, nil), 403, "forbidden")
	r.wantStatus(r.do(reader, "POST", base+"/transcripts", importBody("en", "x", 1, 2, "t")), 403, "forbidden")
	r.wantStatus(r.do("", "GET", base+"/subtitles", nil), 401, "unauthenticated")

	// Another tenant's key cannot see, read, add to, import into or delete from this asset, and
	// cannot tell it exists.
	r.wantStatus(r.do(otherAdmin, "GET", base+"/subtitles", nil), 404, "not_found")
	r.wantStatus(r.do(otherAdmin, "GET", base+"/subtitles/"+track, nil), 404, "not_found")
	r.wantStatus(r.upload(otherAdmin, a.ID.String(), vttForm("en", "x", goodVTT)...), 404, "not_found")
	r.wantStatus(r.do(otherAdmin, "POST", base+"/transcripts", importBody("en", "x", 1, 2, "t")), 404, "not_found")
	r.wantStatus(r.do(otherAdmin, "DELETE", base+"/subtitles/"+track, nil), 404, "not_found")
	// The other tenant's own asset does not serve this tenant's track ID either.
	b := r.readyAsset(otherRes)
	r.wantStatus(r.do(otherAdmin, "GET", "/v1/assets/"+b.ID.String()+"/subtitles/"+track, nil), 404, "not_found")
	r.wantStatus(r.do(otherAdmin, "DELETE", "/v1/assets/"+b.ID.String()+"/subtitles/"+track, nil), 404, "not_found")
	// A malformed ID is not_found like an unknown one.
	r.wantStatus(r.do(admin, "GET", base+"/subtitles/not-an-id", nil), 404, "not_found")
	r.wantStatus(r.do(admin, "GET", base+"/subtitles/sub_00000000000000000000000000", nil), 404, "not_found")

	if len(r.mustOK(r.do(admin, "GET", base+"/subtitles", nil), 200).m["items"].([]any)) != 1 {
		t.Error("a refused request changed the track list")
	}
	if got := r.signedManifest(admin, a); len(got.Manifest.Subtitles) != 1 {
		t.Errorf("manifest has %d tracks", len(got.Manifest.Subtitles))
	}
}

func importBody(lang, label string, start, end float64, text string) map[string]any {
	return map[string]any{"language": lang, "label": label, "cues": []map[string]any{{"start": start, "end": end, "text": text}}}
}

func TestSubtitleAssetStates(t *testing.T) {
	r := newSubtitleRig(t)
	admin, res := r.bootstrap("acme")
	post := func(a db.Asset) resp {
		return r.upload(admin, a.ID.String(), vttForm("en", "English", goodVTT)...)
	}

	// An asset that is not ready is refused with asset_not_ready, whatever the stage.
	for _, st := range []db.AssetState{db.AssetCreated, db.AssetProcessing} {
		a := r.newAsset(res, st)
		r.wantStatus(post(a), 409, "asset_not_ready")
		r.wantStatus(r.do(admin, "POST", "/v1/assets/"+a.ID.String()+"/transcripts", importBody("en", "x", 1, 2, "t")), 409, "asset_not_ready")
	}

	// An asset that is being deleted refuses tracks, and keeps the ones it had until the purge.
	a := r.readyAsset(res)
	track := str(r.mustOK(post(a), 201).m, "id")
	r.mustOK(r.do(admin, "DELETE", "/v1/assets/"+a.ID.String(), nil), 202)
	r.wantStatus(post(a), 409, "conflict")
	r.wantStatus(r.do(admin, "DELETE", "/v1/assets/"+a.ID.String()+"/subtitles/"+track, nil), 409, "conflict")
	r.mustOK(r.do(admin, "GET", "/v1/assets/"+a.ID.String()+"/subtitles", nil), 200)

	// A deleted asset (the tombstone) answers not_found.
	if _, err := r.pool.Exec(context.Background(),
		`UPDATE assets SET state = 'deleted', deleted_at = now() WHERE id = $1`, a.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	r.wantStatus(post(a), 404, "not_found")
	r.wantStatus(r.do(admin, "GET", "/v1/assets/"+a.ID.String()+"/subtitles", nil), 404, "not_found")
	r.wantStatus(r.do(admin, "DELETE", "/v1/assets/"+a.ID.String()+"/subtitles/"+track, nil), 404, "not_found")
}

func TestSubtitleValidationAtTheAPI(t *testing.T) {
	r := newSubtitleRig(t)
	admin, res := r.bootstrap("acme")
	a := r.readyAsset(res)
	id := a.ID.String()
	invalid := func(name string, got resp) {
		t.Helper()
		if got.status != 400 || got.code() != "invalid_request" {
			t.Errorf("%s: status %d code %q: %s", name, got.status, got.code(), got.raw)
		}
		if strings.Contains(string(got.raw), "secret-name") {
			t.Errorf("%s: the answer quotes the upload: %s", name, got.raw)
		}
	}
	invalid("no file", r.upload(admin, id, formPart{"language", "", "en"}, formPart{"label", "", "x"}))
	invalid("no language", r.upload(admin, id, formPart{"file", "f.vtt", goodVTT}, formPart{"label", "", "x"}))
	invalid("no label", r.upload(admin, id, formPart{"file", "f.vtt", goodVTT}, formPart{"language", "", "en"}))
	invalid("bad language", r.upload(admin, id, vttForm("english", "x", goodVTT)...))
	invalid("language injection", r.upload(admin, id, vttForm("en\"\n#EXT-X-ENDLIST", "x", goodVTT)...))
	invalid("empty label", r.upload(admin, id, vttForm("en", "   ", goodVTT)...))
	invalid("long label", r.upload(admin, id, vttForm("en", strings.Repeat("x", 101), goodVTT)...))
	invalid("label newline", r.upload(admin, id, vttForm("en", "a\nb", goodVTT)...))
	invalid("bad default", r.upload(admin, id, vttForm("en", "x", goodVTT, formPart{"default", "", "yes"})...))
	invalid("unknown member", r.upload(admin, id, vttForm("en", "x", goodVTT, formPart{"extra", "", "1"})...))
	invalid("duplicate member", r.upload(admin, id, vttForm("en", "x", goodVTT, formPart{"label", "", "again"})...))
	invalid("not a subtitle", r.upload(admin, id, vttForm("en", "x", "hello world")...))
	invalid("cue past the video", r.upload(admin, id, vttForm("en", "x", "WEBVTT\n\n00:09:00.000 --> 00:11:00.000\nhi\n")...))
	invalid("cues out of order", r.upload(admin, id, vttForm("en", "x", "WEBVTT\n\n00:00:05.000 --> 00:00:06.000\na\n\n00:00:01.000 --> 00:00:02.000\nb\n")...))
	invalid("negative time", r.upload(admin, id, vttForm("en", "x", "WEBVTT\n\n00:00:-5.000 --> 00:00:06.000\na\n")...))
	invalid("no cues", r.upload(admin, id, vttForm("en", "x", "WEBVTT\n")...))
	invalid("binary", r.upload(admin, id, vttForm("en", "x", "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\na\x00b\n")...))
	invalid("not multipart", r.raw(admin, "POST", "/v1/assets/"+id+"/subtitles", "multipart/form-data; boundary=x", []byte("garbage")))

	// A wrong content type is a client error too, not a crash.
	if got := r.raw(admin, "POST", "/v1/assets/"+id+"/subtitles", "application/json", []byte("{}")); got.status != 400 && got.status != 415 {
		t.Errorf("JSON to the upload: %d %s", got.status, got.raw)
	}

	// A field error names the field and the cue, never the content.
	got := r.upload(admin, id, vttForm("en", "x", "WEBVTT\n\n00:00:05.000 --> 00:00:02.000\nTOP-SECRET-TEXT\n")...)
	if !strings.Contains(string(got.raw), `"file"`) || strings.Contains(string(got.raw), "TOP-SECRET-TEXT") {
		t.Errorf("field error = %s", got.raw)
	}

	// Over 2 MB: 413, both for the file and for a whole body past the cap.
	big := "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\n" + strings.Repeat("x", subtitles.MaxBytes) + "\n"
	r.wantStatus(r.upload(admin, id, vttForm("en", "x", big)...), 413, "payload_too_large")
	huge := strings.Repeat("y", subtitles.MaxRequestBytes+1024)
	r.wantStatus(r.upload(admin, id, vttForm("en", "x", huge)...), 413, "payload_too_large")

	// Nothing of all that was kept.
	if len(r.store.keys()) != 0 || r.count(`SELECT count(*) FROM asset_subtitles WHERE asset_id = $1`, a.ID.UUID()) != 0 {
		t.Errorf("a refused upload left something behind: %v", r.store.keys())
	}

	// What is fine: BOM, CRLF, hostile markup (rewritten), the extremes of the tolerances.
	hostile := "\ufeffWEBVTT\r\n\r\n00:00:01.000 --> 00:00:02.000 align:start\r\n<script>alert(1)</script><b onclick=x>bold</b> &#60; <v Ann\"><c.x\" y>hi\r\n"
	ok := r.mustOK(r.upload(admin, id, vttForm("en", "ok", hostile)...), 201)
	stored, _ := r.store.get(keys.Subtitle(res.Tenant.ID, a.ID, mustSubtitleID(t, str(ok.m, "id"))))
	if want := "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nalert(1)<b>bold</b> &amp;#60; <v Ann><c>hi</c></v>\n\n"; string(stored) != want {
		t.Errorf("hostile upload stored as %q, want %q", stored, want)
	}
	r.mustOK(r.upload(admin, id, vttForm("en", "edge", "WEBVTT\n\n00:09:59.000 --> 00:10:01.500\nlast\n")...), 201)
}

func TestSubtitleTrackLimit(t *testing.T) {
	r := newSubtitleRig(t)
	admin, res := r.bootstrap("acme")
	a := r.readyAsset(res)
	for i := range subtitles.MaxTracks {
		r.mustOK(r.upload(admin, a.ID.String(), vttForm("en", fmt.Sprintf("Track %d", i), goodVTT)...), 201)
	}
	r.wantStatus(r.upload(admin, a.ID.String(), vttForm("en", "one too many", goodVTT)...), 409, "conflict")
	r.wantStatus(r.do(admin, "POST", "/v1/assets/"+a.ID.String()+"/transcripts", importBody("en", "x", 1, 2, "t")), 409, "conflict")
	if n := len(r.store.keys()); n != subtitles.MaxTracks {
		t.Errorf("%d objects stored, want %d (the refused upload must leave none)", n, subtitles.MaxTracks)
	}
	if m := r.signedManifest(admin, a); len(m.Manifest.Subtitles) != subtitles.MaxTracks {
		t.Errorf("manifest lists %d tracks", len(m.Manifest.Subtitles))
	}
	// Deleting one makes room again.
	list := r.mustOK(r.do(admin, "GET", "/v1/assets/"+a.ID.String()+"/subtitles", nil), 200).m["items"].([]any)
	r.mustOK(r.do(admin, "DELETE", "/v1/assets/"+a.ID.String()+"/subtitles/"+str(list[0].(map[string]any), "id"), nil), 204)
	r.mustOK(r.upload(admin, a.ID.String(), vttForm("en", "fits now", goodVTT)...), 201)
}

func TestTranscriptImport(t *testing.T) {
	r := newSubtitleRig(t)
	admin, res := r.bootstrap("acme")
	a := r.readyAsset(res)
	path := "/v1/assets/" + a.ID.String() + "/transcripts"

	body := map[string]any{
		"language": "de", "label": "Deutsch", "default": true,
		"cues": []map[string]any{
			{"start": 0.5, "end": 2, "text": "Hallo <b>& Welt</b>", "speaker": "Anna <x>"},
			{"start": 3, "end": 4.25, "text": "zweite\nZeile"},
		},
	}
	got := r.mustOK(r.do(admin, "POST", path, body), 201)
	if got.m["origin"] != "import" || got.m["language"] != "de" || got.m["default"] != true || got.m["cue_count"] != float64(2) {
		t.Fatalf("created = %s", got.raw)
	}
	stored, _ := r.store.get(keys.Subtitle(res.Tenant.ID, a.ID, mustSubtitleID(t, str(got.m, "id"))))
	want := "WEBVTT\n\n00:00:00.500 --> 00:00:02.000\n<v Anna x>Hallo &lt;b&gt;&amp; Welt&lt;/b&gt;</v>\n\n00:00:03.000 --> 00:00:04.250\nzweite\nZeile\n\n"
	if string(stored) != want {
		t.Errorf("stored = %q, want %q", stored, want)
	}
	if m := r.signedManifest(admin, a); len(m.Manifest.Subtitles) != 1 || m.Manifest.Subtitles[0].Origin != "import" {
		t.Errorf("manifest = %+v", m.Manifest.Subtitles)
	}

	for name, b := range map[string]any{
		"no cues":       map[string]any{"language": "en", "label": "x", "cues": []any{}},
		"bad language":  importBody("klingon-xx-yy-zz-aa-bb", "x", 1, 2, "t"),
		"end first":     importBody("en", "x", 5, 2, "t"),
		"negative":      importBody("en", "x", -1, 2, "t"),
		"past the end":  importBody("en", "x", 1, 9999, "t"),
		"empty text":    importBody("en", "x", 1, 2, " "),
		"huge text":     importBody("en", "x", 1, 2, strings.Repeat("x", 1001)),
		"extra member":  map[string]any{"language": "en", "label": "x", "cues": []any{}, "file": "x"},
		"unordered":     map[string]any{"language": "en", "label": "x", "cues": []map[string]any{{"start": 5, "end": 6, "text": "a"}, {"start": 1, "end": 2, "text": "b"}}},
		"missing label": map[string]any{"language": "en", "cues": []map[string]any{{"start": 1, "end": 2, "text": "a"}}},
	} {
		if got := r.do(admin, "POST", path, b); got.status != 400 || got.code() != "invalid_request" {
			t.Errorf("%s: status %d code %q: %s", name, got.status, got.code(), got.raw)
		}
	}
	r.wantStatus(r.do(admin, "POST", path, "{not json"), 400, "invalid_request")
	if n := len(r.store.keys()); n != 1 {
		t.Errorf("%d objects stored after refused imports, want 1", n)
	}
}

// A failed write to the bucket leaves no row, no registry entry and the old manifest; the same
// request works once storage is back.
func TestSubtitleStorageFailureLeavesNothing(t *testing.T) {
	r := newSubtitleRig(t)
	admin, res := r.bootstrap("acme")
	a := r.readyAsset(res)
	before := r.manifestEnvelope(admin, a)

	r.store.failPut = true
	if got := r.upload(admin, a.ID.String(), vttForm("en", "English", goodVTT)...); got.status < 500 {
		t.Fatalf("status %d: %s", got.status, got.raw)
	}
	r.store.failPut = false
	if r.count(`SELECT count(*) FROM asset_subtitles WHERE asset_id = $1`, a.ID.UUID()) != 0 ||
		r.count(`SELECT count(*) FROM asset_artifacts WHERE asset_id = $1 AND kind = 'subtitle'`, a.ID.UUID()) != 0 ||
		len(r.store.keys()) != 0 {
		t.Error("a failed upload left a row, a registry entry or an object")
	}
	if !bytes.Equal(before, r.manifestEnvelope(admin, a)) {
		t.Error("a failed upload changed the manifest")
	}
	r.mustOK(r.upload(admin, a.ID.String(), vttForm("en", "English", goodVTT)...), 201)
}

// Concurrent changes serialise on the asset: the manifest always lists exactly the tracks that
// exist, and at most one is the default.
func TestSubtitleConcurrentChanges(t *testing.T) {
	r := newSubtitleRig(t)
	admin, res := r.bootstrap("acme")
	a := r.readyAsset(res)
	const n = 8
	var wg sync.WaitGroup
	statuses := make([]int, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses[i] = r.upload(admin, a.ID.String(), vttForm("en", fmt.Sprintf("T%d", i), goodVTT, formPart{"default", "", "true"})...).status
		}()
	}
	wg.Wait()
	for i, s := range statuses {
		if s != 201 {
			t.Fatalf("upload %d: status %d", i, s)
		}
	}
	m := r.signedManifest(admin, a)
	rows, err := r.repos.ListSubtitles(context.Background(), res.Tenant.ID, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Manifest.Subtitles) != n || len(rows) != n || len(r.store.keys()) != n {
		t.Fatalf("manifest %d, rows %d, objects %d, want %d each", len(m.Manifest.Subtitles), len(rows), len(r.store.keys()), n)
	}
	defaults := 0
	for _, s := range m.Manifest.Subtitles {
		if s.Default {
			defaults++
		}
	}
	if defaults != 1 {
		t.Errorf("%d defaults in the manifest", defaults)
	}
	for _, row := range rows {
		var found bool
		for _, s := range m.Manifest.Subtitles {
			found = found || (s.ID == row.ID.String() && s.SHA256 == hex.EncodeToString(row.SHA256) && s.Default == row.Default)
		}
		if !found {
			t.Errorf("track %s is not in the manifest as stored", row.ID)
		}
	}
}

func TestSubtitleServiceUnavailableWithoutOne(t *testing.T) {
	h := newHarness(t) // no subtitle service wired
	admin, res := h.bootstrap("acme")
	a, _ := h.readyAssetWithManifest(res, false)
	h.wantStatus(h.do(admin, "GET", "/v1/assets/"+a.ID.String()+"/subtitles", nil), 503, "dependency_unavailable")
}
