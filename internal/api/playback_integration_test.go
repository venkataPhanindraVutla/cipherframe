//go:build integration

package api_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
)

// newAsset creates an asset of the tenant and walks it to state.
func (h *harness) newAsset(res auth.BootstrapResult, state db.AssetState) db.Asset {
	h.t.Helper()
	ctx := context.Background()
	a, err := h.repos.CreateUploadAsset(ctx, db.NewUploadAsset{
		ID: id.New[id.AssetKind](), TenantID: res.Tenant.ID, ClientID: res.Client.ID, SizeBytes: 1000,
		Method: db.UploadTus, SourceKey: "test-fixture-source-" + id.New[id.AssetKind]().String(),
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
	})
	if err != nil {
		h.t.Fatal(err)
	}
	path := []db.AssetState{db.AssetUploading, db.AssetCommitted, db.AssetProcessing, db.AssetReady}
	for _, next := range path {
		if a.State == state {
			break
		}
		if a, err = h.repos.TransitionAsset(ctx, res.Tenant.ID, a.ID, db.Transition{From: a.State, To: next}); err != nil {
			h.t.Fatal(err)
		}
	}
	return a
}

func (h *harness) createSession(key string, assetID, viewer string) resp {
	h.t.Helper()
	return h.do(key, "POST", "/v1/playback-sessions", map[string]any{"asset_id": assetID, "viewer_id": viewer})
}

// setSettings stores settings for a tenant directly; the settings endpoint has its own tests.
func (h *harness) setSettings(res auth.BootstrapResult, edit func(*db.PlaybackSettings)) {
	h.t.Helper()
	s := db.DefaultPlaybackSettings()
	edit(&s)
	if _, err := h.repos.PutPlaybackSettings(context.Background(), res.Tenant.ID, s, h.clk.Now()); err != nil {
		h.t.Fatal(err)
	}
}

func TestCreatePlaybackSession(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	asset := h.newAsset(res, db.AssetReady)

	r := h.mustOK(h.createSession(key, asset.ID.String(), "viewer-42"), 201)
	if cc := r.hdr.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q", cc)
	}
	sid, tok := str(r.m, "session_id"), str(r.m, "token")
	parsed, err := id.ParseSession(sid)
	if err != nil {
		t.Fatalf("session_id %q: %v", sid, err)
	}
	// The token verifies for every scope and for this asset only.
	now := h.clk.Now()
	for _, sc := range []token.Scope{token.ScopeManifest, token.ScopeKey, token.ScopeSegment} {
		c, err := h.keyring.Verify(tok, now, sc, asset.ID.String())
		if err != nil {
			t.Fatalf("token does not verify for %s: %v", sc, err)
		}
		if c.SessionID != sid || c.AssetID != asset.ID.String() {
			t.Fatalf("claims = %+v", c)
		}
	}
	if _, err := h.keyring.Verify(tok, now, token.ScopeKey, id.New[id.AssetKind]().String()); err == nil {
		t.Fatal("token verified for another asset")
	}
	if _, err := h.keyring.Verify(tok, now.Add(601*time.Second), token.ScopeKey, asset.ID.String()); err == nil {
		t.Fatal("token verified after its expiry")
	}
	// The documented shape and defaults (ADR 0028).
	if got, want := str(r.m, "manifest_url"), testEdgeURL+"/v1/play/"+sid+"/master.m3u8"; got != want {
		t.Fatalf("manifest_url = %q, want %q", got, want)
	}
	if str(r.m, "token_transport") != "header" || r.m["heartbeat_interval_seconds"] != float64(60) {
		t.Fatalf("response = %s", r.raw)
	}
	wantTokExp := now.Add(10 * time.Minute).Truncate(time.Second)
	if got := parseTime(t, str(r.m, "token_expires_at")); !got.Equal(wantTokExp) {
		t.Fatalf("token_expires_at = %v, want %v", got, wantTokExp)
	}
	wantSessExp := now.Truncate(time.Microsecond).Add(4 * time.Hour)
	if got := parseTime(t, str(r.m, "session_expires_at")); !got.Equal(wantSessExp) {
		t.Fatalf("session_expires_at = %v, want %v", got, wantSessExp)
	}
	// The row is stored under the hash of the ID, for the right asset, viewer and client.
	row, err := h.repos.GetPlaybackSession(context.Background(), res.Tenant.ID, db.SessionHash(parsed))
	if err != nil {
		t.Fatal(err)
	}
	if row.State != db.PlaybackActive || row.AssetID != asset.ID || row.ViewerID != "viewer-42" || row.ClientID != res.Client.ID {
		t.Fatalf("row = %+v", row)
	}
	var stored int
	if err := h.pool.QueryRow(context.Background(), "SELECT count(*) FROM playback_sessions WHERE playback_sessions::text LIKE '%' || $1 || '%'", sid[4:]).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("the session ID is stored in the table: n=%d err=%v", stored, err)
	}
	// Neither the token nor the session ID reaches the log.
	for _, secret := range []string{tok, sid, sid[4:]} {
		if strings.Contains(h.logs.String(), secret) {
			t.Fatal("a session secret reached the log")
		}
	}
}

func TestCreatePlaybackSessionTokenInURL(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	asset := h.newAsset(res, db.AssetReady)
	h.setSettings(res, func(s *db.PlaybackSettings) { s.TokenInURL = true })

	r := h.mustOK(h.createSession(key, asset.ID.String(), "v"), 201)
	sid, tok := str(r.m, "session_id"), str(r.m, "token")
	if want := testEdgeURL + "/v1/play/" + sid + "/master.m3u8?t=" + tok; str(r.m, "manifest_url") != want {
		t.Fatalf("manifest_url = %q, want %q", str(r.m, "manifest_url"), want)
	}
	if str(r.m, "token_transport") != "url" {
		t.Fatalf("token_transport = %q", str(r.m, "token_transport"))
	}
	if _, err := h.keyring.Verify(tok, h.clk.Now(), token.ScopeManifest, asset.ID.String()); err != nil {
		t.Fatal(err)
	}
	// Turning it off again goes back to the plain URL.
	h.setSettings(res, func(s *db.PlaybackSettings) { s.TokenInURL = false })
	r = h.mustOK(h.createSession(key, asset.ID.String(), "v"), 201)
	if strings.Contains(str(r.m, "manifest_url"), "?") || str(r.m, "token_transport") != "header" {
		t.Fatalf("response = %s", r.raw)
	}
	// The token appears nowhere in the log either way.
	if strings.Contains(h.logs.String(), tok) {
		t.Fatal("the token reached the log")
	}
}

func TestCreatePlaybackSessionTokenNeverOutlivesTheSession(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	asset := h.newAsset(res, db.AssetReady)
	h.setSettings(res, func(s *db.PlaybackSettings) { s.TokenTTLSeconds, s.SessionMaxSeconds = 3600, 300 })
	r := h.mustOK(h.createSession(key, asset.ID.String(), "v"), 201)
	tokExp, sessExp := parseTime(t, str(r.m, "token_expires_at")), parseTime(t, str(r.m, "session_expires_at"))
	if tokExp.After(sessExp) {
		t.Fatalf("token expires %v, after the session at %v", tokExp, sessExp)
	}
	if sessExp.Sub(h.clk.Now()) > 5*time.Minute+time.Second || tokExp.Before(sessExp.Add(-time.Second)) {
		t.Fatalf("token %v, session %v", tokExp, sessExp)
	}
}

func TestCreatePlaybackSessionAssetRules(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	otherKey, otherRes := h.bootstrap("other")
	_ = otherKey

	// Another tenant's asset looks exactly like a missing one.
	foreign := h.newAsset(otherRes, db.AssetReady)
	missing := h.do(key, "POST", "/v1/playback-sessions", map[string]any{"asset_id": id.New[id.AssetKind]().String(), "viewer_id": "v"})
	h.wantStatus(missing, 404, "not_found")
	cross := h.createSession(key, foreign.ID.String(), "v")
	h.wantStatus(cross, 404, "not_found")
	if missing.m["detail"] != cross.m["detail"] {
		t.Fatalf("details differ: %v vs %v", missing.m["detail"], cross.m["detail"])
	}

	// An asset that is not ready, in each earlier state and failed.
	for _, st := range []db.AssetState{db.AssetCreated, db.AssetUploading, db.AssetCommitted, db.AssetProcessing} {
		a := h.newAsset(res, st)
		h.wantStatus(h.createSession(key, a.ID.String(), "v"), 409, "asset_not_ready")
	}
	failed := h.newAsset(res, db.AssetCreated)
	if _, err := h.repos.TransitionAsset(context.Background(), res.Tenant.ID, failed.ID, db.Transition{From: db.AssetCreated, To: db.AssetFailed, FailureCode: "upload_aborted"}); err != nil {
		t.Fatal(err)
	}
	h.wantStatus(h.createSession(key, failed.ID.String(), "v"), 409, "asset_not_ready")
	var n int
	if err := h.pool.QueryRow(context.Background(), "SELECT count(*) FROM playback_sessions").Scan(&n); err != nil || n != 0 {
		t.Fatalf("sessions after rejected requests = %d, %v", n, err)
	}
}

func TestCreatePlaybackSessionValidation(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	asset := h.newAsset(res, db.AssetReady)
	field := func(r resp) string {
		errs, _ := r.m["errors"].([]any)
		if len(errs) != 1 {
			return ""
		}
		f, _ := errs[0].(map[string]any)["field"].(string)
		return f
	}
	for name, viewer := range map[string]string{
		"empty":        "",
		"too long":     strings.Repeat("v", 129),
		"nul":          "a\x00b",
		"newline":      "a\nb",
		"tab":          "a\tb",
		"escape":       "a\x1bb",
		"unit sep":     "a\u2028b",
		"bidi control": "a\u202eb",
	} {
		r := h.createSession(key, asset.ID.String(), viewer)
		h.wantStatus(r, 400, "invalid_request")
		if field(r) != "viewer_id" {
			t.Errorf("%s: errors = %v", name, r.m["errors"])
		}
	}
	// 128 characters, of several bytes each, is fine; so are ordinary printable ones.
	h.setSettings(res, func(s *db.PlaybackSettings) { s.MaxSessionsPerViewer = 0 })
	for _, viewer := range []string{strings.Repeat("v", 128), strings.Repeat("é", 128), "user 42/ü:テスト", "a"} {
		h.mustOK(h.createSession(key, asset.ID.String(), viewer), 201)
	}
	// A malformed asset ID is a field error, and a missing body is a plain 400.
	r := h.createSession(key, "ast_nope", "v")
	h.wantStatus(r, 400, "invalid_request")
	if field(r) != "asset_id" {
		t.Errorf("errors = %v", r.m["errors"])
	}
	h.wantStatus(h.do(key, "POST", "/v1/playback-sessions", `{"viewer_id":"v"}`), 400, "invalid_request")
	h.wantStatus(h.do(key, "POST", "/v1/playback-sessions", `not json`), 400, "invalid_request")
}

func TestCreatePlaybackSessionNeedsTheSessionsScope(t *testing.T) {
	h := newHarness(t)
	admin, res := h.bootstrap("acme")
	asset := h.newAsset(res, db.AssetReady)
	cli := h.newClient(admin, "svc")
	reader := str(h.newKey(admin, cli, "reader", []string{"assets:read", "assets:write", "admin"}).m, "key")
	h.wantStatus(h.createSession(reader, asset.ID.String(), "v"), 403, "forbidden")
	writer := str(h.newKey(admin, cli, "sessions", []string{"sessions:write"}).m, "key")
	h.mustOK(h.createSession(writer, asset.ID.String(), "v"), 201)
	h.wantStatus(h.createSession("", asset.ID.String(), "v"), 401, "unauthenticated")
	cid, err := id.Parse[id.ClientKind](cli)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := h.pool.QueryRow(context.Background(), "SELECT count(*) FROM playback_sessions WHERE client_id = $1", cid.UUID()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("sessions of the sessions key's client = %d, %v", n, err)
	}
}

func TestPlaybackSessionLimit(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	otherKey, otherRes := h.bootstrap("other")
	asset, otherAsset := h.newAsset(res, db.AssetReady), h.newAsset(otherRes, db.AssetReady)

	var first resp
	for i := range 3 {
		r := h.mustOK(h.createSession(key, asset.ID.String(), "viewer-xyz-7731"), 201)
		if i == 0 {
			first = r
		}
	}
	over := h.createSession(key, asset.ID.String(), "viewer-xyz-7731")
	h.wantStatus(over, 409, "session_limit")
	if strings.Contains(string(over.raw), "viewer-xyz-7731") {
		t.Fatalf("the problem body echoes the viewer ID: %s", over.raw)
	}
	// The existing sessions are left alone.
	var active int
	if err := h.pool.QueryRow(context.Background(), "SELECT count(*) FROM playback_sessions WHERE state = 'active'").Scan(&active); err != nil || active != 3 {
		t.Fatalf("active sessions = %d, %v", active, err)
	}
	// The limit is per viewer and per tenant.
	h.mustOK(h.createSession(key, asset.ID.String(), "someone else"), 201)
	h.mustOK(h.createSession(otherKey, otherAsset.ID.String(), "viewer-xyz-7731"), 201)

	// An ended or revoked session stops counting only once it is no longer active; a heartbeat
	// older than the idle timeout stops counting without any other change.
	parsed, _ := id.ParseSession(str(first.m, "session_id"))
	if _, err := h.pool.Exec(context.Background(), "UPDATE playback_sessions SET last_heartbeat_at = $1 WHERE id_hash = $2",
		h.clk.Now().Add(-5*time.Minute-time.Second), db.SessionHash(parsed)); err != nil {
		t.Fatal(err)
	}
	h.mustOK(h.createSession(key, asset.ID.String(), "viewer-xyz-7731"), 201)
	got, err := h.repos.GetPlaybackSession(context.Background(), res.Tenant.ID, db.SessionHash(parsed))
	if err != nil || got.State != db.PlaybackEnded || got.EndedAt == nil {
		t.Fatalf("the idle session = %+v, %v; want it ended", got, err)
	}
	h.wantStatus(h.createSession(key, asset.ID.String(), "viewer-xyz-7731"), 409, "session_limit")
}

func TestPlaybackSessionExpiredStopsCounting(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	asset := h.newAsset(res, db.AssetReady)
	h.setSettings(res, func(s *db.PlaybackSettings) { s.MaxSessionsPerViewer, s.SessionMaxSeconds = 1, 300 })
	h.mustOK(h.createSession(key, asset.ID.String(), "v"), 201)
	h.wantStatus(h.createSession(key, asset.ID.String(), "v"), 409, "session_limit")
	// Heartbeats are not implemented yet, so move the stored heartbeat forward with the clock to
	// isolate the maximum age.
	h.clk.Advance(301 * time.Second)
	if _, err := h.pool.Exec(context.Background(), "UPDATE playback_sessions SET last_heartbeat_at = $1", h.clk.Now()); err != nil {
		t.Fatal(err)
	}
	h.mustOK(h.createSession(key, asset.ID.String(), "v"), 201)
}

func TestPlaybackSessionLimitZeroIsUnlimited(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	asset := h.newAsset(res, db.AssetReady)
	h.setSettings(res, func(s *db.PlaybackSettings) { s.MaxSessionsPerViewer = 0 })
	for range 8 {
		h.mustOK(h.createSession(key, asset.ID.String(), "viewer-xyz-7731"), 201)
	}
	h.setSettings(res, func(s *db.PlaybackSettings) { s.MaxSessionsPerViewer = 8 })
	h.wantStatus(h.createSession(key, asset.ID.String(), "viewer-xyz-7731"), 409, "session_limit")
}

func TestPlaybackSessionLimitRace(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	asset := h.newAsset(res, db.AssetReady)

	const n = 10
	results := make([]resp, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i] = h.createSession(key, asset.ID.String(), "racer")
		}()
	}
	close(start)
	wg.Wait()

	var ok, limited int
	for _, r := range results {
		switch {
		case r.status == 201:
			ok++
		case r.status == 409 && r.code() == "session_limit":
			limited++
		default:
			t.Errorf("unexpected response %d: %s", r.status, r.raw)
		}
	}
	if ok != 3 || limited != n-3 {
		t.Fatalf("%d created and %d limited, want 3 and %d", ok, limited, n-3)
	}
	var active int
	if err := h.pool.QueryRow(context.Background(), "SELECT count(*) FROM playback_sessions WHERE state = 'active'").Scan(&active); err != nil || active != 3 {
		t.Fatalf("active rows = %d, %v", active, err)
	}
	// Distinct tokens and IDs, none of them logged.
	seen := map[string]bool{}
	for _, r := range results {
		if r.status != 201 {
			continue
		}
		for _, secret := range []string{str(r.m, "session_id"), str(r.m, "token")} {
			seen[secret] = true
			if strings.Contains(h.logs.String(), secret) {
				t.Fatal("a session secret reached the log")
			}
		}
	}
	if len(seen) != 6 {
		t.Fatalf("session IDs and tokens are not all distinct: %d values", len(seen))
	}
}

func parseTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("time %q: %v", s, err)
	}
	return v
}

func TestCreatePlaybackSessionVariants(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	h.setSettings(res, func(s *db.PlaybackSettings) { s.MaxSessionsPerViewer = 0 })
	create := func(asset db.Asset, variant any) resp {
		body := map[string]any{"asset_id": asset.ID.String(), "viewer_id": "viewer-v"}
		if variant != nil {
			body["variant"] = variant
		}
		return h.do(key, "POST", "/v1/playback-sessions", body)
	}
	tokenVariant := func(r resp) string {
		t.Helper()
		c, err := h.keyring.Open(str(r.m, "token"), h.clk.Now(), token.ScopeManifest)
		if err != nil {
			t.Fatal(err)
		}
		return c.Variant
	}

	// An asset without masking: original by default; masked is a 409.
	plain := h.newAsset(res, db.AssetReady)
	r := h.mustOK(create(plain, nil), 201)
	if str(r.m, "variant") != "original" || tokenVariant(r) != "original" {
		t.Fatalf("plain default: %s", r.raw)
	}
	h.wantStatus(create(plain, "masked"), 409, "variant_unavailable")
	h.wantStatus(create(plain, "sepia"), 400, "invalid_request")

	// An asset with masking: the default is masked, never the original.
	m := h.newAsset(res, db.AssetReady)
	if _, err := h.pool.Exec(context.Background(), "UPDATE assets SET mask_faces = true, masking_state = 'pending' WHERE id = $1", m.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	h.wantStatus(create(m, nil), 409, "variant_not_ready")
	h.wantStatus(create(m, "masked"), 409, "variant_not_ready")
	r = h.mustOK(create(m, "original"), 201)
	if str(r.m, "variant") != "original" {
		t.Fatalf("explicit original: %s", r.raw)
	}
	faces := 2
	if _, err := h.repos.SetAssetMasking(context.Background(), res.Tenant.ID, m.ID, db.MaskingReady, &faces, time.Time{}); err != nil {
		t.Fatal(err)
	}
	r = h.mustOK(create(m, nil), 201)
	if str(r.m, "variant") != "masked" || tokenVariant(r) != "masked" {
		t.Fatalf("masking default: %s", r.raw)
	}
	sid, err := id.ParseSession(str(r.m, "session_id"))
	if err != nil {
		t.Fatal(err)
	}
	if row, err := h.repos.GetPlaybackSession(context.Background(), res.Tenant.ID, db.SessionHash(sid)); err != nil || row.Variant != "masked" {
		t.Fatalf("row: %+v, %v", row, err)
	}
	r = h.mustOK(create(m, "original"), 201)
	if str(r.m, "variant") != "original" {
		t.Fatalf("original on a masking asset: %s", r.raw)
	}
}
