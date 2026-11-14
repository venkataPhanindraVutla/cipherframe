//go:build integration

package contract

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/accesslog"
	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
)

// TestAccessLogAndPrivacyOperationsMatchSpec exercises the access-log reads and the privacy
// settings through the real handler chain and validates every request and response against the
// spec, including the problem responses.
func TestAccessLogAndPrivacyOperationsMatchSpec(t *testing.T) {
	doc := loadSpec(t)
	pool := dbtest.NewMigrated(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	repos := db.New(pool)
	mgr := auth.NewManager(pool, onePepper{}, nil)
	keyring, err := token.NewKeyring(map[int][]byte{1: []byte("test-fixture-playback-token-key-0123456789")}, 1)
	if err != nil {
		t.Fatal(err)
	}
	rec := accesslog.New(accesslog.Options{Store: repos, FlushInterval: 10 * time.Millisecond})
	pb, err := playback.NewService(playback.Deps{Pool: pool, Keyring: keyring, EdgeURL: "https://media.example.com", Access: rec})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.New(api.Deps{Log: log, Verifier: auth.NewVerifier(repos, onePepper{}, log, nil), Manager: mgr, Playback: pb}).Handler())
	t.Cleanup(srv.Close)

	ctx := context.Background()
	res, err := mgr.Bootstrap(ctx, "contract", "contract client")
	if err != nil {
		t.Fatal(err)
	}
	admin := map[string]string{"Authorization": "Bearer " + res.Secret.Reveal()}
	cli, err := mgr.CreateClient(ctx, res.Tenant.ID, auth.Actor{}, "reader")
	if err != nil {
		t.Fatal(err)
	}
	key, err := mgr.CreateKey(ctx, res.Tenant.ID, auth.Actor{}, auth.CreateKeyInput{ClientID: cli.ID, Name: "reader", Scopes: []db.Scope{db.ScopeAssetsRead}})
	if err != nil {
		t.Fatal(err)
	}
	reader := map[string]string{"Authorization": "Bearer " + key.Secret.Reveal()}
	covered := map[string]bool{}

	call := func(hdr map[string]string, method, path string, body any, wantStatus int) map[string]any {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		ex := doBody(t, srv.URL, method, path, hdr, raw)
		if ex.resp.StatusCode != wantStatus {
			t.Fatalf("%s %s: status %d, want %d: %s", method, path, ex.resp.StatusCode, wantStatus, ex.body)
		}
		if op := validate(t, doc, ex); op != "" && wantStatus < 300 {
			covered[op] = true
		}
		var m map[string]any
		_ = json.Unmarshal(ex.body, &m)
		return m
	}
	// bad sends a request that breaks the spec's own constraints (so no request validation) and
	// expects a valid 400 Problem.
	bad := func(method, path string, body any) {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		ex := doBody(t, srv.URL, method, path, admin, raw)
		if ex.resp.StatusCode != 400 {
			t.Fatalf("%s %s: status %d, want 400: %s", method, path, ex.resp.StatusCode, ex.body)
		}
		validateProblem(t, doc, ex)
	}

	asset := readyAsset(t, repos, res, db.AssetReady)
	created := call(admin, "POST", "/v1/playback-sessions", map[string]any{"asset_id": asset.ID.String(), "viewer_id": "viewer-1"}, 201)
	sessionID := created["session_id"].(string)
	call(admin, "POST", "/v1/playback-sessions/"+sessionID+"/revoke", map[string]any{"reason": "test"}, 200)
	// Wait for the writer: two rows for this asset (created, revoked).
	sid, err := id.ParseSession(sessionID)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		rows, _, err := repos.ListSessionAccessLog(ctx, res.Tenant.ID, db.SessionHash(sid), db.AccessLogQuery{Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("rows written = %d, want 2", len(rows))
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Privacy settings: defaults, a full replacement, a missing field, the scope.
	defaults := call(admin, "GET", "/v1/privacy-settings", nil, 200)
	if _, has := defaults["updated_at"]; has || defaults["store_ip"] != false || defaults["store_user_agent"] != false {
		t.Fatalf("default privacy settings = %v", defaults)
	}
	put := call(admin, "PUT", "/v1/privacy-settings", map[string]any{"store_ip": true, "store_user_agent": false}, 200)
	if _, has := put["updated_at"]; !has || put["store_ip"] != true || put["store_user_agent"] != false {
		t.Fatalf("replaced privacy settings = %v", put)
	}
	if _, has := put["asset_ttl_seconds"]; has || defaults["asset_ttl_seconds"] != nil {
		t.Fatalf("a default time-to-live appeared by itself: %v %v", defaults, put)
	}
	// The tenant's default time-to-live: set with the rest, validated, and gone again when a later
	// replacement leaves it out.
	withTTL := call(admin, "PUT", "/v1/privacy-settings", map[string]any{"store_ip": true, "store_user_agent": false, "asset_ttl_seconds": 86400}, 200)
	if withTTL["asset_ttl_seconds"] != float64(86400) {
		t.Fatalf("privacy settings with a time-to-live = %v", withTTL)
	}
	if got := call(admin, "GET", "/v1/privacy-settings", nil, 200); got["asset_ttl_seconds"] != float64(86400) {
		t.Fatalf("GET after setting a time-to-live = %v", got)
	}
	bad("PUT", "/v1/privacy-settings", map[string]any{"store_ip": true, "store_user_agent": false, "asset_ttl_seconds": 59})
	bad("PUT", "/v1/privacy-settings", map[string]any{"store_ip": true, "store_user_agent": false, "asset_ttl_seconds": 315360001})
	if got := call(admin, "PUT", "/v1/privacy-settings", map[string]any{"store_ip": true, "store_user_agent": false}, 200); got["asset_ttl_seconds"] != nil {
		t.Fatalf("a replacement without asset_ttl_seconds kept it: %v", got)
	}
	bad("PUT", "/v1/privacy-settings", map[string]any{"store_ip": true})
	call(reader, "GET", "/v1/privacy-settings", nil, 403)
	call(reader, "PUT", "/v1/privacy-settings", map[string]any{"store_ip": true, "store_user_agent": true}, 403)
	call(nil, "GET", "/v1/privacy-settings", nil, 401)

	// The asset's trail: both rows, newest first, pages, filters, and never a session ID.
	base := "/v1/assets/" + asset.ID.String() + "/access-log"
	all := call(reader, "GET", base, nil, 200)
	items := all["items"].([]any)
	if len(items) != 2 || items[0].(map[string]any)["event"] != "revoked" || items[1].(map[string]any)["event"] != "session_created" {
		t.Fatalf("trail = %v", all)
	}
	first := items[1].(map[string]any)
	if first["viewer_id"] != "viewer-1" || first["auth_method"] != "api_key" || len(first["session"].(string)) != 8 {
		t.Fatalf("created row = %v", first)
	}
	if _, has := first["ip"]; has {
		t.Fatalf("an API-key creation row has an address: %v", first)
	}
	page := call(reader, "GET", base+"?limit=1", nil, 200)
	next, _ := page["next_cursor"].(string)
	if next == "" || len(page["items"].([]any)) != 1 {
		t.Fatalf("first page = %v", page)
	}
	last := call(reader, "GET", base+"?limit=1&cursor="+next, nil, 200)
	if _, more := last["next_cursor"]; more || last["items"].([]any)[0].(map[string]any)["event"] != "session_created" {
		t.Fatalf("second page = %v", last)
	}
	only := call(reader, "GET", base+"?event=revoked", nil, 200)
	if len(only["items"].([]any)) != 1 {
		t.Fatalf("event filter = %v", only)
	}
	call(reader, "GET", base+"?from="+time.Now().Add(time.Hour).UTC().Format(time.RFC3339), nil, 200)
	call(reader, "GET", base+"?to="+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+"&from="+time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), nil, 200)

	// The session's trail.
	sbase := "/v1/playback-sessions/" + sessionID + "/access-log"
	sess := call(reader, "GET", sbase, nil, 200)
	if len(sess["items"].([]any)) != 2 {
		t.Fatalf("session trail = %v", sess)
	}
	for _, body := range []map[string]any{all, sess} {
		raw, _ := json.Marshal(body)
		if strings.Contains(string(raw), sessionID) || strings.Contains(string(raw), "ses_") {
			t.Fatalf("a response holds the session ID: %s", raw)
		}
	}

	// Problems: bad parameters are 400, another tenant's or an unknown asset and session are 404,
	// no key is 401, a key without the scope is 403.
	bad("GET", base+"?limit=501", nil)
	bad("GET", base+"?limit=0", nil)
	bad("GET", base+"?event=segment_7", nil)
	bad("GET", base+"?cursor=bogus", nil)
	bad("GET", base+"?from=2030-01-02T00:00:00Z&to=2030-01-01T00:00:00Z", nil)
	bad("GET", sbase+"?limit=501", nil)
	call(admin, "GET", "/v1/assets/"+id.New[id.AssetKind]().String()+"/access-log", nil, 404)
	call(admin, "GET", "/v1/playback-sessions/ses_"+strings.Repeat("0", 52)+"/access-log", nil, 404)
	call(nil, "GET", base, nil, 401)
	call(nil, "GET", sbase, nil, 401)
	noScope, err := mgr.CreateKey(ctx, res.Tenant.ID, auth.Actor{}, auth.CreateKeyInput{ClientID: cli.ID, Name: "sessions", Scopes: []db.Scope{db.ScopeSessionsWrite}})
	if err != nil {
		t.Fatal(err)
	}
	wrong := map[string]string{"Authorization": "Bearer " + noScope.Secret.Reveal()}
	call(wrong, "GET", base, nil, 403)
	call(wrong, "GET", sbase, nil, 403)

	// Another tenant sees none of it: its key gets 404 for this tenant's asset and session, and an
	// empty trail for its own.
	otherRes, err := mgr.Bootstrap(ctx, "other", "other client")
	if err != nil {
		t.Fatal(err)
	}
	other := map[string]string{"Authorization": "Bearer " + otherRes.Secret.Reveal()}
	call(other, "GET", base, nil, 404)
	call(other, "GET", sbase, nil, 404)
	otherAsset := readyAsset(t, repos, otherRes, db.AssetReady)
	empty := call(other, "GET", "/v1/assets/"+otherAsset.ID.String()+"/access-log", nil, 200)
	if len(empty["items"].([]any)) != 0 {
		t.Fatalf("another tenant's trail = %v", empty)
	}
	// Reading with the other tenant's key but this tenant's asset never leaks a row through a
	// filter either.
	call(other, "GET", base+"?event=revoked", nil, 404)

	for _, op := range []string{"getAssetAccessLog", "getPlaybackSessionAccessLog", "getPrivacySettings", "updatePrivacySettings"} {
		if !covered[op] {
			t.Fatalf("%s was not exercised with a 2xx response; covered = %v", op, covered)
		}
	}
	closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rec.Close(closeCtx)
}
