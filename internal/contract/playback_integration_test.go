//go:build integration

package contract

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
)

// TestPlaybackOperationsMatchSpec exercises the playback operations through the real handler chain
// and validates every request and response (success, 400, 403, 404 and both 409 codes) against
// the spec.
func TestPlaybackOperationsMatchSpec(t *testing.T) {
	doc := loadSpec(t)
	pool := dbtest.NewMigrated(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	repos := db.New(pool)
	mgr := auth.NewManager(pool, onePepper{}, nil)
	keyring, err := token.NewKeyring(map[int][]byte{1: []byte("test-fixture-playback-token-key-0123456789")}, 1)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := playback.NewService(playback.Deps{Pool: pool, Keyring: keyring, EdgeURL: "https://media.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	a := api.New(api.Deps{Log: log, Verifier: auth.NewVerifier(repos, onePepper{}, log, nil), Manager: mgr, Playback: pb})
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)

	ctx := context.Background()
	res, err := mgr.Bootstrap(ctx, "contract", "contract client")
	if err != nil {
		t.Fatal(err)
	}
	admin := map[string]string{"Authorization": "Bearer " + res.Secret.Reveal()}
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
		raw, _ := json.Marshal(body)
		ex := doBody(t, srv.URL, method, path, admin, raw)
		if ex.resp.StatusCode != 400 {
			t.Fatalf("%s %s: status %d, want 400: %s", method, path, ex.resp.StatusCode, ex.body)
		}
		validateProblem(t, doc, ex)
	}

	asset := readyAsset(t, repos, res, db.AssetReady)
	pending := readyAsset(t, repos, res, db.AssetCommitted)
	sess := map[string]any{"asset_id": asset.ID.String(), "viewer_id": "viewer-1"}

	created := call(admin, "POST", "/v1/playback-sessions", sess, 201)
	if created["token_transport"] != "header" {
		t.Fatalf("response = %v", created)
	}
	call(admin, "POST", "/v1/playback-sessions", map[string]any{"asset_id": id.New[id.AssetKind]().String(), "viewer_id": "v"}, 404)
	call(admin, "POST", "/v1/playback-sessions", map[string]any{"asset_id": pending.ID.String(), "viewer_id": "v"}, 409)
	bad("POST", "/v1/playback-sessions", map[string]any{"asset_id": asset.ID.String(), "viewer_id": ""})
	bad("POST", "/v1/playback-sessions", map[string]any{"asset_id": "nope", "viewer_id": "v"})
	call(admin, "POST", "/v1/playback-sessions", sess, 201)
	call(admin, "POST", "/v1/playback-sessions", sess, 201)
	call(admin, "POST", "/v1/playback-sessions", sess, 409) // session_limit

	cli, err := mgr.CreateClient(ctx, res.Tenant.ID, auth.Actor{}, "reader")
	if err != nil {
		t.Fatal(err)
	}
	key, err := mgr.CreateKey(ctx, res.Tenant.ID, auth.Actor{}, auth.CreateKeyInput{ClientID: cli.ID, Name: "reader", Scopes: []db.Scope{db.ScopeAssetsRead}})
	if err != nil {
		t.Fatal(err)
	}
	reader := map[string]string{"Authorization": "Bearer " + key.Secret.Reveal()}
	call(reader, "POST", "/v1/playback-sessions", sess, 403)
	call(nil, "POST", "/v1/playback-sessions", sess, 401)

	// Settings: defaults, a full replacement, field errors, and the scope.
	defaults := call(admin, "GET", "/v1/playback-settings", nil, 200)
	if _, has := defaults["updated_at"]; has || defaults["max_sessions_per_viewer"] != float64(3) {
		t.Fatalf("default settings = %v", defaults)
	}
	full := map[string]any{
		"token_ttl_seconds": 900, "heartbeat_interval_seconds": 30, "idle_timeout_seconds": 120,
		"session_max_seconds": 7200, "max_sessions_per_viewer": 0, "key_fetches_per_token": 10,
		"key_requests_per_minute": 15, "allowed_origins": []string{"https://app.example.com", "http://localhost:3000"},
		"token_in_url": true, "delivery": "presigned",
		"anomaly_sessions_per_viewer_10m": 20, "anomaly_segments_without_key": 0, "auto_revoke": []string{"key_replay", "segments_without_key"},
	}
	put := call(admin, "PUT", "/v1/playback-settings", full, 200)
	if _, has := put["updated_at"]; !has || put["token_in_url"] != true || put["delivery"] != "presigned" {
		t.Fatalf("replaced settings = %v", put)
	}
	call(admin, "GET", "/v1/playback-settings", nil, 200)
	bad("PUT", "/v1/playback-settings", map[string]any{"token_ttl_seconds": 1})
	full["allowed_origins"] = []string{"https://*.example.com"}
	bad("PUT", "/v1/playback-settings", full)
	call(reader, "GET", "/v1/playback-settings", nil, 403)
	call(reader, "PUT", "/v1/playback-settings", full, 403)
	call(nil, "GET", "/v1/playback-settings", nil, 401)

	for _, op := range []string{"createPlaybackSession", "getPlaybackSettings", "updatePlaybackSettings"} {
		if !covered[op] {
			t.Fatalf("%s was not exercised with a 2xx response; covered = %v", op, covered)
		}
	}
}

// readyAsset creates an asset of the bootstrap tenant and walks it to state.
func readyAsset(t *testing.T, r *db.Repos, res auth.BootstrapResult, state db.AssetState) db.Asset {
	t.Helper()
	ctx := context.Background()
	a, err := r.CreateUploadAsset(ctx, db.NewUploadAsset{
		ID: id.New[id.AssetKind](), TenantID: res.Tenant.ID, ClientID: res.Client.ID, SizeBytes: 1000,
		Method: db.UploadTus, SourceKey: "test-fixture-source-" + id.New[id.AssetKind]().String(),
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, next := range []db.AssetState{db.AssetUploading, db.AssetCommitted, db.AssetProcessing, db.AssetReady} {
		if a.State == state {
			break
		}
		if a, err = r.TransitionAsset(ctx, res.Tenant.ID, a.ID, db.Transition{From: a.State, To: next}); err != nil {
			t.Fatal(err)
		}
	}
	return a
}
