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

	"github.com/venkataPhanindraVutla/cipherframe/internal/anomaly"
	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
)

// TestAnomalyOperationsMatchSpec reads the events endpoint through the real handler chain and
// validates every request and response against the spec, including the problem responses, and
// checks that the new playback settings fields round-trip as the spec describes.
func TestAnomalyOperationsMatchSpec(t *testing.T) {
	doc := loadSpec(t)
	pool := dbtest.NewMigrated(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	repos := db.New(pool)
	mgr := auth.NewManager(pool, onePepper{}, nil)
	keyring, err := token.NewKeyring(map[int][]byte{1: []byte("test-fixture-playback-token-key-0123456789")}, 1)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := playback.NewService(playback.Deps{
		Pool: pool, Keyring: keyring, EdgeURL: "https://media.example.com",
		Anomalies: anomaly.New(anomaly.Deps{Pool: pool, Log: log}),
	})
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
	bad := func(path string) {
		t.Helper()
		ex := doBody(t, srv.URL, "GET", path, reader, nil)
		if ex.resp.StatusCode != 400 {
			t.Fatalf("GET %s: status %d, want 400: %s", path, ex.resp.StatusCode, ex.body)
		}
		validateProblem(t, doc, ex)
	}

	// An empty list first, then one real event: a refused creation raises session_limit.
	if got := call(reader, "GET", "/v1/playback-events", nil, 200); len(got["items"].([]any)) != 0 {
		t.Fatalf("events before anything happened = %v", got)
	}
	asset := readyAsset(t, repos, res, db.AssetReady)
	call(admin, "PUT", "/v1/playback-settings", map[string]any{
		"token_ttl_seconds": 600, "heartbeat_interval_seconds": 60, "idle_timeout_seconds": 300,
		"session_max_seconds": 14400, "max_sessions_per_viewer": 1, "key_fetches_per_token": 20,
		"key_requests_per_minute": 30, "allowed_origins": []string{}, "token_in_url": false, "delivery": "proxy",
		"anomaly_sessions_per_viewer_10m": 10, "anomaly_segments_without_key": 30, "auto_revoke": []string{"segments_without_key"},
	}, 200)
	sess := map[string]any{"asset_id": asset.ID.String(), "viewer_id": "viewer-1"}
	call(admin, "POST", "/v1/playback-sessions", sess, 201)
	call(admin, "POST", "/v1/playback-sessions", sess, 409)

	got := call(reader, "GET", "/v1/playback-events", nil, 200)
	items := got["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("events = %v", got)
	}
	ev := items[0].(map[string]any)
	if ev["kind"] != "session_limit" || ev["viewer_id"] != "viewer-1" || ev["asset_id"] != asset.ID.String() {
		t.Fatalf("event = %v", ev)
	}
	if _, has := ev["session"]; has {
		t.Fatalf("a viewer-level event has a session fingerprint: %v", ev)
	}
	if _, ok := ev["detail"].(map[string]any); !ok {
		t.Fatalf("event has no detail object: %v", ev)
	}

	// Every filter and the paging parameters, through the spec's own validation.
	base := "/v1/playback-events"
	call(reader, "GET", base+"?kind=session_limit&asset_id="+asset.ID.String()+"&viewer_id=viewer-1&limit=10", nil, 200)
	call(reader, "GET", base+"?from="+time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)+"&to="+time.Now().Add(time.Hour).UTC().Format(time.RFC3339), nil, 200)
	for _, kind := range []string{"key_replay", "key_rate", "rapid_session_creation", "segments_without_key"} {
		if r := call(reader, "GET", base+"?kind="+kind, nil, 200); len(r["items"].([]any)) != 0 {
			t.Fatalf("kind %s = %v", kind, r)
		}
	}
	bad(base + "?kind=nope")
	bad(base + "?limit=0")
	bad(base + "?limit=501")
	bad(base + "?asset_id=not-an-asset")
	bad(base + "?cursor=bogus")
	bad(base + "?from=2030-01-02T00:00:00Z&to=2030-01-01T00:00:00Z")
	call(nil, "GET", base, nil, 401)
	noScope, err := mgr.CreateKey(ctx, res.Tenant.ID, auth.Actor{}, auth.CreateKeyInput{ClientID: cli.ID, Name: "sessions", Scopes: []db.Scope{db.ScopeSessionsWrite}})
	if err != nil {
		t.Fatal(err)
	}
	call(map[string]string{"Authorization": "Bearer " + noScope.Secret.Reveal()}, "GET", base, nil, 403)

	settings := call(admin, "GET", "/v1/playback-settings", nil, 200)
	if settings["anomaly_sessions_per_viewer_10m"] != float64(10) || settings["anomaly_segments_without_key"] != float64(30) {
		t.Fatalf("settings = %v", settings)
	}
	if ar, _ := settings["auto_revoke"].([]any); len(ar) != 1 || ar[0] != "segments_without_key" {
		t.Fatalf("auto_revoke = %v", settings["auto_revoke"])
	}
	if raw, _ := json.Marshal(got); strings.Contains(string(raw), "ses_") {
		t.Fatalf("a response holds a session ID: %s", raw)
	}

	for _, op := range []string{"listPlaybackEvents", "getPlaybackSettings", "updatePlaybackSettings"} {
		if !covered[op] {
			t.Fatalf("%s was not exercised with a 2xx response; covered = %v", op, covered)
		}
	}
}
