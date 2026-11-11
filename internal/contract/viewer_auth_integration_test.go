//go:build integration

package contract

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/kmstest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/local"
	"github.com/venkataPhanindraVutla/cipherframe/internal/outbound"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/storagetest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth/viewerauthtest"

	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
)

// TestViewerAuthOperationsMatchSpec drives the five admin operations of the viewer-authorization
// providers on the api listener and the browser-session operation on the edge listener through the
// real handler chains, and validates every request and response against the spec.
func TestViewerAuthOperationsMatchSpec(t *testing.T) {
	doc := loadSpec(t)
	ctx := context.Background()
	pool := dbtest.NewMigrated(t)
	repos := db.New(pool)
	mgr := auth.NewManager(pool, onePepper{}, nil)
	res, err := mgr.Bootstrap(ctx, "contract", "contract client")
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := token.NewKeyring(map[int][]byte{1: []byte("test-fixture-playback-token-key-0123456789")}, 1)
	if err != nil {
		t.Fatal(err)
	}
	lp, err := local.NewFromKeys(config.Development, map[int][]byte{1: bytes.Repeat([]byte{0x41}, config.KEKBytes)}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	faulty := kmstest.NewFaulty(lp)
	reg, err := kms.NewRegistry(faulty)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := playback.NewService(playback.Deps{Pool: pool, Keyring: keyring, EdgeURL: "https://media.example.com", KMS: reg})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	apiSrv := httptest.NewServer(api.New(api.Deps{Log: log, Verifier: auth.NewVerifier(repos, onePepper{}, log, nil), Manager: mgr, Playback: svc}).Handler())
	t.Cleanup(apiSrv.Close)

	// The edge trusts the callback test server's certificate and may reach loopback (test only).
	cb := &callbackStub{}
	cbSrv := httptest.NewTLSServer(cb)
	t.Cleanup(cbSrv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(cbSrv.Certificate())
	verifier, err := viewerauth.NewVerifier(viewerauth.VerifierOptions{
		Client:         outbound.New(outbound.Options{AllowLoopback: true, RootCAs: roots}),
		ValidateViewer: playback.ValidateViewerID,
	})
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := viewerauth.NewAuthorizer(viewerauth.AuthorizerOptions{
		Client:         outbound.New(outbound.Options{AllowLoopback: true, RootCAs: roots}),
		ValidateViewer: playback.ValidateViewerID,
	})
	if err != nil {
		t.Fatal(err)
	}
	buckets, err := storage.New(ctx, storagetest.Shared(t).Config())
	if err != nil {
		t.Fatal(err)
	}
	p, err := edge.NewPlayback(edge.PlaybackDeps{
		Keyring: keyring, Store: repos, Delivery: buckets.Delivery,
		Viewer: &edge.ViewerDeps{Sessions: svc, Store: repos, Secrets: viewerauth.NewSecretBox(reg), Verifier: verifier, Callback: authorizer},
	})
	if err != nil {
		t.Fatal(err)
	}
	edgeSrv := httptest.NewServer(edge.New(edge.Deps{Log: log, Playback: p}).Handler())
	t.Cleanup(edgeSrv.Close)

	admin := map[string]string{"Authorization": "Bearer " + res.Secret.Reveal()}
	covered := map[string]bool{}
	call := func(base string, hdr map[string]string, method, path string, body any, wantStatus int) map[string]any {
		t.Helper()
		var raw []byte
		if body != nil {
			var ok bool
			if raw, ok = body.([]byte); !ok {
				raw, _ = json.Marshal(body)
			}
		}
		ex := doBody(t, base, method, path, hdr, raw)
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
	// expects a valid problem with the given status.
	bad := func(base string, hdr map[string]string, method, path string, body any, wantStatus int) {
		t.Helper()
		raw, _ := json.Marshal(body)
		ex := doBody(t, base, method, path, hdr, raw)
		if ex.resp.StatusCode != wantStatus {
			t.Fatalf("%s %s: status %d, want %d: %s", method, path, ex.resp.StatusCode, wantStatus, ex.body)
		}
		validateProblem(t, doc, ex)
	}

	// Admin operations.
	defaults := call(apiSrv.URL, admin, "GET", "/v1/playback-auth", nil, 200)
	if defaults["jwt_enabled"] != false || defaults["callback_secret_version"] != float64(0) {
		t.Fatalf("defaults = %v", defaults)
	}
	ed := viewerauthtest.NewKey(t, "EdDSA", "contract-key")
	call(apiSrv.URL, admin, "PUT", "/v1/playback-auth/jwt-keys/contract-key", ed.PublicJWK(t), 200)
	bad(apiSrv.URL, admin, "PUT", "/v1/playback-auth/jwt-keys/contract-key", map[string]any{"kty": "OKP", "alg": "RS256"}, 400)
	call(apiSrv.URL, admin, "PUT", "/v1/playback-auth/jwt-keys/to-delete", viewerauthtest.NewKey(t, "ES256", "to-delete").PublicJWK(t), 200)
	call(apiSrv.URL, admin, "DELETE", "/v1/playback-auth/jwt-keys/to-delete", nil, 204)
	call(apiSrv.URL, admin, "DELETE", "/v1/playback-auth/jwt-keys/to-delete", nil, 404)
	rot := call(apiSrv.URL, admin, "POST", "/v1/playback-auth/callback-secret/rotate", nil, 200)
	if s, _ := rot["secret"].(string); len(s) != 50 {
		t.Fatalf("rotation = %v", rot)
	}
	faulty.SetOutage(true)
	call(apiSrv.URL, admin, "POST", "/v1/playback-auth/callback-secret/rotate", nil, 503)
	faulty.SetOutage(false)
	call(apiSrv.URL, admin, "PUT", "/v1/playback-auth", map[string]any{
		"jwt_enabled": true, "jwt_issuer": "https://issuer.example.com", "jwt_audiences": []string{"cipherframe"},
		"callback_enabled": true, "callback_url": "https://app.example.com/authorize",
	}, 200)
	// The API refuses a loopback URL (rightly), so the test points the stored callback at its own
	// TLS server directly; edge's test-only loopback allowance lets it through.
	cfg, err := repos.GetPlaybackAuth(ctx, res.Tenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CallbackURL = cbSrv.URL + "/authorize"
	if _, err := repos.PutPlaybackAuthConfig(ctx, res.Tenant.ID, cfg, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got := call(apiSrv.URL, admin, "GET", "/v1/playback-auth", nil, 200)
	if got["callback_secret_configured"] != true || got["callback_secret_version"] != float64(1) || len(got["jwt_keys"].([]any)) != 1 {
		t.Fatalf("settings = %v", got)
	}
	bad(apiSrv.URL, admin, "PUT", "/v1/playback-auth", map[string]any{"jwt_enabled": true, "callback_enabled": false}, 400)
	call(apiSrv.URL, nil, "GET", "/v1/playback-auth", nil, 401)

	// The browser-session operation.
	asset := readyAsset(t, repos, res, db.AssetReady)
	pending := readyAsset(t, repos, res, db.AssetCommitted)
	path := "/v1/play/tenants/" + res.Tenant.ID.String() + "/sessions"
	now := time.Now()
	jwtFor := func(a db.Asset, viewer string) map[string]string {
		c := viewerauthtest.Claims(now, "https://issuer.example.com", "cipherframe", a.ID.String(), viewer)
		return map[string]string{"Authorization": "Bearer " + ed.Sign(t, c)}
	}
	body := func(a db.Asset, method string) map[string]any {
		m := map[string]any{"asset_id": a.ID.String(), "method": method}
		if method == "callback" {
			m["ticket"] = "test-fixture-ticket"
		}
		return m
	}
	// Settings and configuration reach edge through caches of 30 seconds; nothing was read before.
	created := call(edgeSrv.URL, jwtFor(asset, "viewer-1"), "POST", path, body(asset, "jwt"), 201)
	if created["token_transport"] != "header" || created["session_id"] == nil {
		t.Fatalf("jwt session = %v", created)
	}
	cb.set(200, `{"allow": true, "viewer_id": "viewer-2"}`)
	call(edgeSrv.URL, nil, "POST", path, body(asset, "callback"), 201)
	call(edgeSrv.URL, nil, "POST", path, body(asset, "jwt"), 401) // no token
	call(edgeSrv.URL, map[string]string{"Authorization": "Bearer nope"}, "POST", path, body(asset, "jwt"), 401)
	cb.set(200, `{"allow": false}`)
	call(edgeSrv.URL, nil, "POST", path, body(asset, "callback"), 401)
	bad(edgeSrv.URL, nil, "POST", path, map[string]any{"asset_id": "nope", "method": "jwt"}, 400)
	bad(edgeSrv.URL, nil, "POST", path, map[string]any{"asset_id": asset.ID.String(), "method": "callback"}, 400)
	missing := db.Asset{ID: id.New[id.AssetKind]()}
	call(edgeSrv.URL, jwtFor(missing, "viewer-3"), "POST", path, body(missing, "jwt"), 404)
	call(edgeSrv.URL, jwtFor(pending, "viewer-3"), "POST", path, body(pending, "jwt"), 409) // asset_not_ready
	for range 2 {
		call(edgeSrv.URL, jwtFor(asset, "viewer-4"), "POST", path, body(asset, "jwt"), 201)
	}
	call(edgeSrv.URL, jwtFor(asset, "viewer-4"), "POST", path, body(asset, "jwt"), 201)
	call(edgeSrv.URL, jwtFor(asset, "viewer-4"), "POST", path, body(asset, "jwt"), 409) // session_limit
	cb.set(200, `{"allow": true, "viewer_id": "viewer-5"}`)
	faulty.SetOutage(true)
	call(edgeSrv.URL, nil, "POST", path, body(asset, "callback"), 503)
	faulty.SetOutage(false)

	ex := doBody(t, edgeSrv.URL, "OPTIONS", path, map[string]string{"Origin": "https://app.example.com", "Access-Control-Request-Method": "POST"}, nil)
	if ex.resp.StatusCode != 204 {
		t.Fatalf("preflight status %d", ex.resp.StatusCode)
	}
	for _, op := range []string{
		"getPlaybackAuth", "updatePlaybackAuth", "putPlaybackJwtKey", "deletePlaybackJwtKey", "rotatePlaybackCallbackSecret", "createBrowserPlaybackSession",
	} {
		if !covered[op] {
			t.Fatalf("%s was not exercised with a 2xx response; covered = %v", op, covered)
		}
	}
}

// callbackStub is a tenant's callback endpoint with a settable answer.
type callbackStub struct {
	status int
	body   string
}

func (c *callbackStub) set(status int, body string) { c.status, c.body = status, body }

func (c *callbackStub) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(c.status)
	_, _ = w.Write([]byte(c.body))
}
