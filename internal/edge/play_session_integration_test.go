//go:build integration

package edge_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/outbound"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth/viewerauthtest"
)

// Browser-started playback sessions (ADR 0029, 0031): the JWT and signed-callback providers.

const (
	vIssuer   = "https://issuer.example.com"
	vAudience = "cipherframe"
	vTicket   = "test-fixture-ticket-<&>-0123"
)

// viewerExtras tunes the browser-session route of an env.
type viewerExtras struct {
	pool *x509.CertPool // roots the outbound client trusts (the test servers' certificates)
	// denyLoopback turns the test-only loopback allowance OFF, as in production.
	denyLoopback bool
}

func (e *env) extras() *viewerExtras {
	if e.vx == nil {
		e.vx = &viewerExtras{pool: x509.NewCertPool()}
	}
	return e.vx
}

func (e *env) registry() *kms.Registry {
	reg, err := kms.NewRegistry(e.kms)
	if err != nil {
		e.t.Fatal(err)
	}
	return reg
}

func (e *env) adminSvc() *playback.Service {
	svc, err := playback.NewService(playback.Deps{
		Pool: e.pool, Keyring: e.keyring, EdgeURL: "https://media.example.com", KMS: e.registry(), Now: e.clk.Now,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return svc
}

func (e *env) viewerDeps() *edge.ViewerDeps {
	x := e.extras()
	reg := e.registry()
	verifier, err := viewerauth.NewVerifier(viewerauth.VerifierOptions{
		Client:         outbound.New(outbound.Options{AllowLoopback: !x.denyLoopback, RootCAs: x.pool, Timeout: 3 * time.Second}),
		ValidateViewer: playback.ValidateViewerID, Now: e.clk.Now,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	cb, err := viewerauth.NewAuthorizer(viewerauth.AuthorizerOptions{
		Client:         outbound.New(outbound.Options{AllowLoopback: !x.denyLoopback, RootCAs: x.pool, Timeout: viewerauth.CallbackTimeout}),
		ValidateViewer: playback.ValidateViewerID, Now: e.clk.Now,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return &edge.ViewerDeps{
		Sessions: e.adminSvc(), Store: e.repos, Secrets: viewerauth.NewSecretBox(reg), Verifier: verifier, Callback: cb,
	}
}

// tlsServer starts a TLS server that the edge's outbound client trusts.
func (e *env) tlsServer(h http.Handler) *httptest.Server {
	e.t.Helper()
	srv := httptest.NewTLSServer(h)
	e.t.Cleanup(srv.Close)
	e.extras().pool.AddCert(srv.Certificate())
	return srv
}

func (e *env) postJSON(path string, body any, hdr map[string]string) reply {
	e.t.Helper()
	var b []byte
	switch v := body.(type) {
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		var err error
		if b, err = json.Marshal(body); err != nil {
			e.t.Fatal(err)
		}
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, e.srv.URL+path, bytes.NewReader(b))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return reply{resp.StatusCode, resp.Header, out}
}

func (e *env) sessionsPath() string {
	return "/v1/play/tenants/" + e.res.Tenant.ID.String() + "/sessions"
}

// viaJWT asks for a session with a JWT.
func (e *env) viaJWT(tok string) reply {
	e.t.Helper()
	return e.postJSON(e.sessionsPath(), map[string]any{"asset_id": e.asset.ID.String(), "method": "jwt"}, bearer(tok))
}

// viaCallback asks for a session with a callback ticket.
func (e *env) viaCallback(ticket string) reply {
	e.t.Helper()
	return e.postJSON(e.sessionsPath(), map[string]any{"asset_id": e.asset.ID.String(), "method": "callback", "ticket": ticket}, nil)
}

func (e *env) configure(edit func(*db.PlaybackAuth)) {
	e.t.Helper()
	ctx := context.Background()
	a, err := e.repos.GetPlaybackAuth(ctx, e.res.Tenant.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	a.JWTViewerClaim = db.DefaultViewerClaim
	edit(&a)
	if _, err := e.repos.PutPlaybackAuthConfig(ctx, e.res.Tenant.ID, a, time.Now().UTC()); err != nil {
		e.t.Fatal(err)
	}
	e.clk.advance(playbackCacheTTL) // the edge may have cached the old configuration
}

func (e *env) enableJWT(jwksURL string) {
	e.t.Helper()
	e.configure(func(a *db.PlaybackAuth) {
		a.JWTEnabled, a.JWTIssuer, a.JWTAudiences, a.JWKSURL = true, vIssuer, []string{vAudience, "second"}, jwksURL
	})
}

func (e *env) uploadKey(k viewerauthtest.Key) {
	e.t.Helper()
	ctx := context.Background()
	pk, err := viewerauth.ParseUploadedJWK(k.Kid, k.PublicJWK(e.t))
	if err != nil {
		e.t.Fatal(err)
	}
	if err := db.Tx(ctx, e.pool, func(tx *db.Repos) error {
		_, err := tx.PutPlaybackJWTKey(ctx, e.res.Tenant.ID, db.PlaybackJWTKey{Kid: k.Kid, Alg: pk.Alg, JWK: pk.JWK}, time.Now().UTC())
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	e.clk.advance(playbackCacheTTL)
}

func (e *env) claims(viewer string) map[string]any {
	return viewerauthtest.Claims(e.clk.Now(), vIssuer, vAudience, e.asset.ID.String(), viewer)
}

// rotate rotates the tenant's callback secret and returns it ("whsec_...") and its version.
func (e *env) rotate() (string, int) {
	e.t.Helper()
	r, err := e.adminSvc().RotateCallbackSecret(context.Background(), e.res.Tenant.ID, auth.Actor{ClientID: e.res.Client.ID})
	if err != nil {
		e.t.Fatal(err)
	}
	return r.Secret.Reveal(), r.Version
}

func (e *env) enableCallback(url string) {
	e.t.Helper()
	e.configure(func(a *db.PlaybackAuth) { a.CallbackEnabled, a.CallbackURL = true, url })
}

// sessionCount counts the tenant's sessions by auth method.
func (e *env) sessionCount(method string) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM playback_sessions WHERE tenant_id = $1 AND auth_method = $2",
		e.res.Tenant.ID.UUID(), method).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func decode(t *testing.T, r reply) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.body, &m); err != nil {
		t.Fatalf("not JSON: %v: %s", err, r.body)
	}
	return m
}

// wantCreated checks a 201 and returns the session's ID and token.
func (e *env) wantCreated(r reply) session {
	e.t.Helper()
	want(e.t, r, 201)
	if r.hdr.Get("Cache-Control") != "no-store" {
		e.t.Fatalf("Cache-Control = %q", r.hdr.Get("Cache-Control"))
	}
	m := decode(e.t, r)
	for _, k := range []string{"session_id", "token", "token_expires_at", "heartbeat_interval_seconds", "session_expires_at", "manifest_url", "token_transport"} {
		if _, ok := m[k]; !ok {
			e.t.Fatalf("response lacks %s: %s", k, r.body)
		}
	}
	return session{id: m["session_id"].(string), token: m["token"].(string)}
}

// wantDenied checks the generic 401 and returns its body with the request ID removed, so that
// every cause can be shown to look the same.
func wantDenied(t *testing.T, name string, r reply) string {
	t.Helper()
	if r.status != 401 {
		t.Fatalf("%s: status = %d, want 401; body %s", name, r.status, r.body)
	}
	if r.hdr.Get("WWW-Authenticate") != "Bearer" || r.hdr.Get("Cache-Control") != "no-store" || r.hdr.Get("Content-Type") != "application/problem+json" {
		t.Fatalf("%s: headers = %v", name, r.hdr)
	}
	m := decode(t, r)
	if m["code"] != "unauthenticated" {
		t.Fatalf("%s: code = %v", name, m["code"])
	}
	delete(m, "request_id")
	b, _ := json.Marshal(m)
	return string(b)
}

func TestViewerJWTWithUploadedKeys(t *testing.T) {
	e := newEnv(t)
	e.enableJWT("")
	ctx := context.Background()
	keys := map[string]viewerauthtest.Key{}
	for _, alg := range []string{"EdDSA", "ES256", "RS256"} {
		k := viewerauthtest.NewKey(t, alg, "key-"+alg)
		keys[alg] = k
		e.uploadKey(k)
		s := e.wantCreated(e.viaJWT(k.Sign(t, e.claims("viewer-"+alg))))
		// The session is the viewer's, made without a client, and it plays.
		sid, err := parseSession(s.id)
		if err != nil {
			t.Fatal(err)
		}
		row, err := e.repos.GetPlaybackSession(ctx, e.res.Tenant.ID, db.SessionHash(sid))
		if err != nil || row.AuthMethod != db.AuthMethodJWT || !row.ClientID.IsZero() || row.ViewerID != "viewer-"+alg || row.AssetID != e.asset.ID {
			t.Fatalf("%s: row %+v, err %v", alg, row, err)
		}
		want(t, e.get("/v1/play/"+s.id+"/master.m3u8", s.token), 200)
	}
	if n := e.sessionCount(db.AuthMethodJWT); n != 3 {
		t.Fatalf("jwt sessions = %d", n)
	}
	// An aud list that contains one configured audience, a custom viewer claim, nbf and iat as sent.
	e.configure(func(a *db.PlaybackAuth) { a.JWTViewerClaim = "uid" })
	k := keys["EdDSA"]
	c := e.claims("ignored")
	c["aud"], c["uid"] = []string{"other", "second"}, "viewer-uid"
	e.wantCreated(e.viaJWT(k.Sign(t, c)))

	// The used jti rows are removed by the sweeper once the tokens could no longer verify.
	var n int
	if err := e.pool.QueryRow(ctx, "SELECT count(*) FROM playback_jwt_jti WHERE tenant_id = $1", e.res.Tenant.ID.UUID()).Scan(&n); err != nil || n != 4 {
		t.Fatalf("jti rows = %d, %v", n, err)
	}
	if got, err := playback.SweepJWTIDs(ctx, e.repos, time.Now()); err != nil || got != 0 {
		t.Fatalf("early sweep: %d %v", got, err)
	}
	if got, err := playback.SweepJWTIDs(ctx, e.repos, time.Now().Add(2*time.Hour)); err != nil || got != 4 {
		t.Fatalf("sweep: %d %v", got, err)
	}
}

func TestViewerJWTNegatives(t *testing.T) {
	e := newEnv(t)
	e.enableJWT("")
	ed := viewerauthtest.NewKey(t, "EdDSA", "k-ed")
	rs := viewerauthtest.NewKey(t, "RS256", "k-rs")
	e.uploadKey(ed)
	e.uploadKey(rs)
	edPub, err := viewerauth.ParseUploadedJWK("k-ed", ed.PublicJWK(t))
	if err != nil {
		t.Fatal(err)
	}
	now := e.clk.Now()
	with := func(name string, v any) map[string]any {
		c := e.claims("viewer-1")
		if v == nil {
			delete(c, name)
		} else {
			c[name] = v
		}
		return c
	}
	cases := map[string]string{
		"alg none":                         viewerauthtest.UnsignedToken(t, "k-ed", e.claims("v")),
		"HS256 signed with the public key": viewerauthtest.HS256Token(t, "k-ed", edPub.JWK, e.claims("v")),
		"HS256 with the RSA public key":    viewerauthtest.HS256Token(t, "k-rs", rs.PublicJWK(t), e.claims("v")),
		"wrong audience":                   ed.Sign(t, with("aud", "someone-else")),
		"wrong issuer":                     ed.Sign(t, with("iss", "https://evil.example.com")),
		"expired beyond the skew":          ed.Sign(t, with("exp", now.Add(-61*time.Second).Unix())),
		"nbf in the future":                ed.Sign(t, with("nbf", now.Add(2*time.Minute).Unix())),
		"missing jti":                      ed.Sign(t, with("jti", nil)),
		"missing exp":                      ed.Sign(t, with("exp", nil)),
		"unknown kid":                      viewerauthtest.NewKey(t, "EdDSA", "k-unknown").Sign(t, e.claims("v")),
		"key used with a different alg":    viewerauthtest.NewKey(t, "ES256", "k-ed").Sign(t, e.claims("v")),
		"RS256 token for the EdDSA kid":    viewerauthtest.NewKey(t, "RS256", "k-ed").Sign(t, e.claims("v")),
		"signed by another key":            viewerauthtest.NewKey(t, "EdDSA", "k-ed").Sign(t, e.claims("v")),
		"wrong asset_id claim":             ed.Sign(t, with("asset_id", id.New[id.AssetKind]().String())),
		"missing asset_id claim":           ed.Sign(t, with("asset_id", nil)),
		"missing viewer claim":             ed.Sign(t, with("sub", nil)),
		"garbage":                          "not.a.jwt",
		"empty bearer":                     "",
	}
	var first string
	for name, tok := range cases {
		hdr := bearer(tok)
		if tok == "" {
			hdr = nil
		}
		body := wantDenied(t, name, e.postJSON(e.sessionsPath(), map[string]any{"asset_id": e.asset.ID.String(), "method": "jwt"}, hdr))
		if first == "" {
			first = body
		} else if body != first {
			t.Errorf("%s: the denial differs from the others:\n%s\n%s", name, body, first)
		}
	}
	if n := e.sessionCount(db.AuthMethodJWT); n != 0 {
		t.Fatalf("%d sessions were created by refused tokens", n)
	}

	// A replayed jti: the first use works, every later use is the same denial.
	tok := ed.Sign(t, e.claims("viewer-replay"))
	e.wantCreated(e.viaJWT(tok))
	for range 2 {
		if body := wantDenied(t, "replay", e.viaJWT(tok)); body != first {
			t.Fatalf("replay denial differs: %s", body)
		}
	}
	// The same jti from another token is a replay too; a fresh jti is not.
	c := e.claims("viewer-replay")
	c["jti"] = decodeJTI(t, tok)
	wantDenied(t, "same jti, new token", e.viaJWT(ed.Sign(t, c)))
	e.wantCreated(e.viaJWT(ed.Sign(t, e.claims("viewer-replay"))))

	// Two concurrent uses of one token: exactly one wins.
	race := ed.Sign(t, e.claims("viewer-race"))
	var wg sync.WaitGroup
	var mu sync.Mutex
	created := 0
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := e.viaJWT(race); r.status == 201 {
				mu.Lock()
				created++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if created != 1 {
		t.Fatalf("%d concurrent uses of one token created a session, want 1", created)
	}

	// A token is for one tenant: the right key for another tenant's path is no key at all.
	otherRes, err := auth.NewManager(e.pool, pepper{}, nil).Bootstrap(context.Background(), "other", "other client")
	if err != nil {
		t.Fatal(err)
	}
	otherAsset := readyAsset(t, e.repos, otherRes)
	r := e.postJSON("/v1/play/tenants/"+otherRes.Tenant.ID.String()+"/sessions", map[string]any{"asset_id": otherAsset.ID.String(), "method": "jwt"},
		bearer(ed.Sign(t, viewerauthtest.Claims(now, vIssuer, vAudience, otherAsset.ID.String(), "v"))))
	if body := wantDenied(t, "tenant without configuration", r); body != first {
		t.Fatalf("no-configuration denial differs: %s", body)
	}
	// A tenant that is not configured, an unknown tenant and a switched-off method are the same 401.
	unknown := id.New[id.TenantKind]().String()
	wantDenied(t, "unknown tenant", e.postJSON("/v1/play/tenants/"+unknown+"/sessions", map[string]any{"asset_id": e.asset.ID.String(), "method": "jwt"}, bearer(ed.Sign(t, e.claims("v")))))
	e.configure(func(a *db.PlaybackAuth) { a.JWTEnabled = false })
	wantDenied(t, "jwt off", e.viaJWT(ed.Sign(t, e.claims("v"))))
	wantDenied(t, "callback method with nothing configured", e.viaCallback(vTicket))
}

// tamper changes the first character of the token's signature, which carries six whole bits.
func tamper(tok string) string {
	parts := strings.Split(tok, ".")
	c := byte('A')
	if parts[2][0] == 'A' {
		c = 'B'
	}
	parts[2] = string(c) + parts[2][1:]
	return strings.Join(parts, ".")
}

func parseSession(s string) (id.SessionID, error) { return id.ParseSession(s) }

func decodeSegment(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func decodeJTI(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	payload, err := decodeSegment(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	return c.JTI
}

func TestViewerRequestValidation(t *testing.T) {
	e := newEnv(t)
	e.enableJWT("")
	ed := viewerauthtest.NewKey(t, "EdDSA", "k")
	e.uploadKey(ed)
	tok := func() map[string]string { return bearer(ed.Sign(t, e.claims("v"))) }
	asset := e.asset.ID.String()
	cases := map[string]struct {
		body   any
		status int
	}{
		"not json":                {`nope`, 400},
		"no method":               {map[string]any{"asset_id": asset}, 400},
		"unknown method":          {map[string]any{"asset_id": asset, "method": "basic"}, 400},
		"bad asset id":            {map[string]any{"asset_id": "ast_nope", "method": "jwt"}, 400},
		"callback without ticket": {map[string]any{"asset_id": asset, "method": "callback"}, 400},
		"ticket too long":         {map[string]any{"asset_id": asset, "method": "callback", "ticket": strings.Repeat("t", 2049)}, 400},
		"body too large":          {map[string]any{"asset_id": asset, "method": "jwt", "ticket": strings.Repeat("t", 9<<10)}, 400},
		"asset of nobody":         {map[string]any{"asset_id": id.New[id.AssetKind]().String(), "method": "jwt"}, 401}, // the token's asset_id differs
	}
	for name, c := range cases {
		r := e.postJSON(e.sessionsPath(), c.body, tok())
		if r.status != c.status && (c.status != 400 || r.status != 413) {
			t.Errorf("%s: status %d, want %d: %s", name, r.status, c.status, r.body)
		}
		if strings.Contains(string(r.body), "test-fixture") {
			t.Errorf("%s: the error echoes input", name)
		}
	}
	// A malformed tenant ID in the path is a 404.
	want(t, e.postJSON("/v1/play/tenants/ten_nope/sessions", map[string]any{"asset_id": asset, "method": "jwt"}, tok()), 404)

	// An asset that does not exist or is not ready is reported after the viewer is authorised.
	missing := id.New[id.AssetKind]().String()
	c := viewerauthtest.Claims(e.clk.Now(), vIssuer, vAudience, missing, "v")
	r := e.postJSON(e.sessionsPath(), map[string]any{"asset_id": missing, "method": "jwt"}, bearer(ed.Sign(t, c)))
	want(t, r, 404)
	if decode(t, r)["code"] != "not_found" {
		t.Fatalf("body = %s", r.body)
	}
}

func TestViewerJWTViaJWKS(t *testing.T) {
	e := newEnv(t)
	first := viewerauthtest.NewKey(t, "ES256", "jwks-1")
	second := viewerauthtest.NewKey(t, "RS256", "jwks-2")
	var mu sync.Mutex
	published := []viewerauthtest.Key{first}
	var hits int
	srv := e.tlsServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		hits++
		if r.URL.Path != "/jwks.json" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(viewerauthtest.JWKS(t, published...))
	}))
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return hits
	}
	e.enableJWT(srv.URL + "/jwks.json")

	e.wantCreated(e.viaJWT(first.Sign(t, e.claims("viewer-a"))))
	e.wantCreated(e.viaJWT(first.Sign(t, e.claims("viewer-b"))))
	if count() != 1 {
		t.Fatalf("JWKS fetches = %d, want 1 (cached)", count())
	}

	// The tenant publishes a second key. Within 30 seconds of the last fetch a token that names it
	// is refused and nothing is refetched; a flood of unknown kids refetches nothing either.
	mu.Lock()
	published = []viewerauthtest.Key{first, second}
	mu.Unlock()
	e.clk.advance(5 * time.Second)
	wantDenied(t, "new kid too soon", e.viaJWT(second.Sign(t, e.claims("viewer-c"))))
	for range 5 {
		wantDenied(t, "unknown kid", e.viaJWT(viewerauthtest.NewKey(t, "EdDSA", "nope").Sign(t, e.claims("v"))))
	}
	if count() != 1 {
		t.Fatalf("JWKS fetches within the rate limit = %d, want 1", count())
	}
	// After 30 seconds the unknown kid triggers one refetch and the token is accepted.
	e.clk.advance(30 * time.Second)
	e.wantCreated(e.viaJWT(second.Sign(t, e.claims("viewer-c"))))
	if count() != 2 {
		t.Fatalf("JWKS fetches = %d, want 2", count())
	}
	// Uploaded keys are tried first and cost no fetch.
	up := viewerauthtest.NewKey(t, "EdDSA", "uploaded")
	e.uploadKey(up)
	before := count()
	e.wantCreated(e.viaJWT(up.Sign(t, e.claims("viewer-d"))))
	if count() != before {
		t.Fatalf("an uploaded key caused a fetch")
	}
}

func TestViewerJWKSProblems(t *testing.T) {
	e := newEnv(t)
	k := viewerauthtest.NewKey(t, "EdDSA", "jwks-1")
	var mu sync.Mutex
	mode := "big"
	var hits int
	srv := e.tlsServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		m := mode
		hits++
		mu.Unlock()
		switch m {
		case "big":
			_, _ = w.Write(append(viewerauthtest.JWKS(t, k), bytes.Repeat([]byte(" "), 65<<10)...))
		case "redirect":
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		case "500":
			w.WriteHeader(500)
		default:
			_, _ = w.Write(viewerauthtest.JWKS(t, k))
		}
	}))
	e.enableJWT(srv.URL + "/jwks.json")
	for _, m := range []string{"big", "redirect", "500"} {
		mu.Lock()
		mode = m
		mu.Unlock()
		e.clk.advance(time.Minute)
		wantDenied(t, m, e.viaJWT(k.Sign(t, e.claims("v"))))
	}
	mu.Lock()
	mode = "ok"
	mu.Unlock()
	e.clk.advance(time.Minute)
	e.wantCreated(e.viaJWT(k.Sign(t, e.claims("v"))))
}

// recorder is a callback endpoint: it records requests and answers as the test says.
type recorder struct {
	mu   sync.Mutex
	hits int
	hdr  http.Header
	body []byte
	h    http.HandlerFunc
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.hits++
	r.hdr, r.body = req.Header.Clone(), b
	h := r.h
	r.mu.Unlock()
	h(w, req)
}

func (r *recorder) last() (int, http.Header, []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits, r.hdr, r.body
}

func (r *recorder) set(h http.HandlerFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.h = h
}

func answer(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

const allowAnswer = `{"allow": true, "viewer_id": "viewer-cb"}`

func TestViewerCallbackAllow(t *testing.T) {
	e := newEnv(t)
	rec := &recorder{h: answer(200, allowAnswer)}
	srv := e.tlsServer(rec)
	secret, _ := e.rotate()
	e.enableCallback(srv.URL + "/authorize-test-fixture")

	r := e.viaCallback(vTicket)
	s := e.wantCreated(r)
	sid, err := parseSession(s.id)
	if err != nil {
		t.Fatal(err)
	}
	row, err := e.repos.GetPlaybackSession(context.Background(), e.res.Tenant.ID, db.SessionHash(sid))
	if err != nil || row.AuthMethod != db.AuthMethodCallback || !row.ClientID.IsZero() || row.ViewerID != "viewer-cb" {
		t.Fatalf("row %+v, err %v", row, err)
	}
	want(t, e.get("/v1/play/"+s.id+"/master.m3u8", s.token), 200)

	// What the tenant received: a signed Standard Webhooks request.
	hits, hdr, body := rec.last()
	if hits != 1 || hdr.Get("Content-Type") != "application/json" {
		t.Fatalf("hits %d, headers %v", hits, hdr)
	}
	n, err := viewerauthtest.VerifyWebhook(secret, hdr, body, e.clk.Now(), 5*time.Minute)
	if err != nil || n != 1 {
		t.Fatalf("reference verifier: %d signatures, %v", n, err)
	}
	var got map[string]string
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["type"] != "playback.authorize" || got["tenant_id"] != e.res.Tenant.ID.String() || got["asset_id"] != e.asset.ID.String() ||
		got["ticket"] != vTicket || got["request_id"] != r.hdr.Get("X-Request-Id") || len(got) != 6 {
		t.Fatalf("callback body = %v (response request id %q)", got, r.hdr.Get("X-Request-Id"))
	}
	// A signature made with another secret does not verify.
	if _, err := viewerauthtest.VerifyWebhook(viewerauth.FormatSecret(bytes.Repeat([]byte{1}, 32)), hdr, body, e.clk.Now(), 5*time.Minute); err == nil {
		t.Fatal("verified with the wrong secret")
	}
	// Not cached: every session creation asks again.
	e.wantCreated(e.viaCallback(vTicket))
	if hits, _, _ := rec.last(); hits != 2 {
		t.Fatalf("callback hits = %d, want 2", hits)
	}
	// The callback decides first, then the asset is checked: an unknown asset is a 404.
	missing := id.New[id.AssetKind]().String()
	want(t, e.postJSON(e.sessionsPath(), map[string]any{"asset_id": missing, "method": "callback", "ticket": vTicket}, nil), 404)
	// A viewer ID the callback returns is validated like any other.
	rec.set(answer(200, `{"allow": true, "viewer_id": "`+strings.Repeat("v", 129)+`"}`))
	wantDenied(t, "bad viewer id", e.viaCallback(vTicket))
}

func TestViewerCallbackDenials(t *testing.T) {
	e := newEnv(t)
	var targetHits int
	var tmu sync.Mutex
	rec := &recorder{h: answer(200, allowAnswer)}
	srv := e.tlsServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			tmu.Lock()
			targetHits++
			tmu.Unlock()
			_, _ = w.Write([]byte(allowAnswer))
			return
		}
		rec.ServeHTTP(w, r)
	}))
	e.rotate()
	e.enableCallback(srv.URL + "/authorize")

	cases := []struct {
		name string
		h    http.HandlerFunc
	}{
		{"allow false", answer(200, `{"allow": false}`)},
		{"allow false with a viewer", answer(200, `{"allow": false, "viewer_id": "viewer-cb"}`)},
		{"403", answer(403, allowAnswer)},
		{"500", answer(500, allowAnswer)},
		{"202", answer(202, allowAnswer)},
		{"not json", answer(200, `ok`)},
		{"allow as a string", answer(200, `{"allow": "true", "viewer_id": "v"}`)},
		{"missing allow", answer(200, `{"viewer_id": "v"}`)},
		{"missing viewer", answer(200, `{"allow": true}`)},
		{"unknown field", answer(200, `{"allow": true, "viewer_id": "v", "x": 1}`)},
		{"oversized body", answer(200, allowAnswer+strings.Repeat(" ", 9<<10))},
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/target", http.StatusTemporaryRedirect)
		}},
	}
	var first string
	for _, c := range cases {
		rec.set(c.h)
		body := wantDenied(t, c.name, e.viaCallback(vTicket))
		if first == "" {
			first = body
		} else if body != first {
			t.Errorf("%s: the denial differs from the others", c.name)
		}
	}
	tmu.Lock()
	defer tmu.Unlock()
	if targetHits != 0 {
		t.Fatal("a redirect was followed")
	}
	if n := e.sessionCount(db.AuthMethodCallback); n != 0 {
		t.Fatalf("%d sessions created by denied callbacks", n)
	}
}

func TestViewerCallbackTimeout(t *testing.T) {
	e := newEnv(t)
	rec := &recorder{h: func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
		}
		_, _ = w.Write([]byte(allowAnswer))
	}}
	srv := e.tlsServer(rec)
	e.rotate()
	e.enableCallback(srv.URL)
	start := time.Now()
	r := e.viaCallback(vTicket)
	took := time.Since(start)
	wantDenied(t, "timeout", r)
	if took < 1500*time.Millisecond || took > 2800*time.Millisecond {
		t.Fatalf("the callback was abandoned after %v, want about 2s", took)
	}
	if n := e.sessionCount(db.AuthMethodCallback); n != 0 {
		t.Fatalf("%d sessions created after a timeout", n)
	}
}

func TestViewerCallbackSecretRotationOverlap(t *testing.T) {
	e := newEnv(t)
	rec := &recorder{h: answer(200, allowAnswer)}
	srv := e.tlsServer(rec)
	first, v1 := e.rotate()
	e.enableCallback(srv.URL)

	signatures := func(secrets ...string) int {
		t.Helper()
		e.wantCreated(e.viaCallback(vTicket))
		_, hdr, body := rec.last()
		count := 0
		for _, s := range secrets {
			n, err := viewerauthtest.VerifyWebhook(s, hdr, body, e.clk.Now(), 5*time.Minute)
			if err != nil {
				t.Fatalf("a tenant holding %s... does not verify: %v", s[:9], err)
			}
			count = n
		}
		return count
	}
	// One secret, one signature.
	if n := signatures(first); n != 1 || v1 != 1 {
		t.Fatalf("signatures = %d (version %d), want 1", n, v1)
	}
	// After a rotation the callback carries two, and either secret verifies.
	second, v2 := e.rotate()
	if n := signatures(first, second); n != 2 || v2 != 2 {
		t.Fatalf("signatures = %d (version %d), want 2 during the overlap", n, v2)
	}
	// After 24 hours the previous secret no longer signs: one signature, the current secret only.
	e.clk.advance(24*time.Hour + time.Minute)
	if n := signatures(second); n != 1 {
		t.Fatalf("signatures = %d, want 1 after the overlap", n)
	}
	_, hdr, body := rec.last()
	if _, err := viewerauthtest.VerifyWebhook(first, hdr, body, e.clk.Now(), 5*time.Minute); err == nil {
		t.Fatal("the previous secret still signs after 24 hours")
	}
}

func TestViewerCallbackKMSFailureIs503(t *testing.T) {
	e := newEnv(t)
	rec := &recorder{h: answer(200, allowAnswer)}
	srv := e.tlsServer(rec)
	e.rotate()
	e.enableCallback(srv.URL)

	e.kms.SetOutage(true)
	r := e.viaCallback(vTicket)
	want(t, r, 503)
	if decode(t, r)["code"] != "dependency_unavailable" {
		t.Fatalf("body = %s", r.body)
	}
	if hits, _, _ := rec.last(); hits != 0 {
		t.Fatal("the tenant's callback was called although the secret could not be unwrapped")
	}
	e.kms.SetOutage(false)
	e.wantCreated(e.viaCallback(vTicket))

	// A damaged envelope is our failure too, not the tenant's denial.
	if _, err := e.pool.Exec(context.Background(), "UPDATE playback_auth SET callback_secret_envelope = '\\x0100' WHERE tenant_id = $1", e.res.Tenant.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	want(t, e.viaCallback(vTicket), 503)
}

func TestViewerCallbackDisabled(t *testing.T) {
	e := newEnv(t)
	rec := &recorder{h: answer(200, allowAnswer)}
	srv := e.tlsServer(rec)
	e.rotate()
	e.enableCallback(srv.URL)
	e.wantCreated(e.viaCallback(vTicket))
	// Switching it off applies at once (the callback configuration is not cached).
	e.configure(func(a *db.PlaybackAuth) { a.CallbackEnabled = false })
	wantDenied(t, "callback off", e.viaCallback(vTicket))
	if hits, _, _ := rec.last(); hits != 1 {
		t.Fatalf("callback hits = %d, want 1", hits)
	}
}

func TestViewerSSRFGuard(t *testing.T) {
	e := newEnv(t)
	e.extras().denyLoopback = true // production behaviour: loopback is refused
	e.start()

	var mu sync.Mutex
	hits := 0
	count := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		_, _ = w.Write([]byte(allowAnswer))
	})
	srv := e.tlsServer(count)
	ed := viewerauthtest.NewKey(t, "EdDSA", "not-uploaded")
	e.rotate()
	port := srv.URL[strings.LastIndex(srv.URL, ":"):]

	urls := []string{
		srv.URL,                                     // 127.0.0.1: a real, trusted TLS server on loopback
		"https://localhost" + port + "/x",           // a name that resolves to loopback
		"https://127.0.0.1:1/x",                     //
		"https://10.0.0.1/x",                        // RFC 1918
		"https://172.16.5.5/x",                      //
		"https://192.168.1.1/x",                     //
		"https://169.254.169.254/latest/meta-data/", // cloud metadata
		"https://[::1]" + port + "/x",               // IPv6 loopback
		"https://[fd00::1]/x",                       // ULA
		"https://[fe80::1]/x",                       // link-local
		"https://100.64.0.1/x",                      // CGNAT
		"https://0.0.0.0/x",                         // unspecified
		"https://224.0.0.1/x",                       // multicast
		"https://[::ffff:10.0.0.1]/x",               // IPv4-mapped
	}
	for _, u := range urls {
		// JWKS: a token whose kid is not uploaded makes edge fetch the JWKS.
		e.enableJWT(u)
		start := time.Now()
		wantDenied(t, "jwks "+u, e.viaJWT(ed.Sign(t, e.claims("v"))))
		if time.Since(start) > time.Second {
			t.Errorf("jwks %s: refusing took %v", u, time.Since(start))
		}
		e.clk.advance(time.Minute) // past the refetch rate limit, so each URL is really tried
		// Callback.
		e.enableCallback(u)
		start = time.Now()
		wantDenied(t, "callback "+u, e.viaCallback(vTicket))
		if time.Since(start) > time.Second {
			t.Errorf("callback %s: refusing took %v", u, time.Since(start))
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Fatalf("the guard let %d requests through to the loopback server", hits)
	}
}

func TestViewerSessionsCountTowardTheViewerLimit(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) { s.MaxSessionsPerViewer = 2 })
	ed := viewerauthtest.NewKey(t, "EdDSA", "k")
	e.enableJWT("")
	e.uploadKey(ed)
	rec := &recorder{h: answer(200, `{"allow": true, "viewer_id": "shared"}`)}
	srv := e.tlsServer(rec)
	e.rotate()
	e.enableCallback(srv.URL)

	e.session("shared") // an API-key session of the same viewer
	e.wantCreated(e.viaJWT(ed.Sign(t, e.claims("shared"))))
	// The third, by either method, is over the limit.
	for name, r := range map[string]reply{
		"jwt":      e.viaJWT(ed.Sign(t, e.claims("shared"))),
		"callback": e.viaCallback(vTicket),
	} {
		want(t, r, 409)
		if decode(t, r)["code"] != "session_limit" {
			t.Fatalf("%s: body = %s", name, r.body)
		}
	}
	// Another viewer is not affected.
	e.wantCreated(e.viaJWT(ed.Sign(t, e.claims("someone-else"))))
	// Ending the viewer's session frees a slot, for either method.
	if _, err := e.pool.Exec(context.Background(), "UPDATE playback_sessions SET state = 'ended', ended_at = now() WHERE tenant_id = $1 AND viewer_id = 'shared' AND auth_method = 'jwt'", e.res.Tenant.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	e.wantCreated(e.viaCallback(vTicket))
}

func TestViewerSessionCORS(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) { s.AllowedOrigins = []string{testOrigin} })
	path := e.sessionsPath()
	preflight := func(path, origin string) reply {
		h := map[string]string{"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization, content-type"}
		if origin != "" {
			h["Origin"] = origin
		}
		return e.do("OPTIONS", path, h)
	}

	r := preflight(path, testOrigin)
	want(t, r, 204)
	if r.hdr.Get("Access-Control-Allow-Origin") != testOrigin || !strings.Contains(r.hdr.Get("Access-Control-Allow-Methods"), "POST") ||
		!strings.Contains(r.hdr.Get("Access-Control-Allow-Headers"), "Authorization") || !strings.Contains(r.hdr.Get("Access-Control-Allow-Headers"), "Content-Type") ||
		r.hdr.Get("Access-Control-Allow-Credentials") != "" || !strings.Contains(strings.Join(r.hdr.Values("Vary"), ","), "Origin") {
		t.Fatalf("preflight headers = %v", r.hdr)
	}
	// Any other origin, no origin, an unknown tenant and a malformed one: 204, no CORS headers.
	for name, r := range map[string]reply{
		"other origin":   preflight(path, "https://evil.example.com"),
		"no origin":      preflight(path, ""),
		"unknown tenant": preflight("/v1/play/tenants/"+id.New[id.TenantKind]().String()+"/sessions", testOrigin),
		"malformed":      preflight("/v1/play/tenants/nope/sessions", testOrigin),
	} {
		want(t, r, 204)
		if r.hdr.Get("Access-Control-Allow-Origin") != "" || r.hdr.Get("Access-Control-Allow-Methods") != "" {
			t.Errorf("%s: CORS headers %v", name, r.hdr)
		}
	}

	// The real request carries the CORS header for an allowed origin, on success and on denial.
	ed := viewerauthtest.NewKey(t, "EdDSA", "k")
	e.enableJWT("")
	e.uploadKey(ed)
	hdr := bearer(ed.Sign(t, e.claims("v")))
	hdr["Origin"] = testOrigin
	body := map[string]any{"asset_id": e.asset.ID.String(), "method": "jwt"}
	if r := e.postJSON(path, body, hdr); r.status != 201 || r.hdr.Get("Access-Control-Allow-Origin") != testOrigin {
		t.Fatalf("201 without CORS: %d %v", r.status, r.hdr)
	}
	hdr["Authorization"] = "Bearer nope"
	if r := e.postJSON(path, body, hdr); r.status != 401 || r.hdr.Get("Access-Control-Allow-Origin") != testOrigin {
		t.Fatalf("401 without CORS: %d %v", r.status, r.hdr)
	}
	hdr["Origin"] = "https://evil.example.com"
	if r := e.postJSON(path, body, hdr); r.hdr.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("CORS for another origin: %v", r.hdr)
	}
	// The other playback preflights are unchanged.
	s := e.session("viewer-x")
	pr := e.do("OPTIONS", "/v1/play/"+s.id+"/master.m3u8", map[string]string{"Origin": testOrigin, "Access-Control-Request-Method": "GET"})
	want(t, pr, 204)
	if pr.hdr.Get("Access-Control-Allow-Origin") != testOrigin {
		t.Fatalf("session preflight lost its CORS headers: %v", pr.hdr)
	}
}

func TestViewerRouteUnavailableWithoutDeps(t *testing.T) {
	e := newEnv(t)
	p, err := edge.NewPlayback(edge.PlaybackDeps{Keyring: e.keyring, Store: e.repos, Delivery: e.store, Now: e.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(edge.New(edge.Deps{Log: e.log, Playback: p}).Handler())
	defer srv.Close()
	e.srv.Close()
	e.srv = srv
	r := e.viaJWT("whatever")
	want(t, r, 503)
	if decode(t, r)["code"] != "dependency_unavailable" {
		t.Fatalf("body = %s", r.body)
	}
}

func TestViewerNothingSecretReachesTheLogs(t *testing.T) {
	e := newEnv(t)
	ed := viewerauthtest.NewKey(t, "EdDSA", "k")
	e.enableJWT("")
	e.uploadKey(ed)
	rec := &recorder{h: answer(200, allowAnswer)}
	srv := e.tlsServer(rec)
	secret, _ := e.rotate()
	e.enableCallback(srv.URL + "/authorize-test-fixture-path")

	jwtTok := ed.Sign(t, e.claims("viewer-log"))
	var sensitive []string
	j := e.wantCreated(e.viaJWT(jwtTok))
	c := e.wantCreated(e.viaCallback(vTicket))
	sensitive = append(sensitive, jwtTok, strings.Split(jwtTok, ".")[2], vTicket, secret, secret[len("whsec_"):],
		j.token, j.id, c.token, c.id, "authorize-test-fixture-path")
	// Failures log too: refused tokens, a refused callback, a KMS outage.
	bad := ed.Sign(t, e.claims("viewer-log"))
	wantDenied(t, "replay", e.viaJWT(jwtTok))
	wantDenied(t, "tampered", e.viaJWT(tamper(bad)))
	rec.set(answer(500, `{"allow": true}`))
	wantDenied(t, "callback 500", e.viaCallback(vTicket+"-2"))
	e.kms.SetOutage(true)
	want(t, e.viaCallback(vTicket+"-3"), 503)
	sensitive = append(sensitive, bad, vTicket+"-2", vTicket+"-3")

	logs := e.logs.String()
	if logs == "" {
		t.Fatal("no logs to scan")
	}
	for _, s := range sensitive {
		if strings.Contains(logs, s) {
			t.Fatalf("a secret value (%d bytes, starts %q) reached the logs", len(s), s[:min(len(s), 12)])
		}
	}
	for _, banned := range []string{"Bearer ", "webhook-signature", "whsec_"} {
		if strings.Contains(logs, banned) {
			t.Fatalf("%q reached the logs", banned)
		}
	}
}
