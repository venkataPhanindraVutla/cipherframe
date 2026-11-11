package viewerauth_test

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/outbound"
	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth/viewerauthtest"
)

const (
	issuer   = "https://issuer.example.com"
	audience = "cipherframe"
	assetID  = "ast_01test"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newVerifier(t *testing.T, clk *fakeClock, pool *x509.CertPool) *viewerauth.Verifier {
	t.Helper()
	v, err := viewerauth.NewVerifier(viewerauth.VerifierOptions{
		Client:         outbound.New(outbound.Options{AllowLoopback: true, RootCAs: pool, Timeout: 2 * time.Second}),
		ValidateViewer: func(s string) error { return nil },
		Now:            clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func upload(t *testing.T, keys ...viewerauthtest.Key) map[string]viewerauth.PublicKey {
	t.Helper()
	out := map[string]viewerauth.PublicKey{}
	for _, k := range keys {
		pk, err := viewerauth.ParseUploadedJWK(k.Kid, k.PublicJWK(t))
		if err != nil {
			t.Fatal(err)
		}
		out[k.Kid] = pk
	}
	return out
}

func cfg(uploaded map[string]viewerauth.PublicKey) viewerauth.JWTConfig {
	return viewerauth.JWTConfig{Issuer: issuer, Audiences: []string{audience, "second"}, ViewerClaim: "sub", Uploaded: uploaded}
}

func TestVerifyAcceptsEachAlgorithm(t *testing.T) {
	clk := &fakeClock{t: time.Now()}
	v := newVerifier(t, clk, nil)
	for _, alg := range []string{"EdDSA", "ES256", "RS256"} {
		k := viewerauthtest.NewKey(t, alg, "k-"+alg)
		claims := viewerauthtest.Claims(clk.Now(), issuer, audience, assetID, "viewer-1")
		got, err := v.Verify(context.Background(), "t1", cfg(upload(t, k)), k.Sign(t, claims), assetID)
		if err != nil || got.Viewer != "viewer-1" || got.JTI != claims["jti"] {
			t.Fatalf("%s: %+v, %v", alg, got, err)
		}
		if got.Expiry.Unix() != claims["exp"] {
			t.Fatalf("%s: expiry %v", alg, got.Expiry)
		}
	}
	// aud as a list containing one configured audience, and a custom viewer claim.
	k := viewerauthtest.NewKey(t, "EdDSA", "k")
	claims := viewerauthtest.Claims(clk.Now(), issuer, audience, assetID, "x")
	claims["aud"] = []string{"other", "second"}
	claims["uid"] = "user-42"
	c := cfg(upload(t, k))
	c.ViewerClaim = "uid"
	if got, err := v.Verify(context.Background(), "t1", c, k.Sign(t, claims), assetID); err != nil || got.Viewer != "user-42" {
		t.Fatalf("custom claim: %+v, %v", got, err)
	}
}

func TestVerifyDenials(t *testing.T) {
	clk := &fakeClock{t: time.Now()}
	v := newVerifier(t, clk, nil)
	k := viewerauthtest.NewKey(t, "EdDSA", "k")
	other := viewerauthtest.NewKey(t, "EdDSA", "k") // same kid, different key
	es := viewerauthtest.NewKey(t, "ES256", "k")
	rs := viewerauthtest.NewKey(t, "RS256", "k")
	up := upload(t, k)
	now := clk.Now()
	good := func() map[string]any { return viewerauthtest.Claims(now, issuer, audience, assetID, "viewer-1") }
	with := func(name string, val any) map[string]any {
		c := good()
		if val == nil {
			delete(c, name)
		} else {
			c[name] = val
		}
		return c
	}

	rsaPub, err := viewerauth.ParseUploadedJWK("k", rs.PublicJWK(t))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, reason string
		token        string
		cfg          viewerauth.JWTConfig
	}{
		{"alg none", viewerauth.ReasonMalformed, viewerauthtest.UnsignedToken(t, "k", good()), cfg(up)},
		{"HS256 with the public key bytes", viewerauth.ReasonMalformed, viewerauthtest.HS256Token(t, "k", up["k"].JWK, good()), cfg(up)},
		{"HS256 with the raw RSA public key as secret", viewerauth.ReasonMalformed, viewerauthtest.HS256Token(t, "k", rsaPub.JWK, good()), cfg(map[string]viewerauth.PublicKey{"k": rsaPub})},
		{"wrong audience", viewerauth.ReasonAudience, k.Sign(t, with("aud", "someone-else")), cfg(up)},
		{"missing audience", viewerauth.ReasonAudience, k.Sign(t, with("aud", nil)), cfg(up)},
		{"wrong issuer", viewerauth.ReasonIssuer, k.Sign(t, with("iss", "https://evil.example.com")), cfg(up)},
		{"missing issuer", viewerauth.ReasonIssuer, k.Sign(t, with("iss", nil)), cfg(up)},
		{"expired beyond the skew", viewerauth.ReasonExpired, k.Sign(t, with("exp", now.Add(-61*time.Second).Unix())), cfg(up)},
		{"missing exp", viewerauth.ReasonExpired, k.Sign(t, with("exp", nil)), cfg(up)},
		{"nbf in the future", viewerauth.ReasonNotYetValid, k.Sign(t, with("nbf", now.Add(2*time.Minute).Unix())), cfg(up)},
		{"iat in the future", viewerauth.ReasonNotYetValid, k.Sign(t, with("iat", now.Add(2*time.Minute).Unix())), cfg(up)},
		{"exp too far away", viewerauth.ReasonLifetime, k.Sign(t, with("exp", now.Add(25*time.Hour).Unix())), cfg(up)},
		{"missing jti", viewerauth.ReasonJTI, k.Sign(t, with("jti", nil)), cfg(up)},
		{"empty jti", viewerauth.ReasonJTI, k.Sign(t, with("jti", "")), cfg(up)},
		{"jti too long", viewerauth.ReasonJTI, k.Sign(t, with("jti", strings.Repeat("j", 129))), cfg(up)},
		{"unknown kid", viewerauth.ReasonUnknownKey, viewerauthtest.NewKey(t, "EdDSA", "nope").Sign(t, good()), cfg(up)},
		{"no kid", viewerauth.ReasonUnknownKey, k.Sign(t, good(), map[string]any{"kid": ""}), cfg(up)},
		{"signed by another key", viewerauth.ReasonSignature, other.Sign(t, good()), cfg(up)},
		{"ES256 token for an EdDSA key", viewerauth.ReasonAlgorithm, es.Sign(t, good()), cfg(up)},
		{"RS256 token for an EdDSA key", viewerauth.ReasonAlgorithm, rs.Sign(t, good()), cfg(up)},
		{"wrong asset", viewerauth.ReasonAsset, k.Sign(t, with("asset_id", "ast_other")), cfg(up)},
		{"missing asset", viewerauth.ReasonAsset, k.Sign(t, with("asset_id", nil)), cfg(up)},
		{"asset not a string", viewerauth.ReasonAsset, k.Sign(t, with("asset_id", 5)), cfg(up)},
		{"viewer claim missing", viewerauth.ReasonViewer, k.Sign(t, with("sub", nil)), cfg(up)},
		{"sub of the wrong type", viewerauth.ReasonMalformed, k.Sign(t, with("sub", 12)), cfg(up)},
		{"viewer claim not a string", viewerauth.ReasonViewer, k.Sign(t, with("uid", 12)), viewerauth.JWTConfig{Issuer: issuer, Audiences: []string{audience}, ViewerClaim: "uid", Uploaded: up}},
		{"garbage", viewerauth.ReasonMalformed, "not-a-jwt", cfg(up)},
		{"empty", viewerauth.ReasonMalformed, "", cfg(up)},
		{"too long", viewerauth.ReasonMalformed, strings.Repeat("a", viewerauth.MaxTokenBytes+1), cfg(up)},
		{"issuer not configured", viewerauth.ReasonConfig, k.Sign(t, good()), viewerauth.JWTConfig{Audiences: []string{audience}, ViewerClaim: "sub", Uploaded: up}},
		{"audience not configured", viewerauth.ReasonConfig, k.Sign(t, good()), viewerauth.JWTConfig{Issuer: issuer, ViewerClaim: "sub", Uploaded: up}},
	}
	for _, c := range cases {
		_, err := v.Verify(context.Background(), "t1", c.cfg, c.token, assetID)
		if got := viewerauth.ReasonOf(err); got != c.reason {
			t.Errorf("%s: reason %q (err %v), want %q", c.name, got, err, c.reason)
		}
	}

	// A viewer claim that fails the validator.
	strict, err := viewerauth.NewVerifier(viewerauth.VerifierOptions{
		Client:         outbound.New(outbound.Options{}),
		ValidateViewer: func(s string) error { return context.Canceled },
		Now:            clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strict.Verify(context.Background(), "t1", cfg(up), k.Sign(t, good()), assetID); viewerauth.ReasonOf(err) != viewerauth.ReasonViewer {
		t.Errorf("invalid viewer: %v", err)
	}
}

func TestVerifyClockSkewBoundaries(t *testing.T) {
	clk := &fakeClock{t: time.Now()}
	v := newVerifier(t, clk, nil)
	k := viewerauthtest.NewKey(t, "EdDSA", "k")
	up := upload(t, k)
	now := clk.Now()
	tok := func(name string, delta time.Duration) string {
		c := viewerauthtest.Claims(now, issuer, audience, assetID, "v")
		c[name] = now.Add(delta).Unix()
		return k.Sign(t, c)
	}
	// Within the 60 second allowance: accepted.
	for name, delta := range map[string]time.Duration{"exp": -59 * time.Second, "nbf": 59 * time.Second, "iat": 59 * time.Second} {
		if _, err := v.Verify(context.Background(), "t1", cfg(up), tok(name, delta), assetID); err != nil {
			t.Errorf("%s %v within the skew: %v", name, delta, err)
		}
	}
}

func jwksServer(t *testing.T, hits *atomic.Int64, doc func() []byte) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(doc())
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, pool
}

func TestJWKSCacheAndRefetchRateLimit(t *testing.T) {
	clk := &fakeClock{t: time.Now()}
	first := viewerauthtest.NewKey(t, "EdDSA", "first")
	second := viewerauthtest.NewKey(t, "ES256", "second")
	var mu sync.Mutex
	published := []viewerauthtest.Key{first}
	var hits atomic.Int64
	srv, pool := jwksServer(t, &hits, func() []byte {
		mu.Lock()
		defer mu.Unlock()
		return viewerauthtest.JWKS(t, published...)
	})
	v := newVerifier(t, clk, pool)
	c := viewerauth.JWTConfig{Issuer: issuer, Audiences: []string{audience}, ViewerClaim: "sub", JWKSURL: srv.URL + "/jwks.json"}
	verify := func(k viewerauthtest.Key) error {
		claims := viewerauthtest.Claims(clk.Now(), issuer, audience, assetID, "v")
		_, err := v.Verify(context.Background(), "t1", c, k.Sign(t, claims), assetID)
		return err
	}

	// The first token fetches the document; later tokens use the cache.
	for range 3 {
		if err := verify(first); err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("fetches = %d, want 1", hits.Load())
	}

	// The tenant publishes a new key. A token with the new kid right away is a miss: the last
	// fetch was less than 30 seconds ago, so there is no refetch.
	mu.Lock()
	published = []viewerauthtest.Key{first, second}
	mu.Unlock()
	clk.advance(5 * time.Second)
	if err := verify(second); viewerauth.ReasonOf(err) != viewerauth.ReasonUnknownKey {
		t.Fatalf("new kid within 30 s: %v", err)
	}
	for range 5 { // a flood of unknown kids does not hammer the tenant either
		_ = verify(viewerauthtest.NewKey(t, "EdDSA", "unknown"))
	}
	if hits.Load() != 1 {
		t.Fatalf("fetches within the rate limit = %d, want 1", hits.Load())
	}

	// After 30 seconds an unknown kid triggers one refetch, which finds the new key.
	clk.advance(30 * time.Second)
	if err := verify(second); err != nil {
		t.Fatalf("new kid after 30 s: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("fetches = %d, want 2", hits.Load())
	}
	// A kid that is still unknown triggers no second refetch within 30 seconds.
	_ = verify(viewerauthtest.NewKey(t, "EdDSA", "unknown"))
	if hits.Load() != 2 {
		t.Fatalf("fetches = %d, want 2", hits.Load())
	}

	// The cache expires after 10 minutes.
	clk.advance(11 * time.Minute)
	if err := verify(first); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 3 {
		t.Fatalf("fetches after the TTL = %d, want 3", hits.Load())
	}

	// Uploaded keys win over the JWKS and cost no fetch.
	uploaded := viewerauthtest.NewKey(t, "EdDSA", "uploaded")
	c.Uploaded = upload(t, uploaded)
	before := hits.Load()
	if err := verify(uploaded); err != nil || hits.Load() != before {
		t.Fatalf("uploaded key: %v (fetches %d -> %d)", err, before, hits.Load())
	}
}

func TestJWKSFailuresAreMisses(t *testing.T) {
	clk := &fakeClock{t: time.Now()}
	k := viewerauthtest.NewKey(t, "EdDSA", "k")
	var hits atomic.Int64
	mode := atomic.Value{}
	mode.Store("ok")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		switch mode.Load().(string) {
		case "500":
			w.WriteHeader(http.StatusInternalServerError)
		case "big":
			_, _ = w.Write([]byte(strings.Repeat(" ", viewerauth.MaxJWKSBytes+1)))
		default:
			_, _ = w.Write(viewerauthtest.JWKS(t, k))
		}
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	v := newVerifier(t, clk, pool)
	c := viewerauth.JWTConfig{Issuer: issuer, Audiences: []string{audience}, ViewerClaim: "sub", JWKSURL: srv.URL}
	tok := func() string {
		return k.Sign(t, viewerauthtest.Claims(clk.Now(), issuer, audience, assetID, "v"))
	}
	for _, m := range []string{"500", "big"} {
		mode.Store(m)
		clk.advance(time.Minute)
		if _, err := v.Verify(context.Background(), "t1", c, tok(), assetID); viewerauth.ReasonOf(err) != viewerauth.ReasonUnknownKey {
			t.Errorf("%s: %v", m, err)
		}
	}
	// A working JWKS right after a failure is still rate limited, then works.
	mode.Store("ok")
	before := hits.Load()
	if _, err := v.Verify(context.Background(), "t1", c, tok(), assetID); err == nil || hits.Load() != before {
		t.Fatalf("a retry within 30 s must not fetch (err %v, hits %d -> %d)", err, before, hits.Load())
	}
	clk.advance(31 * time.Second)
	if _, err := v.Verify(context.Background(), "t1", c, tok(), assetID); err != nil {
		t.Fatal(err)
	}
	// A stale document is not used when the refresh fails.
	mode.Store("500")
	clk.advance(11 * time.Minute)
	if _, err := v.Verify(context.Background(), "t1", c, tok(), assetID); viewerauth.ReasonOf(err) != viewerauth.ReasonUnknownKey {
		t.Fatalf("stale JWKS used after a failed refresh: %v", err)
	}
}
