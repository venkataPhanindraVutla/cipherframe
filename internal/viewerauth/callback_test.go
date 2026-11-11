package viewerauth_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/kmstest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/local"
	"github.com/venkataPhanindraVutla/cipherframe/internal/outbound"
	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth/viewerauthtest"
)

func newAuthorizer(t *testing.T, pool *x509.CertPool, timeout time.Duration) *viewerauth.Authorizer {
	t.Helper()
	a, err := viewerauth.NewAuthorizer(viewerauth.AuthorizerOptions{
		Client: outbound.New(outbound.Options{AllowLoopback: true, RootCAs: pool, Timeout: 5 * time.Second}),
		ValidateViewer: func(s string) error {
			if s == "" || len(s) > 128 {
				return context.Canceled
			}
			return nil
		},
		Timeout: timeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func callbackServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, pool
}

var testReq = viewerauth.CallbackRequest{TenantID: "tnt_x", AssetID: "ast_y", Ticket: "test-fixture-ticket-<&>", RequestID: "req-1"}

func TestCallbackSignedRequestAndAllow(t *testing.T) {
	secret, err := viewerauth.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	var seen struct {
		hdr  http.Header
		body []byte
		ct   string
	}
	srv, pool := callbackServer(t, func(w http.ResponseWriter, r *http.Request) {
		seen.hdr, seen.ct = r.Header.Clone(), r.Header.Get("Content-Type")
		seen.body, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"allow": true, "viewer_id": "viewer-9"}`))
	})
	a := newAuthorizer(t, pool, 0)
	viewer, err := a.Authorize(context.Background(), srv.URL, [][]byte{secret}, testReq)
	if err != nil || viewer != "viewer-9" {
		t.Fatalf("viewer %q, err %v", viewer, err)
	}
	if n, err := viewerauthtest.VerifyWebhook(viewerauth.FormatSecret(secret), seen.hdr, seen.body, time.Now(), 5*time.Minute); err != nil || n != 1 {
		t.Fatalf("reference verifier: %d signatures, %v", n, err)
	}
	if seen.ct != "application/json" {
		t.Fatalf("content type %q", seen.ct)
	}
	var body map[string]string
	if err := json.Unmarshal(seen.body, &body); err != nil {
		t.Fatal(err)
	}
	if body["type"] != "playback.authorize" || body["tenant_id"] != "tnt_x" || body["asset_id"] != "ast_y" ||
		body["ticket"] != testReq.Ticket || body["request_id"] != "req-1" || len(body) != 6 {
		t.Fatalf("body = %v", body)
	}
	if _, err := time.Parse(time.RFC3339, body["timestamp"]); err != nil {
		t.Fatalf("timestamp %q: %v", body["timestamp"], err)
	}
	// A different secret does not verify.
	other, _ := viewerauth.GenerateSecret()
	if _, err := viewerauthtest.VerifyWebhook(viewerauth.FormatSecret(other), seen.hdr, seen.body, time.Now(), 5*time.Minute); err == nil {
		t.Fatal("verified with the wrong secret")
	}
	// Each request has its own webhook-id.
	first := seen.hdr.Get("webhook-id")
	if _, err := a.Authorize(context.Background(), srv.URL, [][]byte{secret}, testReq); err != nil {
		t.Fatal(err)
	}
	if seen.hdr.Get("webhook-id") == first || !strings.HasPrefix(first, "msg_") {
		t.Fatalf("webhook ids %q then %q", first, seen.hdr.Get("webhook-id"))
	}
}

func TestCallbackTwoSecretsTwoSignatures(t *testing.T) {
	cur, _ := viewerauth.GenerateSecret()
	prev, _ := viewerauth.GenerateSecret()
	var hdr http.Header
	var body []byte
	srv, pool := callbackServer(t, func(w http.ResponseWriter, r *http.Request) {
		hdr = r.Header.Clone()
		body, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"allow":true,"viewer_id":"v"}`))
	})
	a := newAuthorizer(t, pool, 0)
	if _, err := a.Authorize(context.Background(), srv.URL, [][]byte{cur, prev}, testReq); err != nil {
		t.Fatal(err)
	}
	// A tenant that still holds either secret verifies.
	for name, s := range map[string][]byte{"current": cur, "previous": prev} {
		n, err := viewerauthtest.VerifyWebhook(viewerauth.FormatSecret(s), hdr, body, time.Now(), 5*time.Minute)
		if err != nil || n != 2 {
			t.Fatalf("%s secret: %d signatures, %v", name, n, err)
		}
	}
	if _, err := a.Authorize(context.Background(), srv.URL, nil, testReq); viewerauth.ReasonOf(err) != viewerauth.ReasonConfig {
		t.Fatalf("no secret: %v", err)
	}
}

func TestCallbackDenials(t *testing.T) {
	secret, _ := viewerauth.GenerateSecret()
	var targetHits atomic.Int64
	respond := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}
	}
	cases := []struct {
		name   string
		h      http.HandlerFunc
		reason string
	}{
		{"allow false", respond(200, `{"allow": false}`), viewerauth.ReasonCallbackDenied},
		{"allow false with a viewer", respond(200, `{"allow": false, "viewer_id": "v"}`), viewerauth.ReasonCallbackDenied},
		{"403", respond(403, `{"allow": true, "viewer_id": "v"}`), viewerauth.ReasonCallbackStatus},
		{"500", respond(500, `{"allow": true, "viewer_id": "v"}`), viewerauth.ReasonCallbackStatus},
		{"201 is not 200", respond(201, `{"allow": true, "viewer_id": "v"}`), viewerauth.ReasonCallbackStatus},
		{"204", respond(204, ``), viewerauth.ReasonCallbackStatus},
		{"empty body", respond(200, ``), viewerauth.ReasonCallbackResponse},
		{"not json", respond(200, `yes`), viewerauth.ReasonCallbackResponse},
		{"allow as a string", respond(200, `{"allow": "true", "viewer_id": "v"}`), viewerauth.ReasonCallbackResponse},
		{"missing allow", respond(200, `{"viewer_id": "v"}`), viewerauth.ReasonCallbackResponse},
		{"unknown field", respond(200, `{"allow": true, "viewer_id": "v", "extra": 1}`), viewerauth.ReasonCallbackResponse},
		{"trailing data", respond(200, `{"allow": true, "viewer_id": "v"} {}`), viewerauth.ReasonCallbackResponse},
		{"array", respond(200, `[{"allow": true, "viewer_id": "v"}]`), viewerauth.ReasonCallbackResponse},
		{"missing viewer", respond(200, `{"allow": true}`), viewerauth.ReasonCallbackViewer},
		{"empty viewer", respond(200, `{"allow": true, "viewer_id": ""}`), viewerauth.ReasonCallbackViewer},
		{"viewer too long", respond(200, `{"allow": true, "viewer_id": "`+strings.Repeat("v", 129)+`"}`), viewerauth.ReasonCallbackViewer},
		{"oversized body", respond(200, `{"allow": true, "viewer_id": "v", "pad": "`+strings.Repeat("x", 9<<10)+`"}`), viewerauth.ReasonCallbackResponse},
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/target" {
				targetHits.Add(1)
				_, _ = w.Write([]byte(`{"allow": true, "viewer_id": "v"}`))
				return
			}
			http.Redirect(w, r, "/target", http.StatusTemporaryRedirect)
		}, viewerauth.ReasonCallbackFailed},
	}
	for _, c := range cases {
		srv, pool := callbackServer(t, c.h)
		a := newAuthorizer(t, pool, 0)
		_, err := a.Authorize(context.Background(), srv.URL, [][]byte{secret}, testReq)
		if got := viewerauth.ReasonOf(err); got != c.reason {
			t.Errorf("%s: reason %q (%v), want %q", c.name, got, err, c.reason)
		}
	}
	if targetHits.Load() != 0 {
		t.Fatal("a redirect was followed")
	}
}

func TestCallbackTimeoutAndNetworkErrors(t *testing.T) {
	secret, _ := viewerauth.GenerateSecret()
	srv, pool := callbackServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
		}
		_, _ = w.Write([]byte(`{"allow": true, "viewer_id": "v"}`))
	})
	a := newAuthorizer(t, pool, 200*time.Millisecond)
	start := time.Now()
	_, err := a.Authorize(context.Background(), srv.URL, [][]byte{secret}, testReq)
	if viewerauth.ReasonOf(err) != viewerauth.ReasonCallbackFailed || time.Since(start) > time.Second {
		t.Fatalf("timeout: %v after %v", err, time.Since(start))
	}
	// Connection refused, and a URL that is not https.
	closed := httptest.NewTLSServer(http.NotFoundHandler())
	url := closed.URL
	closed.Close()
	if _, err := a.Authorize(context.Background(), url, [][]byte{secret}, testReq); viewerauth.ReasonOf(err) != viewerauth.ReasonCallbackFailed {
		t.Fatalf("refused: %v", err)
	}
	if _, err := a.Authorize(context.Background(), "http://example.com/cb", [][]byte{secret}, testReq); viewerauth.ReasonOf(err) != viewerauth.ReasonCallbackFailed {
		t.Fatalf("http: %v", err)
	}
	// The error never carries the ticket, the secret or the URL.
	if err != nil && (strings.Contains(err.Error(), "test-fixture") || strings.Contains(err.Error(), "127.0.0.1")) {
		t.Fatalf("error leaks: %v", err)
	}
}

func TestSecretFormat(t *testing.T) {
	s, err := viewerauth.GenerateSecret()
	if err != nil || len(s) != viewerauth.SecretBytes {
		t.Fatal(err)
	}
	f := viewerauth.FormatSecret(s)
	if !strings.HasPrefix(f, "whsec_") || len(f) != len("whsec_")+44 {
		t.Fatalf("format %q", f)
	}
	s2, _ := viewerauth.GenerateSecret()
	if bytes.Equal(s, s2) {
		t.Fatal("two secrets are equal")
	}
}

func newBox(t *testing.T) (*viewerauth.SecretBox, *kmstest.Faulty) {
	t.Helper()
	lp, err := local.NewFromKeys(config.Development, map[int][]byte{1: bytes.Repeat([]byte{0x41}, config.KEKBytes)}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := kmstest.NewFaulty(lp)
	reg, err := kms.NewRegistry(f)
	if err != nil {
		t.Fatal(err)
	}
	return viewerauth.NewSecretBox(reg), f
}

func TestSecretBoxBindsTenantAndVersion(t *testing.T) {
	ctx := context.Background()
	box, faulty := newBox(t)
	tenantA, tenantB := id.New[id.TenantKind](), id.New[id.TenantKind]()
	secret, _ := viewerauth.GenerateSecret()

	env, err := box.Seal(ctx, tenantA, 3, secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(env, secret) {
		t.Fatal("the envelope contains the plaintext secret")
	}
	got, err := box.Open(ctx, tenantA, 3, env)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("open: %v", err)
	}
	// Another tenant, another version, a damaged envelope and garbage do not open.
	if _, err := box.Open(ctx, tenantB, 3, env); err == nil {
		t.Fatal("opened for another tenant")
	}
	if _, err := box.Open(ctx, tenantA, 2, env); err == nil {
		t.Fatal("opened for another version")
	}
	damaged := append([]byte(nil), env...)
	damaged[len(damaged)-1] ^= 1
	if _, err := box.Open(ctx, tenantA, 3, damaged); err == nil {
		t.Fatal("opened a damaged envelope")
	}
	for _, junk := range [][]byte{nil, {}, {1}, {2, 0, 0, 0, 0}, bytes.Repeat([]byte{0xff}, 40), env[:len(env)-3]} {
		if _, err := box.Open(ctx, tenantA, 3, junk); err == nil {
			t.Fatalf("opened junk %v", junk)
		}
	}
	// A provider outage is an error, not a secret.
	faulty.SetOutage(true)
	if _, err := box.Open(ctx, tenantA, 3, env); err == nil {
		t.Fatal("opened during an outage")
	}
	if _, err := box.Seal(ctx, tenantA, 4, secret); err == nil {
		t.Fatal("sealed during an outage")
	}
	faulty.SetOutage(false)
	if _, err := box.Seal(ctx, tenantA, 0, secret); err == nil {
		t.Fatal("sealed version 0")
	}
	if _, err := box.Seal(ctx, tenantA, 1, secret[:5]); err == nil {
		t.Fatal("sealed a short secret")
	}
}

// An allow that arrives as the budget runs out must still be a timeout. The server answers the
// moment the client gives up, which is when the transport can hand the response over anyway; run
// it many times so the race is hit.
func TestCallbackAnswerRacingTheDeadlineIsATimeout(t *testing.T) {
	secret, _ := viewerauth.GenerateSecret()
	srv, pool := callbackServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Reading the body lets the server notice the client leaving (net/http only watches the
		// connection once the body is consumed), so the answer is written into the race window.
		_, _ = io.ReadAll(r.Body)
		<-r.Context().Done()
		_, _ = w.Write([]byte(`{"allow": true, "viewer_id": "v"}`))
	})
	a := newAuthorizer(t, pool, 20*time.Millisecond)
	for i := range 200 {
		viewer, err := a.Authorize(context.Background(), srv.URL, [][]byte{secret}, testReq)
		if err == nil || viewer != "" {
			t.Fatalf("attempt %d: a late allow was accepted", i)
		}
	}
}
