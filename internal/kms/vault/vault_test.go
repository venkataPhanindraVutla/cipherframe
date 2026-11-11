package vault_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/kmstest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/vault"
)

const (
	testToken = "hvs.UNIT-TOKEN-distinct-77" //nolint:gosec // test fixture
	testKey   = "cipherframe"
)

// fakeTransit is an in-memory Transit server: real AES-GCM with associated data, versioned keys,
// strict ciphertext handling and the same status codes and error texts as Vault and OpenBao.
type fakeTransit struct {
	mu        sync.Mutex
	keyType   string
	versions  map[int]cipher.AEAD
	latest    int
	down      bool
	hits      map[string]int
	namespace string // last X-Vault-Namespace
}

func newFake(t *testing.T) (*fakeTransit, *httptest.Server) {
	t.Helper()
	f := &fakeTransit{keyType: "aes256-gcm96", versions: map[int]cipher.AEAD{}, hits: map[string]int{}}
	f.rotate()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeTransit) rotate() {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	b, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(b)
	f.latest++
	f.versions[f.latest] = g
}

func (f *fakeTransit) setDown(v bool) {
	f.mu.Lock()
	f.down = v
	f.mu.Unlock()
}

func (f *fakeTransit) hit(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[name]
}

func (f *fakeTransit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		if h, ok := w.(http.Hijacker); ok {
			if c, _, err := h.Hijack(); err == nil {
				_ = c.Close()
			}
		}
		return
	}
	f.namespace = r.Header.Get("X-Vault-Namespace")
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	fail := func(status int, msg string) { reply(status, map[string]any{"errors": []string{msg}}) }
	if r.Header.Get("X-Vault-Token") != testToken {
		fail(http.StatusForbidden, "permission denied")
		return
	}
	f.hits[r.Method+" "+r.URL.Path]++
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/"+testKey:
		reply(200, map[string]any{"data": map[string]any{"type": f.keyType, "latest_version": f.latest}})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/transit/encrypt/"+testKey:
		var in struct {
			Plaintext      string `json:"plaintext"`
			AssociatedData string `json:"associated_data"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		pt, err1 := base64.StdEncoding.DecodeString(in.Plaintext)
		aad, err2 := base64.StdEncoding.DecodeString(in.AssociatedData)
		if err1 != nil || err2 != nil {
			fail(400, "invalid request")
			return
		}
		g := f.versions[f.latest]
		nonce := make([]byte, g.NonceSize())
		_, _ = rand.Read(nonce)
		ct := g.Seal(nonce, nonce, pt, aad)
		reply(200, map[string]any{"data": map[string]any{
			"ciphertext":  fmt.Sprintf("vault:v%d:%s", f.latest, base64.StdEncoding.EncodeToString(ct)),
			"key_version": f.latest,
		}})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/transit/decrypt/"+testKey:
		var in struct {
			C string `json:"ciphertext"`
			A string `json:"associated_data"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		aad, _ := base64.StdEncoding.DecodeString(in.A)
		var ver int
		var payload string
		if _, err := fmt.Sscanf(strings.Replace(in.C, ":", " ", 2), "vault v%d %s", &ver, &payload); err != nil {
			fail(400, "invalid ciphertext: no prefix")
			return
		}
		g, ok := f.versions[ver]
		if !ok {
			fail(400, "invalid ciphertext: version is too new")
			return
		}
		raw, err := base64.StdEncoding.DecodeString(payload)
		if err != nil || len(raw) < g.NonceSize()+g.Overhead() {
			fail(400, "invalid ciphertext length")
			return
		}
		pt, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], aad)
		if err != nil {
			fail(400, "cipher: message authentication failed")
			return
		}
		reply(200, map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(pt)}})
	default:
		fail(404, "no handler for route")
	}
}

func cfgFor(addr string) config.KMSVault {
	return config.KMSVault{
		Addr: addr, Token: config.NewSecret(testToken), TransitMount: "transit", KeyName: testKey,
		Timeout: 5 * time.Second,
	}
}

func newProvider(t *testing.T, cfg config.KMSVault) *vault.Provider {
	t.Helper()
	p, err := vault.New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConformance(t *testing.T) {
	f, srv := newFake(t)
	kmstest.Run(t,
		func(t *testing.T) kms.Provider { return newProvider(t, cfgFor(srv.URL)) },
		kmstest.WithRotated(func(t *testing.T) kms.Provider {
			f.rotate()
			return newProvider(t, cfgFor(srv.URL))
		}),
		kmstest.WithOutage(func(t *testing.T, _ kms.Provider) func() {
			f.setDown(true)
			return func() { f.setDown(false) }
		}),
	)
}

func TestWrapRecordsVersionFromPrefix(t *testing.T) {
	f, srv := newFake(t)
	f.rotate()
	f.rotate()
	p := newProvider(t, cfgFor(srv.URL))
	w, err := p.Wrap(context.Background(), []byte("0123456789abcdef"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if w.Provider != "vault" || w.KeyID != testKey || w.Version != "3" || !bytes.HasPrefix(w.Ciphertext, []byte("vault:v3:")) {
		t.Fatalf("unexpected Wrapped: %s %s %s", w.Provider, w.KeyID, w.Version)
	}
	ref, err := p.Current(context.Background())
	if err != nil || ref != (kms.KeyRef{KeyID: testKey, Version: "3"}) {
		t.Fatalf("Current = %v, %v", ref, err)
	}
}

func TestKeyTypeRefusedThenAccepted(t *testing.T) {
	f, srv := newFake(t)
	f.mu.Lock()
	f.keyType = "rsa-2048"
	f.mu.Unlock()
	p := newProvider(t, cfgFor(srv.URL))
	ctx := context.Background()
	_, err := p.Wrap(ctx, []byte("0123456789abcdef"), []byte("aad"))
	if !errors.Is(err, kms.ErrNotConfigured) || !strings.Contains(err.Error(), "associated data") {
		t.Fatalf("want NotConfigured naming associated data, got %v", err)
	}
	if _, err := p.Current(ctx); !errors.Is(err, kms.ErrNotConfigured) {
		t.Fatalf("Current: want NotConfigured, got %v", err)
	}
	if n := f.hit("POST /v1/transit/encrypt/" + testKey); n != 0 {
		t.Fatalf("encrypt was called %d times on an unsuitable key", n)
	}
	for _, typ := range []string{"aes128-gcm96", "chacha20-poly1305"} {
		f.mu.Lock()
		f.keyType = typ
		f.mu.Unlock()
		if _, err := p.Wrap(ctx, []byte("0123456789abcdef"), []byte("aad")); err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
	}
}

func TestKeyTypeCheckedOnlyOnce(t *testing.T) {
	f, srv := newFake(t)
	p := newProvider(t, cfgFor(srv.URL))
	ctx := context.Background()
	for range 3 {
		if _, err := p.Wrap(ctx, []byte("0123456789abcdef"), []byte("aad")); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.hit("GET /v1/transit/keys/" + testKey); n != 1 {
		t.Fatalf("key metadata read %d times, want 1", n)
	}
}

func TestNamespaceHeader(t *testing.T) {
	f, srv := newFake(t)
	cfg := cfgFor(srv.URL)
	cfg.Namespace = "admin/team"
	if _, err := newProvider(t, cfg).Current(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.namespace != "admin/team" {
		t.Fatalf("X-Vault-Namespace = %q", f.namespace)
	}
	if _, err := newProvider(t, cfgFor(srv.URL)).Current(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.namespace != "" {
		t.Fatalf("namespace header sent although none is configured: %q", f.namespace)
	}
}

func TestMountAndAddrPath(t *testing.T) {
	var path atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path.Store(r.URL.Path)
		_, _ = io.WriteString(w, `{"data":{"type":"aes256-gcm96","latest_version":1}}`)
	}))
	defer srv.Close()
	cfg := cfgFor(srv.URL + "/proxy/")
	cfg.TransitMount = "team/transit"
	if _, err := newProvider(t, cfg).Current(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := path.Load(); got != "/proxy/v1/team/transit/keys/"+testKey {
		t.Fatalf("path = %v", got)
	}
}

func TestWrongTokenIsDenied(t *testing.T) {
	_, srv := newFake(t)
	cfg := cfgFor(srv.URL)
	cfg.Token = config.NewSecret("not-the-token")
	p := newProvider(t, cfg)
	if _, err := p.Wrap(context.Background(), []byte("0123456789abcdef"), []byte("aad")); !errors.Is(err, kms.ErrDenied) {
		t.Fatalf("want Denied, got %v", err)
	}
}

func TestTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	cfg := cfgFor(srv.URL)
	cfg.Timeout = 80 * time.Millisecond
	p := newProvider(t, cfg)
	start := time.Now()
	_, err := p.Wrap(context.Background(), []byte("0123456789abcdef"), []byte("aad"))
	if !errors.Is(err, kms.ErrUnavailable) {
		t.Fatalf("want Unavailable, got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("the timeout was not enforced")
	}
}

func TestConnectionRefusedIsUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	addr := srv.URL
	srv.Close()
	p := newProvider(t, cfgFor(addr))
	if _, err := p.Current(context.Background()); !errors.Is(err, kms.ErrUnavailable) {
		t.Fatalf("want Unavailable, got %v", err)
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	var leaked atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "" {
			leaked.Store(true)
		}
	}))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect) //nolint:gosec // test server redirects to its own fixture
	}))
	defer srv.Close()
	_, err := newProvider(t, cfgFor(srv.URL)).Current(context.Background())
	if !errors.Is(err, kms.ErrUnavailable) {
		t.Fatalf("want Unavailable, got %v", err)
	}
	if leaked.Load() {
		t.Fatal("the token was sent to the redirect target")
	}
}

func TestErrorMapping(t *testing.T) {
	tests := []struct {
		name   string
		op     string // "wrap" or "unwrap"
		status int
		body   string
		want   kms.Kind
	}{
		{"5xx", "wrap", 500, `{"errors":["boom"]}`, kms.Unavailable},
		{"503 sealed", "wrap", 503, `{"errors":["Vault is sealed"]}`, kms.Unavailable},
		{"502 no body", "unwrap", 502, ``, kms.Unavailable},
		{"429 standby", "wrap", 429, `{"errors":["standby"]}`, kms.Unavailable},
		{"redirect", "wrap", 307, ``, kms.Unavailable},
		{"403", "wrap", 403, `{"errors":["permission denied"]}`, kms.Denied},
		{"401", "unwrap", 401, ``, kms.Denied},
		{"404", "wrap", 404, `{"errors":[]}`, kms.NotConfigured},
		{"400 key not found", "unwrap", 400, `{"errors":["encryption key not found"]}`, kms.NotConfigured},
		{"400 version too new", "unwrap", 400, `{"errors":["invalid ciphertext: version is too new"]}`, kms.NotConfigured},
		{"400 version too old", "unwrap", 400, `{"errors":["ciphertext or signature version is disallowed by policy (too old)"]}`, kms.NotConfigured},
		{"400 authentication failed", "unwrap", 400, `{"errors":["cipher: message authentication failed"]}`, kms.Invalid},
		{"400 invalid length", "unwrap", 400, `{"errors":["invalid ciphertext length"]}`, kms.Invalid},
		{"400 bad base64", "unwrap", 400, `{"errors":["invalid ciphertext: could not decode base64"]}`, kms.Invalid},
		{"400 unknown on unwrap", "unwrap", 400, `{"errors":["something else"]}`, kms.Other},
		{"400 no body on unwrap", "unwrap", 400, ``, kms.Other},
		{"400 on wrap", "wrap", 400, `{"errors":["cipher: message authentication failed"]}`, kms.Other},
		{"409", "wrap", 409, `{"errors":["x"]}`, kms.Other},
		{"418", "unwrap", 418, ``, kms.Other},
		{"200 malformed json", "wrap", 200, `not json`, kms.Other},
		{"200 bad ciphertext format", "wrap", 200, `{"data":{"ciphertext":"no-prefix"}}`, kms.Other},
		{"200 non canonical base64", "wrap", 200, `{"data":{"ciphertext":"vault:v1:AAB="}}`, kms.Other},
		{"200 bad plaintext", "unwrap", 200, `{"data":{"plaintext":"!!!"}}`, kms.Other},
		{"200 empty plaintext", "unwrap", 200, `{"data":{"plaintext":""}}`, kms.Other},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet { // key metadata
					_, _ = io.WriteString(w, `{"data":{"type":"aes256-gcm96","latest_version":1}}`)
					return
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			p := newProvider(t, cfgFor(srv.URL))
			ctx := context.Background()
			var err error
			if tc.op == "wrap" {
				_, err = p.Wrap(ctx, []byte("0123456789abcdef"), []byte("aad"))
			} else {
				w := kms.Wrapped{Provider: "vault", KeyID: testKey, Version: "1", Ciphertext: []byte("vault:v1:" + strings.Repeat("A", 60))}
				var pt []byte
				pt, err = p.Unwrap(ctx, w, []byte("aad"))
				if pt != nil {
					t.Fatal("a key was returned with an error")
				}
			}
			if err == nil {
				t.Fatal("no error")
			}
			if got := kms.KindOf(err); got != tc.want {
				t.Fatalf("kind = %v, want %v (%v)", got, tc.want, err)
			}
		})
	}
}

func TestErrorsNeverEchoInput(t *testing.T) {
	const echo = "ECHOED-INPUT-zz81"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, `{"data":{"type":"aes256-gcm96","latest_version":1}}`)
			return
		}
		b, _ := io.ReadAll(r.Body)
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"errors": []string{fmt.Sprintf("cipher: message authentication failed %s %s", echo, b)},
		})
	}))
	defer srv.Close()
	p := newProvider(t, cfgFor(srv.URL))
	ct := "vault:v1:" + strings.Repeat("A", 60)
	_, err := p.Unwrap(context.Background(), kms.Wrapped{Provider: "vault", KeyID: testKey, Version: "1", Ciphertext: []byte(ct)}, []byte("aad-secret"))
	if !errors.Is(err, kms.ErrInvalid) {
		t.Fatalf("want Invalid, got %v", err)
	}
	for _, leak := range []string{echo, ct, "aad-secret", testToken, base64.StdEncoding.EncodeToString([]byte("aad-secret"))} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("the error leaks %q: %v", leak, err)
		}
	}
	if !strings.Contains(err.Error(), "400") {
		t.Fatalf("the error should carry the status: %v", err)
	}
}

func TestUnwrapLocalChecksSkipTheNetwork(t *testing.T) {
	f, srv := newFake(t)
	p := newProvider(t, cfgFor(srv.URL))
	ctx := context.Background()
	w, err := p.Wrap(ctx, []byte("0123456789abcdef"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	before := f.hit("POST /v1/transit/decrypt/" + testKey)
	mut := func(f func(*kms.Wrapped)) kms.Wrapped {
		c := w
		c.Ciphertext = bytes.Clone(w.Ciphertext)
		f(&c)
		return c
	}
	cases := map[string]struct {
		w    kms.Wrapped
		aad  []byte
		want kms.Kind
	}{
		"other provider":              {mut(func(c *kms.Wrapped) { c.Provider = "local" }), []byte("aad"), kms.Invalid},
		"other key id":                {mut(func(c *kms.Wrapped) { c.KeyID = "other" }), []byte("aad"), kms.NotConfigured},
		"bad version":                 {mut(func(c *kms.Wrapped) { c.Version = "x" }), []byte("aad"), kms.Invalid},
		"zero version":                {mut(func(c *kms.Wrapped) { c.Version = "0" }), []byte("aad"), kms.Invalid},
		"version differs from prefix": {mut(func(c *kms.Wrapped) { c.Version = "2" }), []byte("aad"), kms.Invalid},
		"empty aad":                   {w, nil, kms.Invalid},
		"no prefix":                   {mut(func(c *kms.Wrapped) { c.Ciphertext = []byte("AAAA") }), []byte("aad"), kms.Invalid},
		"empty":                       {mut(func(c *kms.Wrapped) { c.Ciphertext = nil }), []byte("aad"), kms.Invalid},
	}
	for name, c := range cases {
		pt, err := p.Unwrap(ctx, c.w, c.aad)
		if pt != nil || kms.KindOf(err) != c.want || err == nil {
			t.Fatalf("%s: got kind %v, err %v", name, kms.KindOf(err), err)
		}
	}
	if f.hit("POST /v1/transit/decrypt/"+testKey) != before {
		t.Fatal("a locally invalid wrapped key reached the server")
	}
}

func TestCiphertextBitFlipsAllFail(t *testing.T) {
	// Vault's base64 decoder ignores trailing padding bits; the provider must not.
	_, srv := newFake(t)
	p := newProvider(t, cfgFor(srv.URL))
	ctx := context.Background()
	w, err := p.Wrap(ctx, []byte("0123456789abcdef"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range w.Ciphertext {
		for bit := range 8 {
			bad := w
			bad.Ciphertext = bytes.Clone(w.Ciphertext)
			bad.Ciphertext[i] ^= 1 << bit
			if pt, err := p.Unwrap(ctx, bad, []byte("aad")); err == nil || pt != nil {
				t.Fatalf("flipping bit %d of byte %d did not fail closed", bit, i)
			}
		}
	}
}

func TestCAFile(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"type":"aes256-gcm96","latest_version":4}}`)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the rejected handshake is expected
	srv.StartTLS()
	defer srv.Close()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := cfgFor(srv.URL)
	cfg.CAFile = caPath
	ref, err := newProvider(t, cfg).Current(context.Background())
	if err != nil || ref.Version != "4" {
		t.Fatalf("with the CA: %v %v", ref, err)
	}
	if _, err := newProvider(t, cfgFor(srv.URL)).Current(context.Background()); !errors.Is(err, kms.ErrUnavailable) {
		t.Fatalf("without the CA the certificate must be rejected, got %v", err)
	}

	cfg.CAFile = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := vault.New(cfg, nil); err == nil {
		t.Fatal("a missing CA file was accepted")
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.CAFile = bad
	if _, err := vault.New(cfg, nil); err == nil {
		t.Fatal("a CA file without certificates was accepted")
	}
}

func TestNewValidates(t *testing.T) {
	for name, mod := range map[string]func(*config.KMSVault){
		"no addr":    func(c *config.KMSVault) { c.Addr = "" },
		"no token":   func(c *config.KMSVault) { c.Token = config.Secret{} },
		"no key":     func(c *config.KMSVault) { c.KeyName = "" },
		"bad scheme": func(c *config.KMSVault) { c.Addr = "ftp://x" },
	} {
		cfg := cfgFor("http://127.0.0.1:1")
		mod(&cfg)
		if _, err := vault.New(cfg, nil); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestPrintedFormsAreRedacted(t *testing.T) {
	p := newProvider(t, cfgFor("http://127.0.0.1:1"))
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	if _, err := vault.New(cfgFor("http://127.0.0.1:1"), log); err != nil {
		t.Fatal(err)
	}
	log.Info("p", "provider", p)
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	forms := []string{fmt.Sprint(p), fmt.Sprintf("%v", p), fmt.Sprintf("%+v", p), fmt.Sprintf("%#v", p), fmt.Sprintf("%s", p), string(b), logs.String()}
	for _, f := range forms {
		if strings.Contains(f, testToken) {
			t.Fatalf("a printed form leaks the token: %.80s", f)
		}
	}
	if !strings.Contains(logs.String(), testKey) {
		t.Fatalf("logs should name the key: %s", logs.String())
	}
}
