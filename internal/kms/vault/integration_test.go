//go:build integration

package vault_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/kmstest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/vault"
)

// Both servers speak the same Transit API (ADR 0021). Images are pinned by tag and digest; the
// digest is the multi-architecture index.
var servers = []struct {
	name    string
	image   string
	rootEnv string
}{
	{
		name:    "hashicorp-vault",
		image:   "hashicorp/vault:2.2.1@sha256:962a92876e168d68eaaa24b0b8b49bbce1cb63024060a67bba95cd158a366fc2",
		rootEnv: "VAULT_DEV_ROOT_TOKEN_ID",
	},
	{
		name:    "openbao",
		image:   "openbao/openbao:2.7.2@sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f",
		rootEnv: "BAO_DEV_ROOT_TOKEN_ID",
	},
}

const rootToken = "integration-root-token" //nolint:gosec // dev server only, never reused

// transit is a running dev server with the Transit engine mounted.
type transit struct {
	addr string // http://host:port
	http *http.Client
}

func startServer(t *testing.T, image, rootEnv string) *transit {
	t.Helper()
	ctx := context.Background()
	ctr, err := testcontainers.Run(ctx, image,
		testcontainers.WithExposedPorts("8200/tcp"),
		testcontainers.WithEnv(map[string]string{rootEnv: rootToken}),
		testcontainers.WithWaitStrategy(
			wait.ForHTTP("/v1/sys/health").WithPort("8200/tcp").WithStartupTimeout(2*time.Minute)),
	)
	testcontainers.CleanupContainer(t, ctr)
	if err != nil {
		t.Fatalf("cannot start the Transit server container: %v", err)
	}
	host, err := ctr.PortEndpoint(ctx, "8200/tcp", "http")
	if err != nil {
		t.Fatal(err)
	}
	tr := &transit{addr: host, http: &http.Client{Timeout: 30 * time.Second}}
	tr.admin(t, rootToken, http.MethodPost, "/v1/sys/mounts/transit", `{"type":"transit"}`)
	return tr
}

// admin sends a management request and fails the test unless it succeeds. It returns the body.
func (s *transit) admin(t *testing.T, token, method, path, body string) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, s.addr+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := s.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("%s %s: status %d", method, path, resp.StatusCode)
	}
	return b
}

func (s *transit) createKey(t *testing.T, name, keyType string) {
	t.Helper()
	s.admin(t, rootToken, http.MethodPost, "/v1/transit/keys/"+name, fmt.Sprintf(`{"type":%q}`, keyType))
}

func (s *transit) rotate(t *testing.T, name string) {
	t.Helper()
	s.admin(t, rootToken, http.MethodPost, "/v1/transit/keys/"+name+"/rotate", "")
}

// scopedToken returns a token that may only read the key and use it to encrypt and decrypt, which
// is the policy the documentation tells operators to grant.
func (s *transit) scopedToken(t *testing.T, key string) string {
	t.Helper()
	policy := fmt.Sprintf(`
path "transit/keys/%[1]s"    { capabilities = ["read"] }
path "transit/encrypt/%[1]s" { capabilities = ["update"] }
path "transit/decrypt/%[1]s" { capabilities = ["update"] }
`, key)
	pj, _ := json.Marshal(map[string]string{"policy": policy})
	s.admin(t, rootToken, http.MethodPut, "/v1/sys/policies/acl/cf-"+key, string(pj))
	out := s.admin(t, rootToken, http.MethodPost, "/v1/auth/token/create",
		fmt.Sprintf(`{"policies":["cf-%s"],"no_parent":true,"ttl":"1h"}`, key))
	var r struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(out, &r); err != nil || r.Auth.ClientToken == "" {
		t.Fatal("no token in the token-create response")
	}
	return r.Auth.ClientToken
}

func (s *transit) provider(t *testing.T, addr, token, key string) *vault.Provider {
	t.Helper()
	p, err := vault.New(config.KMSVault{
		Addr: addr, Token: config.NewSecret(token), TransitMount: "transit", KeyName: key,
		Timeout: 10 * time.Second,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func randName(prefix string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b)
}

// forwarder is a TCP relay in front of the server. Stopping it is an outage: connections are
// refused and open ones are cut. Starting it again restores service on the same address.
type forwarder struct {
	addr, target string
	mu           sync.Mutex
	ln           net.Listener
	conns        []net.Conn
}

func newForwarder(t *testing.T, target string) *forwarder {
	t.Helper()
	f := &forwarder{target: target}
	ln, err := listen(t, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.addr = ln.Addr().String()
	f.serve(ln)
	t.Cleanup(f.stop)
	return f
}

func (f *forwarder) serve(ln net.Listener) {
	f.mu.Lock()
	f.ln = ln
	f.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", f.target)
			if err != nil {
				_ = c.Close()
				continue
			}
			f.mu.Lock()
			f.conns = append(f.conns, c, up)
			f.mu.Unlock()
			go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
			go func() { _, _ = io.Copy(c, up); _ = c.Close() }()
		}
	}()
}

func (f *forwarder) stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ln != nil {
		_ = f.ln.Close()
		f.ln = nil
	}
	for _, c := range f.conns {
		_ = c.Close()
	}
	f.conns = nil
}

func (f *forwarder) start(t *testing.T) {
	t.Helper()
	ln, err := listen(t, f.addr)
	if err != nil {
		t.Fatalf("cannot restore the relay: %v", err)
	}
	f.serve(ln)
}

func TestTransitServers(t *testing.T) {
	for _, srv := range servers {
		t.Run(srv.name, func(t *testing.T) {
			s := startServer(t, srv.image, srv.rootEnv)
			t.Run("conformance", func(t *testing.T) { conformance(t, s) })
			t.Run("server behaviour", func(t *testing.T) { behaviour(t, s) })
		})
	}
}

func conformance(t *testing.T, s *transit) {
	key := randName("conf")
	s.createKey(t, key, "aes256-gcm96")
	token := s.scopedToken(t, key)
	relay := newForwarder(t, strings.TrimPrefix(s.addr, "http://"))
	relayAddr := "http://" + relay.addr

	kmstest.Run(t,
		func(t *testing.T) kms.Provider { return s.provider(t, relayAddr, token, key) },
		kmstest.WithRotated(func(t *testing.T) kms.Provider {
			s.rotate(t, key)
			return s.provider(t, relayAddr, token, key)
		}),
		kmstest.WithOutage(func(t *testing.T, _ kms.Provider) func() {
			relay.stop()
			return func() { relay.start(t) }
		}),
	)
}

func behaviour(t *testing.T, s *transit) {
	ctx := context.Background()
	aad := []byte("aad")
	pt := []byte("0123456789abcdef")

	t.Run("wrong token is denied", func(t *testing.T) {
		key := randName("tok")
		s.createKey(t, key, "aes256-gcm96")
		p := s.provider(t, s.addr, "not-a-valid-token", key)
		if _, err := p.Wrap(ctx, pt, aad); !errors.Is(err, kms.ErrDenied) {
			t.Fatalf("Wrap: want Denied, got %v", err)
		}
		if _, err := p.Current(ctx); !errors.Is(err, kms.ErrDenied) {
			t.Fatalf("Current: want Denied, got %v", err)
		}
	})

	t.Run("scoped token is denied on another key", func(t *testing.T) {
		mine, other := randName("mine"), randName("other")
		s.createKey(t, mine, "aes256-gcm96")
		s.createKey(t, other, "aes256-gcm96")
		p := s.provider(t, s.addr, s.scopedToken(t, mine), other)
		if _, err := p.Wrap(ctx, pt, aad); !errors.Is(err, kms.ErrDenied) {
			t.Fatalf("want Denied, got %v", err)
		}
	})

	t.Run("missing key is not configured and is not created", func(t *testing.T) {
		key := randName("missing")
		p := s.provider(t, s.addr, rootToken, key)
		if _, err := p.Current(ctx); !errors.Is(err, kms.ErrNotConfigured) {
			t.Fatalf("Current: want NotConfigured, got %v", err)
		}
		if _, err := p.Wrap(ctx, pt, aad); !errors.Is(err, kms.ErrNotConfigured) {
			t.Fatalf("Wrap: want NotConfigured, got %v", err)
		}
		// Transit encrypts to a missing key by creating it; the provider must never trigger that.
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.addr+"/v1/transit/keys/"+key, nil)
		req.Header.Set("X-Vault-Token", rootToken)
		resp, err := s.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("the provider created the key (status %d)", resp.StatusCode)
		}
	})

	t.Run("missing mount is not configured", func(t *testing.T) {
		p, err := vault.New(config.KMSVault{
			Addr: s.addr, Token: config.NewSecret(rootToken), TransitMount: "nomount", KeyName: "k",
			Timeout: 10 * time.Second,
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Wrap(ctx, pt, aad); !errors.Is(err, kms.ErrNotConfigured) {
			t.Fatalf("want NotConfigured, got %v", err)
		}
	})

	t.Run("non-AEAD key is refused", func(t *testing.T) {
		key := randName("rsa")
		s.createKey(t, key, "rsa-2048")
		p := s.provider(t, s.addr, rootToken, key)
		_, err := p.Wrap(ctx, pt, aad)
		if !errors.Is(err, kms.ErrNotConfigured) || !strings.Contains(err.Error(), "associated data") {
			t.Fatalf("want a NotConfigured refusal naming associated data, got %v", err)
		}
	})

	t.Run("other AEAD key types work", func(t *testing.T) {
		for _, typ := range []string{"aes128-gcm96", "chacha20-poly1305"} {
			key := randName("t")
			s.createKey(t, key, typ)
			p := s.provider(t, s.addr, rootToken, key)
			w, err := p.Wrap(ctx, pt, aad)
			if err != nil {
				t.Fatalf("%s: %v", typ, err)
			}
			got, err := p.Unwrap(ctx, w, aad)
			if err != nil || !bytes.Equal(got, pt) {
				t.Fatalf("%s: round trip failed: %v", typ, err)
			}
		}
	})

	t.Run("version trimmed by min_decryption_version is not configured", func(t *testing.T) {
		key := randName("trim")
		s.createKey(t, key, "aes256-gcm96")
		p := s.provider(t, s.addr, rootToken, key)
		w, err := p.Wrap(ctx, pt, aad)
		if err != nil {
			t.Fatal(err)
		}
		s.rotate(t, key)
		s.admin(t, rootToken, http.MethodPost, "/v1/transit/keys/"+key+"/config", `{"min_decryption_version":2}`)
		got, err := p.Unwrap(ctx, w, aad)
		if !errors.Is(err, kms.ErrNotConfigured) || got != nil {
			t.Fatalf("want NotConfigured and no key, got %v", err)
		}
	})

	t.Run("unknown newer version is not configured", func(t *testing.T) {
		key := randName("new")
		s.createKey(t, key, "aes256-gcm96")
		p := s.provider(t, s.addr, rootToken, key)
		w, err := p.Wrap(ctx, pt, aad)
		if err != nil {
			t.Fatal(err)
		}
		w.Version = "9"
		w.Ciphertext = bytes.Replace(w.Ciphertext, []byte("vault:v1:"), []byte("vault:v9:"), 1)
		got, err := p.Unwrap(ctx, w, aad)
		if !errors.Is(err, kms.ErrNotConfigured) || got != nil {
			t.Fatalf("want NotConfigured and no key, got %v", err)
		}
	})

	t.Run("a wrap is bound to its associated data", func(t *testing.T) {
		key := randName("aad")
		s.createKey(t, key, "aes256-gcm96")
		p := s.provider(t, s.addr, rootToken, key)
		w, err := p.Wrap(ctx, pt, []byte("slot-a"))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := p.Unwrap(ctx, w, []byte("slot-b")); !errors.Is(err, kms.ErrInvalid) || got != nil {
			t.Fatalf("want Invalid and no key, got %v", err)
		}
	})

	t.Run("closed port is unavailable", func(t *testing.T) {
		ln, err := listen(t, "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		p := s.provider(t, "http://"+addr, rootToken, "k")
		if _, err := p.Current(ctx); !errors.Is(err, kms.ErrUnavailable) {
			t.Fatalf("want Unavailable, got %v", err)
		}
	})
}

func listen(_ *testing.T, addr string) (net.Listener, error) {
	return (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
}
