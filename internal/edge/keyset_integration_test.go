//go:build integration

package edge_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/kmstest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/local"
	"github.com/venkataPhanindraVutla/cipherframe/internal/signing"
)

type keySetResp struct {
	Keys []struct {
		KeyID     string  `json:"keyid"`
		Alg       string  `json:"alg"`
		PublicKey string  `json:"public_key"`
		Status    string  `json:"status"`
		CreatedAt string  `json:"created_at"`
		RetiredAt *string `json:"retired_at"`
	} `json:"keys"`
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestWellKnownKeySetOnEdge(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.NewMigrated(t)
	repos := db.New(pool)
	lp, err := local.NewFromKeys(config.Development, map[int][]byte{1: bytes.Repeat([]byte{0x41}, config.KEKBytes)}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	faulty := kmstest.NewFaulty(lp)
	reg, err := kms.NewRegistry(faulty)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := signing.NewManager(pool, reg, log)
	t.Cleanup(mgr.Close)
	if err := mgr.EnsureCurrent(ctx); err != nil {
		t.Fatal(err)
	}

	// The edge gets only the read side: no key provider reaches it.
	clk := &fakeClock{t: time.Now()}
	srv := httptest.NewServer(edge.New(edge.Deps{Log: log, KeySet: signing.NewKeySet(repos, 0, clk.Now)}).Handler())
	t.Cleanup(srv.Close)
	faulty.SetOutage(true) // the key service being down must not matter to this route
	get := func() (int, http.Header, keySetResp, []byte) {
		t.Helper()
		resp, err := http.Get(srv.URL + "/.well-known/cipherframe-keys.json") //nolint:noctx // test
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		var out keySetResp
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("body %s: %v", raw, err)
		}
		return resp.StatusCode, resp.Header, out, raw
	}

	status, hdr, set, raw := get()
	if status != 200 {
		t.Fatalf("status = %d: %s", status, raw)
	}
	for k, want := range map[string]string{
		"Cache-Control": "public, max-age=300", "Access-Control-Allow-Origin": "*",
	} {
		if got := hdr.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}
	if len(set.Keys) != 1 || set.Keys[0].Alg != "ed25519" || set.Keys[0].Status != "active" || set.Keys[0].RetiredAt != nil {
		t.Fatalf("set = %s", raw)
	}
	pub, err := base64.StdEncoding.DecodeString(set.Keys[0].PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key = %v, %v", pub, err)
	}
	for _, banned := range []string{"private", "envelope", "seed", "tenant"} {
		if bytes.Contains(raw, []byte(banned)) {
			t.Fatalf("the key set contains %q", banned)
		}
	}
	if !bytes.Contains(raw, []byte(`"keyid"`)) {
		t.Fatalf("no keyid in %s", raw)
	}
	first := set.Keys[0].KeyID

	// A rotation reaches the endpoint only after the cache expires (at most 60 s), and the order
	// is by creation time.
	faulty.SetOutage(false)
	rot, err := mgr.Rotate(ctx, signing.Audit{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, set, _ = get(); len(set.Keys) != 1 {
		t.Fatalf("keys = %d inside the cache window, want 1", len(set.Keys))
	}
	clk.Advance(signing.KeySetTTL)
	if _, _, set, raw = get(); len(set.Keys) != 2 || set.Keys[0].KeyID != first || set.Keys[1].KeyID != rot.KeyID {
		t.Fatalf("set after rotation = %s", raw)
	}
	// Retirement keeps the key published, with its status and time.
	if _, err := mgr.Retire(ctx, first, signing.Audit{}); err != nil {
		t.Fatal(err)
	}
	clk.Advance(signing.KeySetTTL)
	if _, _, set, raw = get(); len(set.Keys) != 2 || set.Keys[0].Status != "retired" || set.Keys[0].RetiredAt == nil || set.Keys[1].Status != "active" {
		t.Fatalf("set after retirement = %s", raw)
	}
}
