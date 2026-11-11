package signing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/kmstest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/local"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func testProvider(t *testing.T) *local.Provider {
	t.Helper()
	p, err := local.NewFromKeys(config.Development, map[int][]byte{1: bytes.Repeat([]byte{0x41}, config.KEKBytes)}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// offlineManager builds a Manager that never touches a database: seal and open need only the
// key service.
func offlineManager(t *testing.T, p kms.Provider, logs *lockedBuffer) *Manager {
	t.Helper()
	reg, err := kms.NewRegistry(p)
	if err != nil {
		t.Fatal(err)
	}
	var log *slog.Logger
	if logs != nil {
		log = slog.New(slog.NewTextHandler(logs, nil))
	}
	return &Manager{repos: db.New(nil), reg: reg, log: orDiscard(log), now: time.Now, cache: newSeedCache(DefaultSeedTTL, time.Now)}
}

func orDiscard(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.New(slog.NewTextHandler(&lockedBuffer{}, nil))
}

func TestEnvelopeRoundTripAndAADBinding(t *testing.T) {
	ctx := context.Background()
	m := offlineManager(t, testProvider(t), nil)
	nk, err := m.newKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	row := db.SigningKey{KeyID: nk.KeyID, Algorithm: nk.Algorithm, PublicKey: nk.PublicKey, PrivateEnvelope: nk.PrivateEnvelope}
	priv, err := m.open(ctx, row)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(priv.Public().(ed25519.PublicKey), nk.PublicKey) {
		t.Fatal("unwrapped key does not match the published public key")
	}

	// The same envelope under another key id, or another algorithm, must not open.
	other := row
	other.KeyID = id.New[id.SigningKeyKind]().String()
	if _, err := m.open(ctx, other); err == nil {
		t.Fatal("an envelope moved to another key_id opened")
	}
	other = row
	other.Algorithm = "ed448"
	if _, err := m.open(ctx, other); err == nil {
		t.Fatal("an envelope under another algorithm opened")
	}
	// A seed wrapped for another purpose (same provider, same bytes) must not open as a signing key.
	p := m.reg.Current()
	seed := make([]byte, ed25519.SeedSize)
	_, _ = rand.Read(seed)
	w, err := p.Wrap(ctx, seed, []byte("another-purpose"))
	if err != nil {
		t.Fatal(err)
	}
	bad := db.SigningKey{KeyID: nk.KeyID, Algorithm: AlgEd25519, PublicKey: nk.PublicKey, PrivateEnvelope: encodeEnvelope(w)}
	if _, err := m.open(ctx, bad); err == nil {
		t.Fatal("an envelope wrapped for another purpose opened")
	}
}

func TestOpenRefusesWrongPublicKey(t *testing.T) {
	ctx := context.Background()
	m := offlineManager(t, testProvider(t), nil)
	nk, err := m.newKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	row := db.SigningKey{KeyID: nk.KeyID, Algorithm: nk.Algorithm, PublicKey: pub, PrivateEnvelope: nk.PrivateEnvelope}
	_, err = m.open(ctx, row)
	var e *errs.Error
	if !errors.As(err, &e) || e.Code != errs.InternalError {
		t.Fatalf("err = %v, want internal_error", err)
	}
}

func TestDecodeEnvelopeRejectsDamage(t *testing.T) {
	ctx := context.Background()
	m := offlineManager(t, testProvider(t), nil)
	nk, err := m.newKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"empty":     nil,
		"version":   append([]byte{9}, nk.PrivateEnvelope[1:]...),
		"truncated": nk.PrivateEnvelope[:len(nk.PrivateEnvelope)-3],
		"trailing":  append(append([]byte(nil), nk.PrivateEnvelope...), 0),
	} {
		if _, err := decodeEnvelope(b); !errors.Is(err, ErrEnvelope) {
			t.Errorf("%s: err = %v, want ErrEnvelope", name, err)
		}
	}
}

func TestAADIsUnambiguous(t *testing.T) {
	a := aad(binding{keyID: "ab", algorithm: "c"})
	b := aad(binding{keyID: "a", algorithm: "bc"})
	if bytes.Equal(a, b) {
		t.Fatal("different bindings produced the same associated data")
	}
	if !bytes.Contains(aad(binding{}), []byte(aadPurpose)) {
		t.Fatal("the associated data does not name the purpose")
	}
}

func TestKMSOutageIsDependencyUnavailable(t *testing.T) {
	f := kmstest.NewFaulty(testProvider(t))
	f.SetOutage(true)
	m := offlineManager(t, f, nil)
	_, err := m.newKey(context.Background())
	var e *errs.Error
	if !errors.As(err, &e) || e.Code != errs.DependencyUnavailable {
		t.Fatalf("err = %v, want dependency_unavailable", err)
	}
}

func TestSeedCacheEvictionZeroesMemory(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	c := newSeedCache(DefaultSeedTTL, clock)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	held := priv // the same backing array the cache owns
	c.put("sk_a", priv)
	if _, ok := c.sign("sk_a", []byte("m")); !ok {
		t.Fatal("cache miss right after put")
	}
	if allZero(held) {
		t.Fatal("the cached key is zero before eviction")
	}

	mu.Lock()
	now = now.Add(DefaultSeedTTL)
	mu.Unlock()
	if _, ok := c.sign("sk_a", []byte("m")); ok {
		t.Fatal("an entry older than the TTL was used")
	}
	if !allZero(held) {
		t.Fatal("an expired key was not zeroed")
	}

	// Explicit eviction and close zero too.
	_, p2, _ := ed25519.GenerateKey(rand.Reader)
	_, p3, _ := ed25519.GenerateKey(rand.Reader)
	c.put("sk_b", p2)
	c.put("sk_c", p3)
	c.evict("sk_b")
	if !allZero(p2) {
		t.Fatal("an evicted key was not zeroed")
	}
	c.close()
	if !allZero(p3) {
		t.Fatal("close did not zero the key")
	}
}

func TestSeedTTLIsCappedAtFiveMinutes(t *testing.T) {
	m := NewManager(nil, mustRegistry(t), nil, WithSeedTTL(time.Hour))
	if m.cache.ttl != DefaultSeedTTL {
		t.Fatalf("ttl = %v, want %v", m.cache.ttl, DefaultSeedTTL)
	}
	m = NewManager(nil, mustRegistry(t), nil, WithSeedTTL(time.Second))
	if m.cache.ttl != time.Second {
		t.Fatalf("ttl = %v, want 1s", m.cache.ttl)
	}
}

func mustRegistry(t *testing.T) *kms.Registry {
	t.Helper()
	r, err := kms.NewRegistry(testProvider(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

type fakeLister struct {
	mu    sync.Mutex
	calls int
	rows  []db.SigningKey
	err   error
}

func (f *fakeLister) ListSigningKeys(context.Context, string) ([]db.SigningKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.rows, f.err
}

func TestKeySetCachesForAtMostSixtySeconds(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	l := &fakeLister{rows: []db.SigningKey{{KeyID: "sk_a", Algorithm: AlgEd25519, PublicKey: make([]byte, 32), State: StateActive}}}
	ks := NewKeySet(l, time.Hour, clock) // a longer ttl is capped
	for range 3 {
		if _, err := ks.Get(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if l.calls != 1 {
		t.Fatalf("reads = %d, want 1 within the TTL", l.calls)
	}
	mu.Lock()
	now = now.Add(KeySetTTL)
	mu.Unlock()
	if _, err := ks.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	if l.calls != 2 {
		t.Fatalf("reads = %d, want 2 after the TTL", l.calls)
	}
	// A failed read is an error, not stale data.
	mu.Lock()
	now = now.Add(KeySetTTL)
	mu.Unlock()
	l.err = errs.New(errs.DependencyUnavailable, "x")
	if _, err := ks.Get(context.Background()); err == nil {
		t.Fatal("a failed read was hidden")
	}
}

func TestPublicKeyBase64(t *testing.T) {
	k := PublicKey{PublicKey: bytes.Repeat([]byte{1}, 32)}
	if got := k.PublicKeyBase64(); !strings.HasSuffix(got, "=") || len(got) != 44 {
		t.Fatalf("unexpected base64 %q", got)
	}
}
