package auth

import (
	"bytes"
	"context"
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
)

type fakePeppers struct {
	m   map[int]config.Secret
	cur int
}

func (f fakePeppers) Get(v int) (config.Secret, bool) { s, ok := f.m[v]; return s, ok }
func (f fakePeppers) Current() (int, config.Secret)   { return f.cur, f.m[f.cur] }

func peppers() fakePeppers {
	return fakePeppers{
		m: map[int]config.Secret{
			1: config.NewSecret(strings.Repeat("a", 32)),
			2: config.NewSecret(strings.Repeat("b", 32)),
		},
		cur: 2,
	}
}

type fakeStore struct {
	mu      sync.Mutex
	keys    map[string]db.AuthKey
	err     error
	touches []time.Time
}

func (f *fakeStore) GetActiveAPIKeyByPrefix(_ context.Context, prefix string) (db.AuthKey, error) {
	if f.err != nil {
		return db.AuthKey{}, f.err
	}
	k, ok := f.keys[prefix]
	if !ok {
		return db.AuthKey{}, errs.New(errs.NotFound, "resource not found")
	}
	return k, nil
}

func (f *fakeStore) TouchAPIKeyLastUsed(_ context.Context, _ id.APIKeyID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touches = append(f.touches, at)
	return nil
}

var t0 = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

type env struct {
	store *fakeStore
	v     *Verifier
	now   time.Time
	log   *bytes.Buffer
}

func newEnv(t *testing.T) (*env, Key) {
	t.Helper()
	e := &env{store: &fakeStore{keys: map[string]db.AuthKey{}}, now: t0, log: &bytes.Buffer{}}
	e.v = NewVerifier(e.store, peppers(), slog.New(slog.NewJSONHandler(e.log, nil)), func() time.Time { return e.now })
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	e.put(k, 2)
	return e, k
}

func (e *env) put(k Key, ver int) db.AuthKey {
	p, _ := peppers().Get(ver)
	ak := db.AuthKey{
		APIKey: db.APIKey{
			ID: id.New[id.APIKeyKind](), ClientID: id.New[id.ClientKind](), Name: "n", Prefix: k.Prefix(),
			SecretHash: k.Hash([]byte(p.Reveal())), PepperVersion: ver, Scopes: []db.Scope{db.ScopeAssetsRead},
		},
		TenantID: id.New[id.TenantKind](),
	}
	e.store.keys[k.Prefix()] = ak
	return ak
}

func wantCode(t *testing.T, err error, code errs.Code) {
	t.Helper()
	var e *errs.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("error = %v, want code %s", err, code)
	}
}

func TestAuthenticateOK(t *testing.T) {
	e, k := newEnv(t)
	p, err := e.v.Authenticate(context.Background(), k.Reveal())
	if err != nil {
		t.Fatal(err)
	}
	stored := e.store.keys[k.Prefix()]
	if p.KeyID != stored.ID || p.ClientID != stored.ClientID || p.TenantID != stored.TenantID || !p.HasScope(db.ScopeAssetsRead) || p.HasScope(db.ScopeAdmin) {
		t.Fatalf("unexpected principal %+v", p)
	}
}

func TestAuthenticateRejections(t *testing.T) {
	e, k := newEnv(t)
	ctx := context.Background()
	wrongSecret, _ := WithNewSecret(k.Prefix())
	unknown, _ := NewKey()
	cases := map[string]string{
		"malformed":      "cf_nope",
		"empty":          "",
		"wrong secret":   wrongSecret.Reveal(),
		"unknown prefix": unknown.Reveal(),
	}
	var details []string
	for name, tok := range cases {
		_, err := e.v.Authenticate(ctx, tok)
		wantCode(t, err, errs.Unauthenticated)
		var ee *errs.Error
		errors.As(err, &ee)
		details = append(details, ee.Detail)
		if strings.Contains(err.Error(), tok) && tok != "" {
			t.Errorf("%s: error contains the token", name)
		}
	}
	for _, d := range details[1:] {
		if d != details[0] {
			t.Fatalf("details differ: %q vs %q", d, details[0])
		}
	}
}

func TestAuthenticateOlderPepperVersion(t *testing.T) {
	e, _ := newEnv(t)
	k, _ := NewKey()
	e.put(k, 1) // hashed with the old, still configured pepper
	if _, err := e.v.Authenticate(context.Background(), k.Reveal()); err != nil {
		t.Fatalf("key under pepper v1 rejected: %v", err)
	}
}

func TestAuthenticatePreviousSecretWindow(t *testing.T) {
	e, oldKey := newEnv(t)
	ak := e.store.keys[oldKey.Prefix()]
	newKey, _ := WithNewSecret(oldKey.Prefix())
	p1, _ := peppers().Get(1)
	p2, _ := peppers().Get(2)
	// The old secret was hashed under v1; the key was rotated onto v2 with a 10 minute overlap.
	ak.Previous = &db.PreviousSecret{Hash: oldKey.Hash([]byte(p1.Reveal())), PepperVersion: 1, ValidUntil: t0.Add(10 * time.Minute)}
	ak.SecretHash, ak.PepperVersion = newKey.Hash([]byte(p2.Reveal())), 2
	e.store.keys[oldKey.Prefix()] = ak
	ctx := context.Background()

	if _, err := e.v.Authenticate(ctx, newKey.Reveal()); err != nil {
		t.Fatalf("new key: %v", err)
	}
	if _, err := e.v.Authenticate(ctx, oldKey.Reveal()); err != nil {
		t.Fatalf("old key inside the window: %v", err)
	}
	e.now = t0.Add(10*time.Minute - time.Nanosecond)
	if _, err := e.v.Authenticate(ctx, oldKey.Reveal()); err != nil {
		t.Fatalf("old key just inside the window: %v", err)
	}
	e.now = t0.Add(10 * time.Minute) // valid_until > now is required
	_, err := e.v.Authenticate(ctx, oldKey.Reveal())
	wantCode(t, err, errs.Unauthenticated)
	e.now = t0.Add(time.Hour)
	_, err = e.v.Authenticate(ctx, oldKey.Reveal())
	wantCode(t, err, errs.Unauthenticated)
	if _, err := e.v.Authenticate(ctx, newKey.Reveal()); err != nil {
		t.Fatalf("new key after the window: %v", err)
	}
}

func TestAuthenticateDisabledAndRevoked(t *testing.T) {
	for name, mut := range map[string]func(*db.AuthKey){
		"client disabled": func(k *db.AuthKey) { k.ClientDisabledAt = &t0 },
		"tenant disabled": func(k *db.AuthKey) { k.TenantDisabledAt = &t0 },
		"revoked":         func(k *db.AuthKey) { k.RevokedAt = &t0 },
	} {
		e, k := newEnv(t)
		ak := e.store.keys[k.Prefix()]
		mut(&ak)
		e.store.keys[k.Prefix()] = ak
		_, err := e.v.Authenticate(context.Background(), k.Reveal())
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		wantCode(t, err, errs.Unauthenticated)
	}
}

func TestAuthenticateMissingPepperIsServerFault(t *testing.T) {
	e, _ := newEnv(t)
	k, _ := NewKey()
	ak := e.put(k, 2)
	ak.PepperVersion = 9 // not configured
	e.store.keys[k.Prefix()] = ak
	_, err := e.v.Authenticate(context.Background(), k.Reveal())
	wantCode(t, err, errs.InternalError)
	if !strings.Contains(e.log.String(), `"pepper_version":9`) {
		t.Fatalf("expected the version in the log: %s", e.log.String())
	}
	if strings.Contains(e.log.String(), k.Reveal()[16:]) || strings.Contains(err.Error(), k.Reveal()[16:]) {
		t.Fatal("secret leaked")
	}

	// A previous hash under a missing pepper, inside its window, is also a fault.
	k2, _ := NewKey()
	ak2 := e.put(k2, 2)
	ak2.Previous = &db.PreviousSecret{Hash: []byte("x"), PepperVersion: 9, ValidUntil: t0.Add(time.Hour)}
	e.store.keys[k2.Prefix()] = ak2
	other, _ := WithNewSecret(k2.Prefix())
	_, err = e.v.Authenticate(context.Background(), other.Reveal())
	wantCode(t, err, errs.InternalError)
}

func TestAuthenticateStoreFailureFailsClosed(t *testing.T) {
	e, k := newEnv(t)
	e.store.err = errs.New(errs.DependencyUnavailable, "database unavailable")
	_, err := e.v.Authenticate(context.Background(), k.Reveal())
	wantCode(t, err, errs.DependencyUnavailable)
	e.store.err = errors.New("boom")
	_, err = e.v.Authenticate(context.Background(), k.Reveal())
	wantCode(t, err, errs.InternalError)
}

func TestLastUsedThrottle(t *testing.T) {
	e, k := newEnv(t)
	ctx := context.Background()
	for range 5 {
		if _, err := e.v.Authenticate(ctx, k.Reveal()); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.store.touches) != 1 {
		t.Fatalf("touches = %d, want 1 for a burst", len(e.store.touches))
	}
	e.now = t0.Add(59 * time.Second)
	_, _ = e.v.Authenticate(ctx, k.Reveal())
	if len(e.store.touches) != 1 {
		t.Fatal("touched again inside a minute")
	}
	e.now = t0.Add(61 * time.Second)
	_, _ = e.v.Authenticate(ctx, k.Reveal())
	if len(e.store.touches) != 2 {
		t.Fatalf("touches = %d, want 2 after a minute", len(e.store.touches))
	}

	// A fresh process sees a recent stored last_used_at and does not write.
	ak := e.store.keys[k.Prefix()]
	recent := e.now.Add(-30 * time.Second)
	ak.LastUsedAt = &recent
	e.store.keys[k.Prefix()] = ak
	v2 := NewVerifier(e.store, peppers(), nil, func() time.Time { return e.now })
	_, _ = v2.Authenticate(ctx, k.Reveal())
	if len(e.store.touches) != 2 {
		t.Fatal("wrote although last_used_at was recent")
	}
}

func TestBearerToken(t *testing.T) {
	ok := map[string]string{"Bearer abc": "abc", "bearer abc": "abc", "BEARER abc": "abc", "BeArEr abc": "abc"}
	for in, want := range ok {
		if got, good := BearerToken(in); !good || got != want {
			t.Errorf("BearerToken(%q) = %q, %v", in, got, good)
		}
	}
	for _, in := range []string{"", "Bearer", "Bearer ", "Basic abc", "Bearer  abc", "Bearer abc ", "Bearer a b", "Bearer\tabc", "Bearerabc", "Bearer abc\n"} {
		if got, good := BearerToken(in); good {
			t.Errorf("BearerToken(%q) accepted: %q", in, got)
		}
	}
}
