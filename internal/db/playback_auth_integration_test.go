//go:build integration

package db_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

func TestPlaybackAuthDefaultsMatchTheTable(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f := newFixture(t, r, "acme")
	if got, err := r.GetPlaybackAuth(ctx, f.tenant.ID); err != nil || !reflect.DeepEqual(got, db.DefaultPlaybackAuth()) {
		t.Fatalf("no row: %+v, %v", got, err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO playback_auth (tenant_id) VALUES ($1)", f.tenant.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetPlaybackAuth(ctx, f.tenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	got.UpdatedAt = time.Time{}
	if want := db.DefaultPlaybackAuth(); !reflect.DeepEqual(got, want) {
		t.Fatalf("column defaults %+v != Go defaults %+v", got, want)
	}
}

func TestPlaybackAuthConfigAndSecretRotation(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	at := micro(time.Now())

	cfg := db.PlaybackAuth{
		JWTEnabled: true, JWTIssuer: "https://issuer.example.com", JWTAudiences: []string{"cipherframe"},
		JWKSURL: "https://issuer.example.com/jwks.json", JWTViewerClaim: "sub",
		CallbackEnabled: false, CallbackURL: "https://app.example.com/authorize",
	}
	got, err := r.PutPlaybackAuthConfig(ctx, f.tenant.ID, cfg, at)
	if err != nil || got.JWTIssuer != cfg.JWTIssuer || got.JWKSURL != cfg.JWKSURL || got.CallbackURL != cfg.CallbackURL || got.CallbackSecretVersion != 0 {
		t.Fatalf("put: %+v, %v", got, err)
	}

	// Rotation: the first has no previous secret, the second keeps the first as previous.
	got, err = r.RotatePlaybackCallbackSecret(ctx, f.tenant.ID, []byte("env-1"), 1, at)
	if err != nil || got.CallbackSecretVersion != 1 || string(got.CallbackSecretEnvelope) != "env-1" || got.CallbackSecretPrevVersion != 0 ||
		got.CallbackSecretRotatedAt == nil || got.JWTIssuer != cfg.JWTIssuer {
		t.Fatalf("rotate 1: %+v, %v", got, err)
	}
	got, err = r.RotatePlaybackCallbackSecret(ctx, f.tenant.ID, []byte("env-2"), 2, at.Add(time.Minute))
	if err != nil || got.CallbackSecretVersion != 2 || string(got.CallbackSecretEnvelope) != "env-2" ||
		got.CallbackSecretPrevVersion != 1 || string(got.CallbackSecretPrevEnvelope) != "env-1" {
		t.Fatalf("rotate 2: %+v, %v", got, err)
	}
	// A stale rotation (the version is not the next one) changes nothing.
	if _, err := r.RotatePlaybackCallbackSecret(ctx, f.tenant.ID, []byte("env-x"), 2, at); !isCode(err, errs.Conflict) {
		t.Fatalf("stale rotation: %v", err)
	}
	// Replacing the configuration leaves the secrets alone.
	cfg.JWTEnabled = false
	got, err = r.PutPlaybackAuthConfig(ctx, f.tenant.ID, cfg, at)
	if err != nil || got.CallbackSecretVersion != 2 || got.CallbackSecretPrevVersion != 1 || got.JWTEnabled {
		t.Fatalf("put after rotate: %+v, %v", got, err)
	}
	// Rotation before any config row exists creates the row with everything else off.
	other := newFixture(t, r, "other")
	got, err = r.RotatePlaybackCallbackSecret(ctx, other.tenant.ID, []byte("env"), 1, at)
	if err != nil || got.JWTEnabled || got.CallbackEnabled || got.JWTViewerClaim != "sub" || got.CallbackSecretVersion != 1 {
		t.Fatalf("rotate without a row: %+v, %v", got, err)
	}
}

func isCode(err error, code errs.Code) bool {
	var e *errs.Error
	return errors.As(err, &e) && e.Code == code
}

func TestPlaybackAuthConstraints(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f := newFixture(t, r, "acme")
	tid := f.tenant.ID.UUID()
	bad := map[string]string{
		"http jwks url":                  "INSERT INTO playback_auth (tenant_id, jwt_jwks_url) VALUES ($1, 'http://x.example.com/jwks')",
		"http callback url":              "INSERT INTO playback_auth (tenant_id, callback_url) VALUES ($1, 'http://x.example.com/cb')",
		"callback enabled without a url": "INSERT INTO playback_auth (tenant_id, callback_enabled) VALUES ($1, true)",
		"empty viewer claim":             "INSERT INTO playback_auth (tenant_id, jwt_viewer_claim) VALUES ($1, '')",
		"version without envelope":       "INSERT INTO playback_auth (tenant_id, callback_secret_version) VALUES ($1, 1)",
		"envelope without version":       "INSERT INTO playback_auth (tenant_id, callback_secret_envelope) VALUES ($1, '\\x01')",
	}
	for name, q := range bad {
		if _, err := pool.Exec(ctx, q, tid); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := pool.Exec(ctx, "INSERT INTO playback_jwt_keys (tenant_id, kid, alg, jwk) VALUES ($1, 'k', 'HS256', '{}')", tid); err == nil {
		t.Error("an HS256 key row was accepted")
	}
	if _, err := pool.Exec(ctx, "INSERT INTO playback_jwt_jti (tenant_id, jti_hash, expires_at) VALUES ($1, '\\x00', now())", tid); err == nil {
		t.Error("a short jti hash was accepted")
	}
}

func TestPlaybackJWTKeys(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f := newFixture(t, r, "acme")
	other := newFixture(t, r, "other")
	at := micro(time.Now())
	put := func(tenant db.Tenant, kid string) error {
		return db.Tx(ctx, pool, func(tx *db.Repos) error {
			_, err := tx.PutPlaybackJWTKey(ctx, tenant.ID, db.PlaybackJWTKey{Kid: kid, Alg: "EdDSA", JWK: []byte(`{"kty":"OKP"}`)}, at)
			return err
		})
	}
	for i := range db.MaxPlaybackJWTKeys {
		if err := put(f.tenant, "k"+strings.Repeat("x", i)); err != nil {
			t.Fatalf("key %d: %v", i, err)
		}
	}
	if err := put(f.tenant, "one-too-many"); !isCode(err, errs.Conflict) {
		t.Fatalf("21st key: %v", err)
	}
	// Replacing an existing kid is not a new key, and the cap is per tenant.
	if err := put(f.tenant, "k"); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if err := put(other.tenant, "one"); err != nil {
		t.Fatalf("another tenant: %v", err)
	}
	keys, err := r.ListPlaybackJWTKeys(ctx, f.tenant.ID)
	if err != nil || len(keys) != db.MaxPlaybackJWTKeys {
		t.Fatalf("list: %d keys, %v", len(keys), err)
	}
	if ok, err := r.DeletePlaybackJWTKey(ctx, f.tenant.ID, "k"); err != nil || !ok {
		t.Fatalf("delete: %v %v", ok, err)
	}
	if ok, err := r.DeletePlaybackJWTKey(ctx, f.tenant.ID, "k"); err != nil || ok {
		t.Fatalf("second delete: %v %v", ok, err)
	}
	if ok, err := r.DeletePlaybackJWTKey(ctx, other.tenant.ID, "kx"); err != nil || ok {
		t.Fatalf("another tenant's kid: %v %v", ok, err)
	}

	// Concurrent uploads at the cap: exactly one of two racing inserts of a fresh kid wins.
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := put(f.tenant, "race-"+strings.Repeat("r", i)); err == nil {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if won != 1 { // 19 keys after the delete: room for exactly one more
		t.Fatalf("%d concurrent uploads succeeded, want 1", won)
	}
}

func TestPlaybackJWTIDsAreSingleUse(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	other := newFixture(t, r, "other")
	exp := micro(time.Now().Add(time.Hour))
	for i, want := range []bool{true, false, false} {
		if got, err := r.ClaimPlaybackJWTID(ctx, f.tenant.ID, "jti-1", exp); err != nil || got != want {
			t.Fatalf("claim %d: %v %v", i, got, err)
		}
	}
	// The same jti under another tenant is a different claim.
	if got, err := r.ClaimPlaybackJWTID(ctx, other.tenant.ID, "jti-1", exp); err != nil || !got {
		t.Fatalf("other tenant: %v %v", got, err)
	}
	if _, err := r.ClaimPlaybackJWTID(ctx, f.tenant.ID, "", exp); err == nil {
		t.Fatal("an empty jti was accepted")
	}
	// Exactly one of many racing claims wins.
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, err := r.ClaimPlaybackJWTID(ctx, f.tenant.ID, "jti-race", exp); err == nil && ok {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if won != 1 {
		t.Fatalf("%d racing claims won, want 1", won)
	}
	// The sweep deletes only expired ids.
	if n, err := r.SweepPlaybackJWTIDs(ctx, exp.Add(-time.Minute)); err != nil || n != 0 {
		t.Fatalf("early sweep: %d %v", n, err)
	}
	if n, err := r.SweepPlaybackJWTIDs(ctx, exp.Add(time.Minute)); err != nil || n != 3 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	if got, err := r.ClaimPlaybackJWTID(ctx, f.tenant.ID, "jti-1", exp); err != nil || !got {
		t.Fatalf("claim after sweep: %v %v", got, err)
	}
}

func TestPlaybackSessionAuthMethodAndClient(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f := newFixture(t, r, "acme")
	a := readyAsset(t, r, f)
	now := micro(time.Now())

	// API-key session: the default, with a client.
	in := newSession(f, a, "v1", now)
	s, err := r.InsertPlaybackSession(ctx, in)
	if err != nil || s.AuthMethod != db.AuthMethodAPIKey || s.ClientID != f.client.ID {
		t.Fatalf("api key session: %+v, %v", s, err)
	}
	// JWT and callback sessions have no client.
	for _, m := range []string{db.AuthMethodJWT, db.AuthMethodCallback} {
		in := newSession(f, a, "v-"+m, now)
		in.AuthMethod, in.ClientID = m, id.ClientID{}
		s, err := r.InsertPlaybackSession(ctx, in)
		if err != nil || s.AuthMethod != m || !s.ClientID.IsZero() {
			t.Fatalf("%s session: %+v, %v", m, s, err)
		}
		got, err := r.GetPlaybackSession(ctx, f.tenant.ID, db.SessionHash(in.ID))
		if err != nil || got.AuthMethod != m || !got.ClientID.IsZero() {
			t.Fatalf("read back %s: %+v, %v", m, got, err)
		}
	}
	// The repository refuses the combinations the CHECK forbids, and so does the table.
	bad := newSession(f, a, "bad", now)
	bad.AuthMethod = db.AuthMethodJWT // with a client
	if _, err := r.InsertPlaybackSession(ctx, bad); err == nil {
		t.Fatal("a jwt session with a client was accepted")
	}
	bad = newSession(f, a, "bad", now)
	bad.AuthMethod, bad.ClientID = db.AuthMethodAPIKey, id.ClientID{}
	if _, err := r.InsertPlaybackSession(ctx, bad); err == nil {
		t.Fatal("an api_key session without a client was accepted")
	}
	if _, err := pool.Exec(ctx, "UPDATE playback_sessions SET client_id = NULL WHERE auth_method = 'api_key'"); err == nil {
		t.Fatal("the table accepted an api_key session without a client")
	}
	if _, err := pool.Exec(ctx, "UPDATE playback_sessions SET auth_method = 'bogus'"); err == nil {
		t.Fatal("the table accepted an unknown auth method")
	}
}
