//go:build integration

package db_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

func readyAsset(t *testing.T, r *db.Repos, f fixture) db.Asset {
	t.Helper()
	ctx := context.Background()
	a := newUploadAsset(t, r, f, db.UploadTus)
	for _, edge := range [][2]db.AssetState{
		{db.AssetCreated, db.AssetUploading},
		{db.AssetUploading, db.AssetCommitted},
		{db.AssetCommitted, db.AssetProcessing},
		{db.AssetProcessing, db.AssetReady},
	} {
		var err error
		if a, err = r.TransitionAsset(ctx, f.tenant.ID, a.ID, db.Transition{From: edge[0], To: edge[1]}); err != nil {
			t.Fatal(err)
		}
	}
	return a
}

// The Go defaults and the column defaults are the same numbers.
func TestPlaybackSettingsDefaultsMatchTheTable(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f := newFixture(t, r, "acme")
	if _, err := pool.Exec(ctx, "INSERT INTO playback_settings (tenant_id) VALUES ($1)", f.tenant.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetPlaybackSettings(ctx, f.tenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	got.UpdatedAt = time.Time{}
	if want := db.DefaultPlaybackSettings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("column defaults %+v != Go defaults %+v", got, want)
	}
	// No row: the defaults.
	other := newFixture(t, r, "other")
	if got, err := r.GetPlaybackSettings(ctx, other.tenant.ID); err != nil || !reflect.DeepEqual(got, db.DefaultPlaybackSettings()) {
		t.Fatalf("no row: %+v, %v", got, err)
	}
}

func TestPlaybackSettingsPutReplacesAndIsPerTenant(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	a, b := newFixture(t, r, "a"), newFixture(t, r, "b")
	s := db.DefaultPlaybackSettings()
	s.TokenTTLSeconds, s.MaxSessionsPerViewer, s.TokenInURL = 900, 0, true
	s.AllowedOrigins = []string{"https://a.example.com"}
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := r.PutPlaybackSettings(ctx, a.tenant.ID, s, at); err != nil {
		t.Fatal(err)
	}
	s.TokenTTLSeconds, s.AllowedOrigins = 1200, nil
	got, err := r.PutPlaybackSettings(ctx, a.tenant.ID, s, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got.TokenTTLSeconds != 1200 || got.MaxSessionsPerViewer != 0 || !got.TokenInURL || len(got.AllowedOrigins) != 0 || !got.UpdatedAt.Equal(at.Add(time.Second)) {
		t.Fatalf("replaced settings = %+v", got)
	}
	if other, _ := r.GetPlaybackSettings(ctx, b.tenant.ID); !reflect.DeepEqual(other, db.DefaultPlaybackSettings()) {
		t.Fatalf("another tenant's settings changed: %+v", other)
	}
}

func TestPlaybackSettingsChecks(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f := newFixture(t, r, "acme")
	for name, set := range map[string]string{
		"token ttl low":      "token_ttl_seconds = 59",
		"token ttl high":     "token_ttl_seconds = 3601",
		"heartbeat low":      "heartbeat_interval_seconds = 9",
		"heartbeat high":     "heartbeat_interval_seconds = 601, token_ttl_seconds = 3600, idle_timeout_seconds = 3600",
		"heartbeat >= ttl":   "heartbeat_interval_seconds = 100, token_ttl_seconds = 100",
		"heartbeat >= idle":  "heartbeat_interval_seconds = 100, idle_timeout_seconds = 100",
		"idle low":           "idle_timeout_seconds = 29",
		"idle high":          "idle_timeout_seconds = 3601",
		"session max low":    "session_max_seconds = 299",
		"session max high":   "session_max_seconds = 86401",
		"max sessions neg":   "max_sessions_per_viewer = -1",
		"max sessions high":  "max_sessions_per_viewer = 101",
		"key fetches zero":   "key_fetches_per_token = 0",
		"key fetches high":   "key_fetches_per_token = 1001",
		"key rpm zero":       "key_requests_per_minute = 0",
		"key rpm high":       "key_requests_per_minute = 601",
		"too many origins":   "allowed_origins = (SELECT array_agg('https://h' || i || '.example.com') FROM generate_series(1, 21) i)",
		"null origins":       "allowed_origins = NULL",
		"null url transport": "token_in_url = NULL",
		"unknown delivery":   "delivery = 'cdn'",
		"null delivery":      "delivery = NULL",
	} {
		_, err := pool.Exec(ctx, "INSERT INTO playback_settings (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING", f.tenant.ID.UUID())
		if err != nil {
			t.Fatal(err)
		}
		_, err = pool.Exec(ctx, "UPDATE playback_settings SET "+set+" WHERE tenant_id = $1", f.tenant.ID.UUID())
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || (pe.Code != "23514" && pe.Code != "23502") {
			t.Errorf("%s: err = %v, want a check or not-null violation", name, err)
		}
	}
	// The valid extremes are accepted.
	if _, err := pool.Exec(ctx, `UPDATE playback_settings SET token_ttl_seconds = 60, heartbeat_interval_seconds = 10,
		idle_timeout_seconds = 30, session_max_seconds = 300, max_sessions_per_viewer = 0, key_fetches_per_token = 1,
		key_requests_per_minute = 1 WHERE tenant_id = $1`, f.tenant.ID.UUID()); err != nil {
		t.Fatalf("minimum values rejected: %v", err)
	}
}

func newSession(f fixture, asset db.Asset, viewer string, now time.Time) db.NewPlaybackSession {
	sid, err := id.NewSession()
	if err != nil {
		panic(err)
	}
	return db.NewPlaybackSession{
		ID: sid, TenantID: f.tenant.ID, ClientID: f.client.ID, AssetID: asset.ID, ViewerID: viewer,
		Now: now, ExpiresAt: now.Add(4 * time.Hour),
	}
}

func TestPlaybackSessionsStoreOnlyTheHash(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f := newFixture(t, r, "acme")
	a := readyAsset(t, r, f)
	now := micro(time.Now())
	in := newSession(f, a, "viewer-1", now)
	s, err := r.InsertPlaybackSession(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if s.State != db.PlaybackActive || !bytes.Equal(s.IDHash, db.SessionHash(in.ID)) || s.AssetID != a.ID || s.ClientID != f.client.ID ||
		!s.CreatedAt.Equal(now) || !s.LastHeartbeatAt.Equal(now) || !s.ExpiresAt.Equal(in.ExpiresAt) || s.EndedAt != nil || s.RevokedAt != nil {
		t.Fatalf("session = %+v", s)
	}
	// Nothing in the table is the ID's text.
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM playback_sessions WHERE playback_sessions::text LIKE '%' || $1 || '%'", in.ID.String()[4:20]).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the session ID text appears in the table: n=%d err=%v", n, err)
	}
	got, err := r.GetPlaybackSession(ctx, f.tenant.ID, db.SessionHash(in.ID))
	if err != nil || got.ViewerID != "viewer-1" {
		t.Fatalf("get = %+v, %v", got, err)
	}
	// Another tenant cannot read it.
	other := newFixture(t, r, "other")
	_, err = r.GetPlaybackSession(ctx, other.tenant.ID, db.SessionHash(in.ID))
	wantCode(t, err, errs.NotFound)
}

func TestPlaybackSessionTenant(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	a := readyAsset(t, r, f)
	in := newSession(f, a, "viewer-1", micro(time.Now()))
	if _, err := r.InsertPlaybackSession(ctx, in); err != nil {
		t.Fatal(err)
	}
	got, err := r.PlaybackSessionTenant(ctx, db.SessionHash(in.ID))
	if err != nil || got != f.tenant.ID {
		t.Fatalf("tenant = %v, %v", got, err)
	}
	unknown, err := id.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.PlaybackSessionTenant(ctx, db.SessionHash(unknown))
	wantCode(t, err, errs.NotFound)
}

func TestInsertPlaybackSessionNeedsAReadyAssetOfTheTenant(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	other := newFixture(t, r, "other")
	now := micro(time.Now())

	pending := newUploadAsset(t, r, f, db.UploadTus)
	_, err := r.InsertPlaybackSession(ctx, newSession(f, pending, "v", now))
	wantCode(t, err, errs.Conflict)

	ready := readyAsset(t, r, other)
	in := newSession(f, ready, "v", now) // another tenant's asset
	_, err = r.InsertPlaybackSession(ctx, in)
	wantCode(t, err, errs.Conflict)

	// Invalid input.
	bad := newSession(f, readyAsset(t, r, f), "v", now)
	bad.ViewerID = ""
	if _, err := r.InsertPlaybackSession(ctx, bad); err == nil {
		t.Error("empty viewer accepted")
	}
	bad.ViewerID = strings.Repeat("x", 129)
	if _, err := r.InsertPlaybackSession(ctx, bad); err == nil {
		t.Error("129-character viewer accepted")
	}
	bad.ViewerID, bad.ExpiresAt = "v", now
	if _, err := r.InsertPlaybackSession(ctx, bad); err == nil {
		t.Error("expiry not after creation accepted")
	}
}

func TestEndStaleAndCountActive(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f := newFixture(t, r, "acme")
	a := readyAsset(t, r, f)
	now := micro(time.Now())
	idle := 5 * time.Minute

	var fresh, idleOne, expired, otherViewer db.NewPlaybackSession
	for _, p := range []*db.NewPlaybackSession{&fresh, &idleOne, &expired} {
		*p = newSession(f, a, "v", now)
		if _, err := r.InsertPlaybackSession(ctx, *p); err != nil {
			t.Fatal(err)
		}
	}
	otherViewer = newSession(f, a, "w", now)
	if _, err := r.InsertPlaybackSession(ctx, otherViewer); err != nil {
		t.Fatal(err)
	}
	// Age two of them in the database.
	if _, err := pool.Exec(ctx, "UPDATE playback_sessions SET last_heartbeat_at = $1 WHERE id_hash = $2", now.Add(-idle-time.Second), db.SessionHash(idleOne.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE playback_sessions SET created_at = $1, expires_at = $2 WHERE id_hash = $3", now.Add(-time.Hour), now.Add(-time.Second), db.SessionHash(expired.ID)); err != nil {
		t.Fatal(err)
	}
	// All three are still marked active; only one counts.
	if n, err := r.CountActivePlaybackSessions(ctx, f.tenant.ID, "v", now, idle); err != nil || n != 1 {
		t.Fatalf("count = %d, %v; want 1", n, err)
	}
	// A heartbeat exactly at the idle boundary no longer counts.
	if _, err := pool.Exec(ctx, "UPDATE playback_sessions SET last_heartbeat_at = $1 WHERE id_hash = $2", now.Add(-idle), db.SessionHash(fresh.ID)); err != nil {
		t.Fatal(err)
	}
	if n, _ := r.CountActivePlaybackSessions(ctx, f.tenant.ID, "v", now, idle); n != 0 {
		t.Fatalf("count at the idle boundary = %d, want 0", n)
	}
	if _, err := pool.Exec(ctx, "UPDATE playback_sessions SET last_heartbeat_at = $1 WHERE id_hash = $2", now, db.SessionHash(fresh.ID)); err != nil {
		t.Fatal(err)
	}

	ended, err := r.EndStalePlaybackSessions(ctx, f.tenant.ID, "v", now, idle)
	if err != nil || ended != 2 {
		t.Fatalf("ended = %d, %v; want 2", ended, err)
	}
	for sid, want := range map[id.SessionID]string{
		fresh.ID: db.PlaybackActive, idleOne.ID: db.PlaybackEnded, expired.ID: db.PlaybackEnded, otherViewer.ID: db.PlaybackActive,
	} {
		s, err := r.GetPlaybackSession(ctx, f.tenant.ID, db.SessionHash(sid))
		if err != nil || s.State != want || (want == db.PlaybackEnded && s.EndedAt == nil) {
			t.Errorf("state = %+v (%v), want %s", s, err, want)
		}
	}
	// A second pass changes nothing.
	if ended, _ := r.EndStalePlaybackSessions(ctx, f.tenant.ID, "v", now, idle); ended != 0 {
		t.Fatalf("second pass ended %d", ended)
	}
}

// The viewer lock serialises count-then-insert across connections.
func TestPlaybackViewerLockSerialises(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f := newFixture(t, r, "acme")
	a := readyAsset(t, r, f)
	const limit, workers = 3, 12

	var created atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			now := micro(time.Now())
			err := db.Tx(ctx, pool, func(tx *db.Repos) error {
				if err := tx.LockPlaybackViewer(ctx, f.tenant.ID, "v"); err != nil {
					return err
				}
				n, err := tx.CountActivePlaybackSessions(ctx, f.tenant.ID, "v", now, 5*time.Minute)
				if err != nil || n >= limit {
					return err
				}
				_, err = tx.InsertPlaybackSession(ctx, newSession(f, a, "v", now))
				if err == nil {
					created.Add(1)
				}
				return err
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if created.Load() != limit {
		t.Fatalf("created %d sessions, want %d", created.Load(), limit)
	}
}

func TestPlaybackSessionStateChecks(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f := newFixture(t, r, "acme")
	a := readyAsset(t, r, f)
	in := newSession(f, a, "v", micro(time.Now()))
	if _, err := r.InsertPlaybackSession(ctx, in); err != nil {
		t.Fatal(err)
	}
	for name, set := range map[string]string{
		"unknown state":        "state = 'paused'",
		"ended without time":   "state = 'ended'",
		"revoked without time": "state = 'revoked'",
		"active with end time": "ended_at = now()",
		"long reason":          "revoke_reason = repeat('x', 201)",
	} {
		_, err := pool.Exec(ctx, "UPDATE playback_sessions SET "+set+" WHERE id_hash = $1", db.SessionHash(in.ID))
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "23514" {
			t.Errorf("%s: err = %v, want a check violation", name, err)
		}
	}
	if _, err := pool.Exec(ctx, "UPDATE playback_sessions SET state = 'revoked', revoked_at = now(), revoke_reason = 'test' WHERE id_hash = $1", db.SessionHash(in.ID)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}
