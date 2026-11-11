//go:build integration

package db_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

func keySession(t *testing.T, r *db.Repos, f fixture) db.PlaybackSession {
	t.Helper()
	a := readyAsset(t, r, f)
	sid, err := id.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	s, err := r.InsertPlaybackSession(context.Background(), db.NewPlaybackSession{
		ID: sid, TenantID: f.tenant.ID, ClientID: f.client.ID, AssetID: a.ID, ViewerID: "v", Now: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPlaybackKeyWindowAndFetches(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	s := keySession(t, r, f)
	t0 := time.Now().UTC().Truncate(time.Microsecond)

	// The window counts up, restarts after a minute, and an unknown session is not_found.
	for want := 1; want <= 3; want++ {
		start, n, err := r.BumpPlaybackKeyWindow(ctx, f.tenant.ID, s.IDHash, t0.Add(time.Duration(want)*time.Second))
		if err != nil || n != want || !start.Equal(t0.Add(time.Second)) {
			t.Fatalf("bump %d: start %v, n %d, err %v", want, start, n, err)
		}
	}
	start, n, err := r.BumpPlaybackKeyWindow(ctx, f.tenant.ID, s.IDHash, t0.Add(61*time.Second))
	if err != nil || n != 1 || !start.Equal(t0.Add(61*time.Second)) {
		t.Fatalf("new window: start %v, n %d, err %v", start, n, err)
	}
	if _, _, err := r.BumpPlaybackKeyWindow(ctx, f.tenant.ID, make([]byte, 32), t0); err == nil {
		t.Fatal("an unknown session was counted")
	}

	// Reserve takes exactly limit fetches; release gives one back; replay is recorded once.
	tok := db.TokenHash("test-fixture-token")
	for i := range 2 {
		if ok, err := r.ReservePlaybackKeyFetch(ctx, tok, s.IDHash, t0.Add(time.Hour), 2); err != nil || !ok {
			t.Fatalf("reserve %d: %v, %v", i, ok, err)
		}
	}
	if ok, err := r.ReservePlaybackKeyFetch(ctx, tok, s.IDHash, t0.Add(time.Hour), 2); err != nil || ok {
		t.Fatalf("reserve past the limit: %v, %v", ok, err)
	}
	for i, want := range []bool{true, false, false} {
		hash, got, err := r.MarkKeyReplay(ctx, tok, t0)
		if err != nil || got != want || (got && !bytes.Equal(hash, s.IDHash)) {
			t.Fatalf("replay %d: %v, %v", i, got, err)
		}
	}
	if err := r.ReleasePlaybackKeyFetch(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if ok, err := r.ReservePlaybackKeyFetch(ctx, tok, s.IDHash, t0.Add(time.Hour), 2); err != nil || !ok {
		t.Fatalf("reserve after release: %v, %v", ok, err)
	}
	// A bad token hash is refused before the database.
	if _, err := r.ReservePlaybackKeyFetch(ctx, []byte("short"), s.IDHash, t0, 2); err == nil {
		t.Fatal("a short token hash was accepted")
	}

	// Events: only the known kinds are allowed.
	ev := db.NewAnomalyEvent{TenantID: f.tenant.ID, SessionHash: s.IDHash, AssetID: s.AssetID, Kind: db.EventKeyRate, At: t0, Since: t0.Add(-time.Minute), Detail: map[string]int64{"limit": 3}}
	if ok, err := r.InsertAnomalyEvent(ctx, ev); err != nil || !ok {
		t.Fatalf("insert event: %v, %v", ok, err)
	}
	if ok, err := r.InsertAnomalyEvent(ctx, ev); err != nil || ok {
		t.Fatalf("a duplicate in the window was stored: %v, %v", ok, err)
	}
	ev.Kind = "other"
	if _, err := r.InsertAnomalyEvent(ctx, ev); err == nil {
		t.Fatal("an unknown event kind was accepted")
	}

	// The sweep deletes expired counters only.
	if n, err := r.SweepPlaybackKeyFetches(ctx, t0); err != nil || n != 0 {
		t.Fatalf("early sweep: %d, %v", n, err)
	}
	if n, err := r.SweepPlaybackKeyFetches(ctx, t0.Add(2*time.Hour)); err != nil || n != 1 {
		t.Fatalf("sweep: %d, %v", n, err)
	}
}
