//go:build integration

package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
)

func TestAnomalyEventsAreDeduplicatedPerSubjectAndWindow(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f := newFixture(t, r, "acme")
	s := keySession(t, r, f)
	t0 := time.Now().UTC().Truncate(time.Microsecond)
	win := 10 * time.Minute

	session := db.NewAnomalyEvent{TenantID: f.tenant.ID, SessionHash: s.IDHash, AssetID: s.AssetID, Kind: db.EventKeyRate, At: t0, Since: t0.Add(-win)}
	for i, want := range []bool{true, false} {
		if ok, err := r.InsertAnomalyEvent(ctx, session); err != nil || ok != want {
			t.Fatalf("session event %d: %v, %v", i, ok, err)
		}
	}
	// Another kind, and the same kind once the window has passed, are new events.
	other := session
	other.Kind = db.EventKeyReplay
	if ok, err := r.InsertAnomalyEvent(ctx, other); err != nil || !ok {
		t.Fatalf("another kind: %v, %v", ok, err)
	}
	later := session
	later.At, later.Since = t0.Add(win+time.Second), t0.Add(time.Second)
	if ok, err := r.InsertAnomalyEvent(ctx, later); err != nil || !ok {
		t.Fatalf("after the window: %v, %v", ok, err)
	}
	// The viewer was copied from the session row.
	var viewer string
	if err := pool.QueryRow(ctx, "SELECT viewer_id FROM playback_events WHERE kind = 'key_replay'").Scan(&viewer); err != nil || viewer != "v" {
		t.Fatalf("viewer = %q, %v", viewer, err)
	}

	// Viewer-level events have no session and dedupe per tenant and viewer.
	v := db.NewAnomalyEvent{TenantID: f.tenant.ID, ViewerID: "v", AssetID: s.AssetID, Kind: db.EventSessionLimit, At: t0, Since: t0.Add(-win)}
	for i, want := range []bool{true, false} {
		if ok, err := r.InsertAnomalyEvent(ctx, v); err != nil || ok != want {
			t.Fatalf("viewer event %d: %v, %v", i, ok, err)
		}
	}
	v.ViewerID = "w"
	if ok, err := r.InsertAnomalyEvent(ctx, v); err != nil || !ok {
		t.Fatalf("another viewer: %v, %v", ok, err)
	}
	// An event needs a subject, and a known kind.
	if _, err := r.InsertAnomalyEvent(ctx, db.NewAnomalyEvent{TenantID: f.tenant.ID, AssetID: s.AssetID, Kind: db.EventKeyRate, At: t0}); err == nil {
		t.Fatal("an event without a session or a viewer was stored")
	}
	// The table itself refuses a subjectless row and an unknown kind.
	if _, err := pool.Exec(ctx, "INSERT INTO playback_events (tenant_id, asset_id, kind) VALUES ($1, $2, 'key_rate')", f.tenant.ID.UUID(), s.AssetID.UUID()); err == nil {
		t.Fatal("the table stored an event without a subject")
	}
	if _, err := pool.Exec(ctx, "INSERT INTO playback_events (tenant_id, asset_id, viewer_id, kind) VALUES ($1, $2, 'v', 'nope')", f.tenant.ID.UUID(), s.AssetID.UUID()); err == nil {
		t.Fatal("the table stored an unknown kind")
	}
	// delivered_at is the outbox mark of M7: new events are undelivered.
	var undelivered int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM playback_events WHERE delivered_at IS NULL").Scan(&undelivered); err != nil || undelivered != 5 {
		t.Fatalf("undelivered = %d, %v", undelivered, err)
	}
}

func TestCountViewerSessionsCreatedSince(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	a := readyAsset(t, r, f)
	now := micro(time.Now())
	for i := range 4 {
		if _, err := r.InsertPlaybackSession(ctx, newSession(f, a, "viewer-1", now.Add(-time.Duration(i)*4*time.Minute))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.InsertPlaybackSession(ctx, newSession(f, a, "viewer-2", now)); err != nil {
		t.Fatal(err)
	}
	// Created at now, -4, -8 and -12 minutes: three of them are within the last 10 minutes.
	n, err := r.CountViewerSessionsCreatedSince(ctx, f.tenant.ID, "viewer-1", now.Add(-10*time.Minute))
	if err != nil || n != 3 {
		t.Fatalf("count = %d, %v", n, err)
	}
	other := newFixture(t, r, "other")
	if n, err := r.CountViewerSessionsCreatedSince(ctx, other.tenant.ID, "viewer-1", now.Add(-time.Hour)); err != nil || n != 0 {
		t.Fatalf("another tenant's viewer counted %d, %v", n, err)
	}
}

func TestAddPlaybackSegmentsFindsSessionsOverTheThresholdWithoutAKey(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	noKey, withKey, quiet := keySession(t, r, f), keySession(t, r, f), keySession(t, r, f)
	if err := r.MarkPlaybackKeyServed(ctx, f.tenant.ID, withKey.IDHash, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	over, err := r.AddPlaybackSegments(ctx, []db.SegmentDelta{
		{SessionHash: noKey.IDHash, Count: 31},
		{SessionHash: withKey.IDHash, Count: 500},
		{SessionHash: quiet.IDHash, Count: 30},
		{SessionHash: make([]byte, 32), Count: 99}, // unknown: ignored
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(over) != 1 || string(over[0].SessionHash) != string(noKey.IDHash) || over[0].Served != 31 || over[0].Threshold != 30 || over[0].TenantID != f.tenant.ID {
		t.Fatalf("over = %+v", over)
	}
	// The count is cumulative: 30 and one more crosses the line.
	over, err = r.AddPlaybackSegments(ctx, []db.SegmentDelta{{SessionHash: quiet.IDHash, Count: 1}})
	if err != nil || len(over) != 1 || over[0].Served != 31 {
		t.Fatalf("cumulative over = %+v, %v", over, err)
	}
	// Once an event exists the session is no longer reported.
	if _, err := r.InsertAnomalyEvent(ctx, db.NewAnomalyEvent{
		TenantID: f.tenant.ID, SessionHash: noKey.IDHash, AssetID: noKey.AssetID, Kind: db.EventSegmentsWithoutKey, At: time.Now(), Since: time.Unix(0, 0),
	}); err != nil {
		t.Fatal(err)
	}
	if over, err = r.AddPlaybackSegments(ctx, []db.SegmentDelta{{SessionHash: noKey.IDHash, Count: 5}}); err != nil || len(over) != 0 {
		t.Fatalf("reported again: %+v, %v", over, err)
	}
	// 0 disables the signal for the tenant.
	set := db.DefaultPlaybackSettings()
	set.AnomalySegmentsWithoutKey = 0
	if _, err := r.PutPlaybackSettings(ctx, f.tenant.ID, set, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	third := keySession(t, r, f)
	if over, err = r.AddPlaybackSegments(ctx, []db.SegmentDelta{{SessionHash: third.IDHash, Count: 1000}}); err != nil || len(over) != 0 {
		t.Fatalf("a disabled signal reported %+v, %v", over, err)
	}
}

func TestListPlaybackEventsFiltersPagesAndIsolatesTenants(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	g := newFixture(t, r, "other")
	s := keySession(t, r, f)
	gs := keySession(t, r, g)
	t0 := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
	// Five events, the first four at the same instant so the cursor has to tie-break on the ID.
	add := func(f fixture, hash []byte, viewer string, a db.Asset, kind string, at time.Time) {
		t.Helper()
		ev := db.NewAnomalyEvent{TenantID: f.tenant.ID, SessionHash: hash, ViewerID: viewer, AssetID: a.ID, Kind: kind, At: at, Since: at.Add(-time.Minute)}
		if hash != nil {
			ev.ViewerID = ""
		}
		if ok, err := r.InsertAnomalyEvent(ctx, ev); err != nil || !ok {
			t.Fatalf("insert %s: %v, %v", kind, ok, err)
		}
	}
	asset := db.Asset{ID: s.AssetID}
	add(f, s.IDHash, "", asset, db.EventKeyRate, t0)
	add(f, s.IDHash, "", asset, db.EventKeyReplay, t0)
	add(f, nil, "viewer-x", asset, db.EventSessionLimit, t0)
	add(f, nil, "viewer-x", asset, db.EventRapidSessionCreation, t0)
	add(f, s.IDHash, "", asset, db.EventSegmentsWithoutKey, t0.Add(time.Minute))
	add(g, gs.IDHash, "", db.Asset{ID: gs.AssetID}, db.EventKeyRate, t0)

	all, next, err := r.ListPlaybackEvents(ctx, f.tenant.ID, db.EventQuery{Limit: 100})
	if err != nil || next != nil || len(all) != 5 {
		t.Fatalf("all = %d, next %v, %v", len(all), next, err)
	}
	if all[0].Kind != db.EventSegmentsWithoutKey {
		t.Fatalf("not newest first: %+v", all[0])
	}
	fp := db.SessionFingerprint(s.IDHash, f.tenant.ID)
	for _, e := range all {
		switch e.Kind {
		case db.EventSessionLimit, db.EventRapidSessionCreation:
			if e.SessionFingerprint != "" || e.ViewerID != "viewer-x" {
				t.Fatalf("viewer-level event = %+v", e)
			}
		default:
			if e.SessionFingerprint != fp || len(fp) != 8 || e.ViewerID != "v" {
				t.Fatalf("session event = %+v (fingerprint %s)", e, fp)
			}
		}
	}

	// Pages of 2 walk every event exactly once, across the timestamp tie.
	seen := map[string]bool{}
	var cur *db.EventCursor
	pages := 0
	for {
		page, n, err := r.ListPlaybackEvents(ctx, f.tenant.ID, db.EventQuery{Limit: 2, Cursor: cur})
		if err != nil {
			t.Fatal(err)
		}
		pages++
		for _, e := range page {
			if seen[e.ID.String()] {
				t.Fatalf("event %s on two pages", e.ID)
			}
			seen[e.ID.String()] = true
		}
		if n == nil {
			break
		}
		round, err := db.ParseEventCursor(n.Encode())
		if err != nil || round != *n {
			t.Fatalf("cursor round trip: %+v, %v", round, err)
		}
		cur = n
	}
	if len(seen) != 5 || pages != 3 {
		t.Fatalf("saw %d events in %d pages", len(seen), pages)
	}

	check := func(name string, q db.EventQuery, want int) {
		t.Helper()
		q.Limit = 100
		got, _, err := r.ListPlaybackEvents(ctx, f.tenant.ID, q)
		if err != nil || len(got) != want {
			t.Fatalf("%s: %d events, %v, want %d", name, len(got), err, want)
		}
	}
	check("kind", db.EventQuery{Kind: db.EventKeyRate}, 1)
	check("viewer", db.EventQuery{ViewerID: "viewer-x"}, 2)
	check("session viewer", db.EventQuery{ViewerID: "v"}, 3)
	check("asset", db.EventQuery{AssetID: s.AssetID}, 5)
	check("another tenant's asset", db.EventQuery{AssetID: gs.AssetID}, 0)
	check("from", db.EventQuery{From: t0.Add(time.Second)}, 1)
	check("to", db.EventQuery{To: t0.Add(time.Second)}, 4)

	if _, _, err := r.ListPlaybackEvents(ctx, f.tenant.ID, db.EventQuery{Limit: 0}); err == nil {
		t.Fatal("a zero page size was accepted")
	}
	if _, _, err := r.ListPlaybackEvents(ctx, f.tenant.ID, db.EventQuery{Limit: db.MaxEventPage + 1}); err == nil {
		t.Fatal("an oversize page was accepted")
	}
	if _, err := db.ParseEventCursor("not-a-cursor"); err == nil {
		t.Fatal("a bad cursor was accepted")
	}
	gotOther, _, err := r.ListPlaybackEvents(ctx, g.tenant.ID, db.EventQuery{Limit: 100})
	if err != nil || len(gotOther) != 1 {
		t.Fatalf("the other tenant sees %d events, %v", len(gotOther), err)
	}
}

func TestPlaybackSettingsStoreTheAnomalyFields(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f := newFixture(t, r, "acme")
	set := db.DefaultPlaybackSettings()
	set.AnomalySessionsPerViewer10m, set.AnomalySegmentsWithoutKey = 0, 77
	set.AutoRevoke = []string{db.EventKeyReplay, db.EventSegmentsWithoutKey}
	if _, err := r.PutPlaybackSettings(ctx, f.tenant.ID, set, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetPlaybackSettings(ctx, f.tenant.ID)
	if err != nil || got.AnomalySessionsPerViewer10m != 0 || got.AnomalySegmentsWithoutKey != 77 || len(got.AutoRevoke) != 2 {
		t.Fatalf("settings = %+v, %v", got, err)
	}
	// The table's checks are the backstop for the validation: session_limit is not allowed.
	if _, err := pool.Exec(ctx, "UPDATE playback_settings SET auto_revoke = ARRAY['session_limit']"); err == nil {
		t.Fatal("session_limit was accepted in auto_revoke")
	}
	if _, err := pool.Exec(ctx, "UPDATE playback_settings SET anomaly_segments_without_key = -1"); err == nil {
		t.Fatal("a negative threshold was accepted")
	}
}
