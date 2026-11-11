//go:build integration

package db_test

import (
	"context"
	"crypto/sha256"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

func listPartitions(t *testing.T, q func(string, ...any) []string) []string {
	t.Helper()
	return q(`SELECT c.relname::text FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
	          WHERE i.inhparent = 'playback_access_log'::regclass ORDER BY 1`)
}

func TestAccessLogPartitionsCreatedAheadAndIdempotent(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	query := func(sql string, args ...any) []string {
		rows, err := pool.Query(ctx, sql, args...)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			out = append(out, s)
		}
		return out
	}
	now := time.Now().UTC()
	// The migration made the current and the next month.
	have := listPartitions(t, query)
	cur := now.Format("200601")
	next := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC).Format("200601")
	if !reflect.DeepEqual(have, []string{"playback_access_log_p" + cur, "playback_access_log_p" + next}) {
		t.Fatalf("partitions after migration = %v", have)
	}
	// Ahead = 2 adds exactly one more; a second call adds none.
	if n, err := r.EnsureAccessLogPartitions(ctx, now, 2); err != nil || n != 1 {
		t.Fatalf("ensure = %d, %v; want 1 created", n, err)
	}
	if n, err := r.EnsureAccessLogPartitions(ctx, now, 2); err != nil || n != 0 {
		t.Fatalf("ensure again = %d, %v; want 0", n, err)
	}
	if got := len(listPartitions(t, query)); got != 3 {
		t.Fatalf("%d partitions, want 3", got)
	}
	// Another month, far ahead, to see a year boundary work.
	if n, err := r.EnsureAccessLogPartitions(ctx, time.Date(2031, 12, 15, 0, 0, 0, 0, time.UTC), 1); err != nil || n != 2 {
		t.Fatalf("ensure across a year = %d, %v", n, err)
	}
	// There is no default partition: a row outside every partition is refused, not stored.
	f := newFixture(t, r, "acme")
	err := r.InsertAccessLog(ctx, []db.AccessLogRow{{TenantID: f.tenant.ID, Event: db.AccessKey, At: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)}})
	if err == nil {
		t.Fatal("a row outside every partition was accepted")
	}
	// Concurrent callers (replicas) neither fail nor duplicate.
	errc := make(chan error, 6)
	for range 6 {
		go func() {
			_, err := r.EnsureAccessLogPartitions(ctx, time.Date(2033, 3, 1, 0, 0, 0, 0, time.UTC), 2)
			errc <- err
		}()
	}
	for range 6 {
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
	}
}

// The drop function is not called by the service yet (M6-4). It works: it drops only whole months
// before the cutoff, only partitions of this table, never one that is not in the past.
func TestAccessLogDropPartitionsBefore(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f := newFixture(t, r, "acme")
	jan := time.Date(2020, 1, 10, 0, 0, 0, 0, time.UTC)
	if _, err := r.EnsureAccessLogPartitions(ctx, jan, 2); err != nil { // 2020-01, 02, 03
		t.Fatal(err)
	}
	for _, at := range []time.Time{jan, jan.AddDate(0, 1, 0), jan.AddDate(0, 2, 0)} {
		if err := r.InsertAccessLog(ctx, []db.AccessLogRow{{TenantID: f.tenant.ID, Event: db.AccessHeartbeat, At: at}}); err != nil {
			t.Fatal(err)
		}
	}
	// An unrelated table that merely looks similar must survive.
	if _, err := pool.Exec(ctx, "CREATE TABLE playback_access_log_p202001_other (x int)"); err != nil {
		t.Fatal(err)
	}
	// Cutoff 2020-03-01: January and February end at or before it; March does not.
	dropped, err := r.DropAccessLogPartitionsBefore(ctx, time.Date(2020, 3, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dropped, []string{"playback_access_log_p202001", "playback_access_log_p202002"}) {
		t.Fatalf("dropped = %v", dropped)
	}
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM playback_access_log").Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows left = %d, %v; want the March row", n, err)
	}
	var other bool
	if err := pool.QueryRow(ctx, "SELECT to_regclass('playback_access_log_p202001_other') IS NOT NULL").Scan(&other); err != nil || !other {
		t.Fatalf("the unrelated table was dropped (%v, %v)", other, err)
	}
	// Running again drops nothing, and the current month is never dropped, nor a future cutoff accepted.
	if dropped, err := r.DropAccessLogPartitionsBefore(ctx, time.Date(2020, 3, 1, 0, 0, 0, 0, time.UTC)); err != nil || len(dropped) != 0 {
		t.Fatalf("second run dropped %v, %v", dropped, err)
	}
	if _, err := r.DropAccessLogPartitionsBefore(ctx, time.Now().UTC().AddDate(0, 0, 3)); err == nil {
		t.Fatal("a cutoff in the future was accepted")
	}
	cur := "playback_access_log_p" + time.Now().UTC().Format("200601")
	dropped, err = r.DropAccessLogPartitionsBefore(ctx, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dropped {
		if d == cur {
			t.Fatalf("the current month's partition was dropped")
		}
	}
}

func TestAccessLogInsertAndRead(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	a, b := newFixture(t, r, "a"), newFixture(t, r, "b")
	assetA := readyAsset(t, r, a)
	assetA2 := readyAsset(t, r, a)
	sid, err := id.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	other, err := id.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	hash, otherHash := db.SessionHash(sid), db.SessionHash(other)

	base := time.Now().UTC().Truncate(time.Second)
	var rows []db.AccessLogRow
	for i := range 7 { // 7 rows, two share a timestamp
		at := base.Add(time.Duration(i/2) * time.Second)
		rows = append(rows, db.AccessLogRow{
			TenantID: a.tenant.ID, AssetID: assetA.ID, SessionHash: hash, ViewerID: "viewer-1", AuthMethod: db.AuthMethodJWT,
			Event: db.AccessHeartbeat, At: at, IP: "203.0.113.9", UserAgent: "UA/1", RequestID: "rid",
		})
	}
	rows = append(rows,
		db.AccessLogRow{TenantID: a.tenant.ID, AssetID: assetA.ID, SessionHash: hash, ViewerID: "viewer-1", Event: db.AccessSegments, At: base.Add(10 * time.Second), SegmentsServed: 12},
		db.AccessLogRow{TenantID: a.tenant.ID, AssetID: assetA2.ID, SessionHash: otherHash, ViewerID: "viewer-2", Event: db.AccessKey, At: base},
		db.AccessLogRow{TenantID: a.tenant.ID, AssetID: assetA.ID, Event: db.AccessSessionDenied, At: base.Add(-time.Second)}, // no session, no viewer
		db.AccessLogRow{TenantID: b.tenant.ID, AssetID: assetA.ID, SessionHash: hash, Event: db.AccessKey, At: base},          // another tenant
	)
	if err := r.InsertAccessLog(ctx, rows); err != nil {
		t.Fatal(err)
	}

	// Newest first, in pages of 3, with no row repeated or skipped.
	q := db.AccessLogQuery{Limit: 3}
	var got []db.AccessLogEntry
	pages := 0
	for {
		page, next, err := r.ListAssetAccessLog(ctx, a.tenant.ID, assetA.ID, q)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, page...)
		pages++
		if next == nil {
			break
		}
		cur, err := db.ParseAccessLogCursor(next.Encode())
		if err != nil || cur != *next {
			t.Fatalf("cursor round trip: %v %v", cur, err)
		}
		q.Cursor = &cur
	}
	if len(got) != 9 || pages != 3 { // 7 heartbeats + segments + denied
		t.Fatalf("got %d rows in %d pages, want 9 in 3", len(got), pages)
	}
	for i := 1; i < len(got); i++ {
		if got[i].At.After(got[i-1].At) || (got[i].At.Equal(got[i-1].At) && got[i].ID >= got[i-1].ID) {
			t.Fatalf("rows %d and %d are out of order", i-1, i)
		}
	}
	if got[0].Event != db.AccessSegments || got[0].SegmentsServed != 12 {
		t.Fatalf("newest row = %+v", got[0])
	}
	last := got[len(got)-1]
	if last.Event != db.AccessSessionDenied || last.SessionFingerprint != "" || last.ViewerID != "" || last.IP != "" {
		t.Fatalf("denied row = %+v", last)
	}
	// The fingerprint groups a session's rows and is derived from the hash and the tenant.
	tu := a.tenant.ID.UUID()
	want := sha256.Sum256(append(append([]byte{}, hash...), tu[:]...))
	fp := got[0].SessionFingerprint
	if len(fp) != 8 || !strings.HasPrefix(strings.ToLower(hexOf(want[:])), fp) {
		t.Fatalf("fingerprint %q, want prefix of %x", fp, want[:4])
	}
	if got[1].IP != "203.0.113.9" || got[1].UserAgent != "UA/1" || got[1].RequestID != "rid" {
		t.Fatalf("row = %+v", got[1])
	}

	// Filters: event, range, session.
	page, _, err := r.ListAssetAccessLog(ctx, a.tenant.ID, assetA.ID, db.AccessLogQuery{Limit: 50, Event: db.AccessSegments})
	if err != nil || len(page) != 1 {
		t.Fatalf("event filter: %d rows, %v", len(page), err)
	}
	page, _, err = r.ListAssetAccessLog(ctx, a.tenant.ID, assetA.ID, db.AccessLogQuery{Limit: 50, From: base.Add(time.Second), To: base.Add(3 * time.Second)})
	if err != nil || len(page) != 4 { // heartbeats at +1s (x2) and +2s (x2); +3s is excluded
		t.Fatalf("range filter: %d rows, %v", len(page), err)
	}
	page, _, err = r.ListSessionAccessLog(ctx, a.tenant.ID, otherHash, db.AccessLogQuery{Limit: 50})
	if err != nil || len(page) != 1 || page[0].Event != db.AccessKey {
		t.Fatalf("session read: %+v, %v", page, err)
	}
	// Tenant isolation: tenant b sees only its own row, whatever hash or asset it asks for.
	page, _, err = r.ListSessionAccessLog(ctx, b.tenant.ID, hash, db.AccessLogQuery{Limit: 50})
	if err != nil || len(page) != 1 {
		t.Fatalf("tenant b: %d rows, %v", len(page), err)
	}
	page, _, err = r.ListAssetAccessLog(ctx, b.tenant.ID, assetA2.ID, db.AccessLogQuery{Limit: 50})
	if err != nil || len(page) != 0 {
		t.Fatalf("tenant b reading a's asset: %d rows, %v", len(page), err)
	}

	// Bad input.
	if _, _, err := r.ListAssetAccessLog(ctx, a.tenant.ID, assetA.ID, db.AccessLogQuery{Limit: 0}); err == nil {
		t.Fatal("limit 0 accepted")
	}
	if _, _, err := r.ListAssetAccessLog(ctx, a.tenant.ID, assetA.ID, db.AccessLogQuery{Limit: 501}); err == nil {
		t.Fatal("limit 501 accepted")
	}
	if _, _, err := r.ListAssetAccessLog(ctx, a.tenant.ID, assetA.ID, db.AccessLogQuery{Limit: 5, Event: "watched_segment_7"}); err == nil {
		t.Fatal("unknown event accepted")
	}
	for _, c := range []string{"", "!!!", "MS4x", "MS4x.2"} {
		if _, err := db.ParseAccessLogCursor(c); err == nil {
			t.Fatalf("cursor %q accepted", c)
		}
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}

func TestAccessLogIgnoresRowsOfUnknownTenants(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f := newFixture(t, r, "a")
	now := time.Now().UTC()
	rows := []db.AccessLogRow{
		{TenantID: id.New[id.TenantKind](), Event: db.AccessSessionDenied, At: now},
		{TenantID: f.tenant.ID, Event: db.AccessSessionDenied, At: now},
	}
	if err := r.InsertAccessLog(ctx, rows); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM playback_access_log").Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d rows stored, want 1 (%v)", n, err)
	}
}

func TestAccessLogRejectsBadRows(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "a")
	now := time.Now().UTC()
	for name, row := range map[string]db.AccessLogRow{
		"unknown event":        {TenantID: f.tenant.ID, Event: "segment_17", At: now},
		"no tenant":            {Event: db.AccessKey, At: now},
		"long user agent":      {TenantID: f.tenant.ID, Event: db.AccessKey, At: now, UserAgent: strings.Repeat("x", 257)},
		"short session hash":   {TenantID: f.tenant.ID, Event: db.AccessKey, At: now, SessionHash: []byte{1}},
		"segments no count":    {TenantID: f.tenant.ID, Event: db.AccessSegments, At: now},
		"count on a heartbeat": {TenantID: f.tenant.ID, Event: db.AccessHeartbeat, At: now, SegmentsServed: 3},
	} {
		if err := r.InsertAccessLog(ctx, []db.AccessLogRow{row}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPrivacySettingsDefaultsToMostPrivate(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	a, b := newFixture(t, r, "a"), newFixture(t, r, "b")
	got, err := r.GetPrivacySettings(ctx, a.tenant.ID)
	if err != nil || got.StoreIP || got.StoreUserAgent || !got.UpdatedAt.IsZero() {
		t.Fatalf("defaults = %+v, %v", got, err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := r.PutPrivacySettings(ctx, a.tenant.ID, db.PrivacySettings{StoreIP: true}, at); err != nil {
		t.Fatal(err)
	}
	got, err = r.GetPrivacySettings(ctx, a.tenant.ID)
	if err != nil || !got.StoreIP || got.StoreUserAgent || !got.UpdatedAt.Equal(at) {
		t.Fatalf("stored = %+v, %v", got, err)
	}
	if got, err := r.GetPrivacySettings(ctx, b.tenant.ID); err != nil || got.StoreIP {
		t.Fatalf("other tenant = %+v, %v", got, err)
	}
}
