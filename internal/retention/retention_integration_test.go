//go:build integration

package retention_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/retention"
)

func TestMain(m *testing.M) { os.Exit(dbtest.Run(m)) }

type rig struct {
	t      *testing.T
	pool   *pgxpool.Pool
	repos  *db.Repos
	tenant db.Tenant
	client db.Client
}

func newRig(t *testing.T) *rig {
	t.Helper()
	pool := dbtest.NewMigrated(t)
	r := &rig{t: t, pool: pool, repos: db.New(pool)}
	var err error
	if r.tenant, err = r.repos.CreateTenant(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	if r.client, err = r.repos.CreateClient(context.Background(), r.tenant.ID, "acme-client"); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *rig) count(query string, args ...any) int {
	r.t.Helper()
	var n int
	if err := r.pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func (r *rig) accessRow(asset id.AssetID, at time.Time, viewer string) {
	r.t.Helper()
	err := r.repos.InsertAccessLog(context.Background(), []db.AccessLogRow{{
		TenantID: r.tenant.ID, AssetID: asset, ViewerID: viewer, Event: db.AccessSessionCreated, At: at.UTC().Truncate(time.Microsecond),
	}})
	if err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) event(asset id.AssetID, at time.Time) {
	r.t.Helper()
	_, err := r.pool.Exec(context.Background(),
		`INSERT INTO playback_events (tenant_id, asset_id, kind, at, viewer_id) VALUES ($1, $2, 'session_limit', $3, 'viewer-1')`,
		r.tenant.ID.UUID(), asset.UUID(), at.UTC())
	if err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) viewers(asset id.AssetID) []string {
	r.t.Helper()
	rows, err := r.pool.Query(context.Background(), `SELECT viewer_id FROM playback_access_log WHERE asset_id = $1 ORDER BY viewer_id`, asset.UUID())
	if err != nil {
		r.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			r.t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

// The access trail and the events lose exactly the rows older than the window: whole monthly
// partitions are dropped, older rows of the partition the window ends in are deleted, and
// everything newer stays.
func TestAccessTrailAndEventRetention(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const days = 90
	cutoff := now.AddDate(0, 0, -days)
	if _, err := r.repos.EnsureAccessLogPartitions(ctx, now.AddDate(0, -8, 0), 8); err != nil {
		t.Fatal(err)
	}
	asset := id.New[id.AssetKind]()
	veryOld, justBefore, justAfter := now.AddDate(0, 0, -200), cutoff.Add(-time.Hour), cutoff.Add(time.Hour)
	r.accessRow(asset, veryOld, "a-very-old")
	r.accessRow(asset, justBefore, "b-just-before")
	r.accessRow(asset, justAfter, "c-just-after")
	r.accessRow(asset, now, "d-now")
	r.event(asset, veryOld)
	r.event(asset, justBefore)
	r.event(asset, justAfter)
	r.event(asset, now)

	s := &retention.Sweeper{Store: r.repos, Requester: nopRequester{}, AccessLogDays: days, Log: slog.New(slog.DiscardHandler)}
	res, err := s.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.viewers(asset); !slices.Equal(got, []string{"c-just-after", "d-now"}) {
		t.Errorf("access trail after the sweep = %v", got)
	}
	if n := r.count(`SELECT count(*) FROM playback_events WHERE asset_id = $1`, asset.UUID()); n != 2 {
		t.Errorf("%d events left, want 2", n)
	}
	if res.EventRows != 2 {
		t.Errorf("event rows deleted = %d, want 2", res.EventRows)
	}
	// The month of the very old row is gone as a whole partition, not row by row.
	old := fmt.Sprintf("playback_access_log_p%s", veryOld.Format("200601"))
	if !slices.Contains(res.DroppedPartitions, old) {
		t.Errorf("partition %s was not dropped whole: dropped %v", old, res.DroppedPartitions)
	}
	if n := r.count(`SELECT count(*) FROM pg_class WHERE relname = $1`, old); n != 0 {
		t.Errorf("partition %s still exists", old)
	}
	// The current partition survives, so the trail keeps working, and a second sweep changes nothing.
	r.accessRow(asset, now, "e-after")
	res, err = s.Sweep(ctx)
	if err != nil || res.AccessLogRows != 0 || res.EventRows != 0 || len(res.DroppedPartitions) != 0 {
		t.Errorf("second sweep = %+v, %v", res, err)
	}
	if got := r.viewers(asset); len(got) != 3 {
		t.Errorf("access trail = %v", got)
	}
}

type nopRequester struct{}

func (nopRequester) Request(context.Context, id.TenantID, id.AssetID, string, *auth.Actor) (db.Asset, error) {
	return db.Asset{}, nil
}

func (r *rig) newAsset(expires *time.Time) db.Asset {
	r.t.Helper()
	aid := id.New[id.AssetKind]()
	a, err := r.repos.CreateUploadAsset(context.Background(), db.NewUploadAsset{
		ID: aid, TenantID: r.tenant.ID, ClientID: r.client.ID, SizeBytes: 10, Method: db.UploadTus,
		SourceKey: "t/x/a/y/source/" + aid.String(), ExpiresAt: time.Now().Add(time.Hour), AssetExpiresAt: expires,
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return a
}

// The work list holds the assets whose time-to-live ran out, earliest first, and nothing that is
// kept, not yet due or already being deleted.
func TestListExpiredAssets(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	now := time.Now().UTC()
	hour := func(h int) *time.Time { v := now.Add(time.Duration(h) * time.Hour); return &v }
	later := r.newAsset(hour(-1))
	earlier := r.newAsset(hour(-5))
	r.newAsset(hour(3)) // not yet
	r.newAsset(nil)     // kept until deleted
	deleting := r.newAsset(hour(-2))
	if _, err := r.repos.RequestAssetDeletion(ctx, deleting.TenantID, deleting.ID, db.DeletionRetention, now); err != nil {
		t.Fatal(err)
	}
	got, err := r.repos.ListExpiredAssets(ctx, now, 10)
	if err != nil || len(got) != 2 || got[0].ID != earlier.ID || got[1].ID != later.ID {
		t.Fatalf("expired = %v, %v", got, err)
	}
	if got[0].ExpiresAt == nil || got[0].ExpiresAt.After(now) {
		t.Errorf("expiry = %v", got[0].ExpiresAt)
	}
	// Clearing the expiry takes the asset off the list.
	if a, err := r.repos.SetAssetExpiry(ctx, later.TenantID, later.ID, nil, now); err != nil || a.ExpiresAt != nil {
		t.Fatalf("clear: %+v, %v", a, err)
	}
	if got, _ = r.repos.ListExpiredAssets(ctx, now, 10); len(got) != 1 {
		t.Fatalf("expired after clearing = %d, want 1", len(got))
	}
	// A deleting asset takes no new expiry.
	if _, err := r.repos.SetAssetExpiry(ctx, deleting.TenantID, deleting.ID, hour(5), now); err == nil {
		t.Fatal("an expiry was set on a deleting asset")
	}
}

// Partition creation and retention work from a role that owns nothing: the access-log functions run
// with their owner's rights.
func TestPartitionMaintenanceFromALimitedRole(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	var dbName string
	if err := r.pool.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatal(err)
	}
	const role, pw = "cf_limited", "test-fixture-limited-role"
	for _, q := range []string{
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s'`, role, pw),
		fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s`, dbName, role),
		fmt.Sprintf(`GRANT USAGE ON SCHEMA public TO %s`, role),
		fmt.Sprintf(`GRANT SELECT, INSERT, DELETE ON playback_access_log, playback_events TO %s`, role),
		fmt.Sprintf(`GRANT USAGE ON SEQUENCE playback_access_log_id_seq TO %s`, role),
	} {
		if _, err := r.pool.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	cfg := r.pool.Config()
	cfg.ConnConfig.User, cfg.ConnConfig.Password = role, pw
	limited, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(limited.Close)
	lr := db.New(limited)

	now := time.Now().UTC()
	old := now.AddDate(0, -6, 0)
	// Not every role that can connect may run the functions (they run as their owner)...
	if _, err := lr.EnsureAccessLogPartitions(ctx, old, 1); err == nil {
		t.Fatalf("%s ran the partition function without being granted EXECUTE", role)
	}
	if _, err := limited.Exec(ctx, `SELECT playback_access_log_drop_partitions_before(current_date)`); err == nil {
		t.Fatalf("%s ran the drop function without being granted EXECUTE", role)
	}
	// ... only a role the operator granted them to, as a deployment with a separate service role does.
	for _, fn := range []string{"playback_access_log_ensure_partition(date)", "playback_access_log_drop_partitions_before(date)"} {
		if _, err := r.pool.Exec(ctx, fmt.Sprintf(`GRANT EXECUTE ON FUNCTION %s TO %s`, fn, role)); err != nil {
			t.Fatal(err)
		}
	}
	// A new partition is created by a role that could not do it itself...
	created, err := lr.EnsureAccessLogPartitions(ctx, old, 1)
	if err != nil || created != 2 {
		t.Fatalf("EnsureAccessLogPartitions as %s: %d, %v", role, created, err)
	}
	name := fmt.Sprintf("playback_access_log_p%s", old.Format("200601"))
	if _, err := limited.Exec(ctx, `DROP TABLE `+name); err == nil {
		t.Fatalf("the test role can drop %s itself, so it proves nothing", name)
	}
	// ... and the same role runs the retention sweep, which drops it.
	s := &retention.Sweeper{Store: trailOnly{lr}, Requester: nopRequester{}, AccessLogDays: 30, Log: slog.New(slog.DiscardHandler)}
	res, err := s.Sweep(ctx)
	if err != nil {
		t.Fatalf("sweep as %s: %v", role, err)
	}
	if !slices.Contains(res.DroppedPartitions, name) {
		t.Errorf("partition %s was not dropped: %v", name, res.DroppedPartitions)
	}
}

// trailOnly is a store for a role that only maintains the access trail: it has no asset work list.
type trailOnly struct{ *db.Repos }

func (trailOnly) ListExpiredAssets(context.Context, time.Time, int) ([]db.Asset, error) {
	return nil, nil
}
