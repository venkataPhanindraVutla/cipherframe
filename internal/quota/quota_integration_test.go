//go:build integration

package quota_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/quota"
)

func TestMain(m *testing.M) { os.Exit(dbtest.Run(m)) }

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

type env struct {
	t     *testing.T
	pool  *pgxpool.Pool
	repos *db.Repos
	clk   *clock
	svc   *quota.Service
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pool := dbtest.NewMigrated(t)
	clk := &clock{t: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
	return &env{t: t, pool: pool, repos: db.New(pool), clk: clk, svc: quota.NewService(pool, clk.Now)}
}

type tenant struct {
	id      id.TenantID
	clients []id.ClientID
}

func (e *env) newTenant(name string, clients int) tenant {
	e.t.Helper()
	ctx := context.Background()
	tn, err := e.repos.CreateTenant(ctx, name)
	if err != nil {
		e.t.Fatal(err)
	}
	out := tenant{id: tn.ID}
	for range clients {
		c, err := e.repos.CreateClient(ctx, tn.ID, "client")
		if err != nil {
			e.t.Fatal(err)
		}
		out.clients = append(out.clients, c.ID)
	}
	return out
}

func (e *env) newAsset(tn id.TenantID, client id.ClientID, size int64, state db.AssetState) db.Asset {
	e.t.Helper()
	ctx := context.Background()
	a, err := e.repos.CreateUploadAsset(ctx, db.NewUploadAsset{
		ID: id.New[id.AssetKind](), TenantID: tn, ClientID: client, SizeBytes: size, Method: db.UploadTus,
		SourceKey: "test-fixture-source-" + id.New[id.AssetKind]().String(), ExpiresAt: e.clk.Now().Add(time.Hour),
	})
	if err != nil {
		e.t.Fatal(err)
	}
	path := []db.AssetState{db.AssetUploading, db.AssetCommitted, db.AssetProcessing, db.AssetReady}
	for _, next := range path {
		if a.State == state {
			break
		}
		if a, err = e.repos.TransitionAsset(ctx, tn, a.ID, db.Transition{From: a.State, To: next}); err != nil {
			e.t.Fatal(err)
		}
	}
	return a
}

func (e *env) artifact(a db.Asset, bucket string, size int64) {
	e.t.Helper()
	err := e.repos.RecordArtifact(context.Background(), db.Artifact{
		AssetID: a.ID, Kind: db.ArtifactSegment, Rendition: "720p", Bucket: bucket,
		ObjectKey: "test-fixture-" + id.New[id.AssetKind]().String(), SizeBytes: size, SHA256: make([]byte, 32),
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func ptr[T any](v T) *T { return &v }

func (e *env) setTenantQuotas(tn id.TenantID, q db.Quotas) {
	e.t.Helper()
	if _, err := e.svc.Put(context.Background(), tn, id.ClientID{}, auth.Actor{}, q); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) setClientQuotas(tn id.TenantID, c id.ClientID, q db.Quotas) {
	e.t.Helper()
	if _, err := e.svc.Put(context.Background(), tn, c, auth.Actor{}, q); err != nil {
		e.t.Fatal(err)
	}
}

func wantQuota(t *testing.T, err error, limit string) {
	t.Helper()
	var ee *errs.Error
	if !errors.As(err, &ee) || ee.Code != errs.QuotaExceeded || ee.Limit != limit {
		t.Fatalf("err = %v, want quota_exceeded for %s", err, limit)
	}
}

// ---- transcode minutes ----------------------------------------------------------------------

func TestTranscodeMinutesJustUnderAtAndOver(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tn := e.newTenant("acme", 1)
	e.setTenantQuotas(tn.id, db.Quotas{TranscodeMinutesPerMonth: ptr(10)})
	cl := tn.clients[0]
	a1, a2, a3, a4 := e.newAsset(tn.id, cl, 1, db.AssetProcessing), e.newAsset(tn.id, cl, 1, db.AssetProcessing),
		e.newAsset(tn.id, cl, 1, db.AssetProcessing), e.newAsset(tn.id, cl, 1, db.AssetProcessing)

	if err := e.svc.ChargeTranscode(ctx, tn.id, a1.ID, 6*time.Minute-time.Millisecond); err != nil { // just under
		t.Fatal(err)
	}
	if err := e.svc.ChargeTranscode(ctx, tn.id, a2.ID, 4*time.Minute+time.Millisecond); err != nil { // exactly at the limit
		t.Fatal(err)
	}
	// One millisecond over is refused, and the refused charge is not recorded.
	wantQuota(t, e.svc.ChargeTranscode(ctx, tn.id, a3.ID, time.Millisecond), quota.LimitTranscodeMinutes)
	u, err := e.svc.GetUsage(ctx, tn.id, id.ClientID{})
	if err != nil || u.TranscodeMillis.Used != 10*60_000 || *u.TranscodeMillis.Limit != 10*60_000 {
		t.Fatalf("usage = %+v, %v", u.TranscodeMillis, err)
	}
	// A retry of an asset that was charged is free, even with the month used up.
	if err := e.svc.ChargeTranscode(ctx, tn.id, a1.ID, 6*time.Minute); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if u, _ = e.svc.GetUsage(ctx, tn.id, id.ClientID{}); u.TranscodeMillis.Used != 10*60_000 {
		t.Fatalf("a retry changed the usage: %d", u.TranscodeMillis.Used)
	}
	// The next calendar month (UTC) starts from zero.
	e.clk.Set(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC))
	if err := e.svc.ChargeTranscode(ctx, tn.id, a4.ID, 9*time.Minute); err != nil {
		t.Fatalf("new month: %v", err)
	}
	if u, _ = e.svc.GetUsage(ctx, tn.id, id.ClientID{}); u.TranscodeMillis.Used != 9*60_000 {
		t.Fatalf("december usage = %d", u.TranscodeMillis.Used)
	}
	// Raising the limit lets the refused asset through (a re-run would charge it then).
	e.setTenantQuotas(tn.id, db.Quotas{TranscodeMinutesPerMonth: ptr(20)})
	if err := e.svc.ChargeTranscode(ctx, tn.id, a3.ID, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
}

func TestTranscodeUnlimitedByDefaultAndClientOverride(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tn := e.newTenant("acme", 2)
	big := e.newAsset(tn.id, tn.clients[0], 1, db.AssetProcessing)
	// No quota is set anywhere: a hundred hours is fine.
	if err := e.svc.ChargeTranscode(ctx, tn.id, big.ID, 100*time.Hour); err != nil {
		t.Fatal(err)
	}
	u, _ := e.svc.GetUsage(ctx, tn.id, id.ClientID{})
	if u.TranscodeMillis.Limit != nil || u.Storage.Limit != nil || u.Sessions.Limit != nil || u.RequestsPerMinute != nil {
		t.Fatalf("defaults must be unlimited: %+v", u)
	}

	// The tenant allows 1000 minutes more this month in total, the second client only 5.
	e.setTenantQuotas(tn.id, db.Quotas{TranscodeMinutesPerMonth: ptr(100*60 + 1000)})
	e.setClientQuotas(tn.id, tn.clients[1], db.Quotas{TranscodeMinutesPerMonth: ptr(5)})
	other := e.newAsset(tn.id, tn.clients[1], 1, db.AssetProcessing)
	wantQuota(t, e.svc.ChargeTranscode(ctx, tn.id, other.ID, 6*time.Minute), quota.LimitTranscodeMinutes)
	if err := e.svc.ChargeTranscode(ctx, tn.id, other.ID, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	// The first client has no override: only the tenant's limit applies to it.
	again := e.newAsset(tn.id, tn.clients[0], 1, db.AssetProcessing)
	if err := e.svc.ChargeTranscode(ctx, tn.id, again.ID, 500*time.Minute); err != nil {
		t.Fatal(err)
	}
	// The client's own usage is reported against its own, lower, limit.
	cu, err := e.svc.GetUsage(ctx, tn.id, tn.clients[1])
	if err != nil || cu.TranscodeMillis.Used != 5*60_000 || *cu.TranscodeMillis.Limit != 5*60_000 {
		t.Fatalf("client usage = %+v, %v", cu.TranscodeMillis, err)
	}
}

// ---- storage --------------------------------------------------------------------------------

func TestUsageCountsTheRegistriesAndNothingElse(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tn := e.newTenant("acme", 2)
	other := e.newTenant("other", 1)

	ready := e.newAsset(tn.id, tn.clients[0], 100, db.AssetReady)
	e.artifact(ready, "delivery", 30)
	e.artifact(ready, "delivery", 20)
	uploading := e.newAsset(tn.id, tn.clients[1], 50, db.AssetUploading)
	_ = uploading

	aborted := e.newAsset(tn.id, tn.clients[0], 70, db.AssetCreated)
	if _, err := e.repos.TransitionAsset(ctx, tn.id, aborted.ID, db.Transition{From: db.AssetCreated, To: db.AssetFailed, FailureCode: "upload_aborted"}); err != nil {
		t.Fatal(err)
	}
	failed := e.newAsset(tn.id, tn.clients[0], 11, db.AssetProcessing) // failed processing keeps its source
	if _, err := e.repos.TransitionAsset(ctx, tn.id, failed.ID, db.Transition{From: db.AssetProcessing, To: db.AssetFailed, FailureCode: "invalid_media"}); err != nil {
		t.Fatal(err)
	}

	gone := e.newAsset(tn.id, tn.clients[0], 80, db.AssetReady)
	e.artifact(gone, "delivery", 5)
	if _, err := e.repos.RequestAssetDeletion(ctx, tn.id, gone.ID, db.DeletionRequested, e.clk.Now()); err != nil {
		t.Fatal(err)
	}
	// While it is being deleted it still holds its bytes...
	if u, _ := e.svc.GetUsage(ctx, tn.id, id.ClientID{}); u.Storage.Used != 100+50+50+11+80+5 {
		t.Fatalf("storage while deleting = %d", u.Storage.Used)
	}
	// ...and stops counting when the purge completes.
	if _, err := e.repos.DeleteAssetArtifacts(ctx, gone.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.repos.CompleteAssetDeletion(ctx, tn.id, gone.ID, e.clk.Now()); err != nil {
		t.Fatal(err)
	}
	e.newAsset(other.id, other.clients[0], 9999, db.AssetReady) // another tenant's

	u, err := e.svc.GetUsage(ctx, tn.id, id.ClientID{})
	if err != nil || u.Storage.Used != 100+50+50+11 {
		t.Fatalf("storage = %d, %v; want %d", u.Storage.Used, err, 100+50+50+11)
	}
	c0, _ := e.svc.GetUsage(ctx, tn.id, tn.clients[0])
	c1, _ := e.svc.GetUsage(ctx, tn.id, tn.clients[1])
	if c0.Storage.Used != 100+50+11 || c1.Storage.Used != 50 {
		t.Fatalf("per-client storage = %d and %d", c0.Storage.Used, c1.Storage.Used)
	}
	ou, _ := e.svc.GetUsage(ctx, other.id, id.ClientID{})
	if ou.Storage.Used != 9999 {
		t.Fatalf("other tenant's storage = %d", ou.Storage.Used)
	}
	// One tenant cannot read a client of another, whatever the ID looks like.
	if _, err := e.svc.GetUsage(ctx, tn.id, other.clients[0]); err == nil || !isCode(err, errs.NotFound) {
		t.Fatalf("another tenant's client: %v", err)
	}
	if _, err := e.svc.Put(ctx, tn.id, other.clients[0], auth.Actor{}, db.Quotas{}); err == nil || !isCode(err, errs.NotFound) {
		t.Fatalf("setting another tenant's client: %v", err)
	}
}

func isCode(err error, c errs.Code) bool {
	var ee *errs.Error
	return errors.As(err, &ee) && ee.Code == c
}

func TestStorageCheckJustUnderAtAndOverWithOverride(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tn := e.newTenant("acme", 2)
	e.setTenantQuotas(tn.id, db.Quotas{StorageBytes: ptr(int64(1000))})
	e.setClientQuotas(tn.id, tn.clients[1], db.Quotas{StorageBytes: ptr(int64(300))})
	e.newAsset(tn.id, tn.clients[0], 600, db.AssetUploading)

	check := func(client id.ClientID, add int64) error {
		return db.Tx(ctx, e.pool, func(r *db.Repos) error {
			return quota.CheckStorage(ctx, r, tn.id, client, add, id.AssetID{})
		})
	}
	if err := check(tn.clients[0], 399); err != nil { // just under
		t.Fatal(err)
	}
	if err := check(tn.clients[0], 400); err != nil { // at
		t.Fatal(err)
	}
	wantQuota(t, check(tn.clients[0], 401), quota.LimitStorageBytes) // over
	// The override applies to the second client alone, below the tenant's room.
	if err := check(tn.clients[1], 300); err != nil {
		t.Fatal(err)
	}
	wantQuota(t, check(tn.clients[1], 301), quota.LimitStorageBytes)
	// Excluding the asset being committed leaves its bytes to the `add`.
	a := e.newAsset(tn.id, tn.clients[0], 400, db.AssetUploading)
	wantQuota(t, check(tn.clients[0], 1), quota.LimitStorageBytes) // full now
	err := db.Tx(ctx, e.pool, func(r *db.Repos) error {
		return quota.CheckStorage(ctx, r, tn.id, tn.clients[0], 400, a.ID)
	})
	if err != nil {
		t.Fatalf("commit-time check of an asset already counted: %v", err)
	}
	// Nothing set means nothing refused.
	free := e.newTenant("free", 1)
	if err := db.Tx(ctx, e.pool, func(r *db.Repos) error {
		return quota.CheckStorage(ctx, r, free.id, free.clients[0], 1<<60, id.AssetID{})
	}); err != nil {
		t.Fatalf("unlimited: %v", err)
	}
}

// Racing creations cannot pass the check on the same remaining room: each holds the tenant's lock
// from the check until its asset row is committed.
func TestStorageCheckRace(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tn := e.newTenant("acme", 1)
	e.setTenantQuotas(tn.id, db.Quotas{StorageBytes: ptr(int64(1000))})

	var ok, refused atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := db.Tx(ctx, e.pool, func(r *db.Repos) error {
				if err := quota.CheckStorage(ctx, r, tn.id, tn.clients[0], 300, id.AssetID{}); err != nil {
					return err
				}
				_, err := r.CreateUploadAsset(ctx, db.NewUploadAsset{
					ID: id.New[id.AssetKind](), TenantID: tn.id, ClientID: tn.clients[0], SizeBytes: 300, Method: db.UploadTus,
					SourceKey: "test-fixture-source-" + id.New[id.AssetKind]().String(), ExpiresAt: e.clk.Now().Add(time.Hour),
				})
				return err
			})
			switch {
			case err == nil:
				ok.Add(1)
			case isCode(err, errs.QuotaExceeded):
				refused.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 3 || refused.Load() != 9 {
		t.Fatalf("%d creations passed and %d were refused, want 3 and 9", ok.Load(), refused.Load())
	}
	if u, _ := e.svc.GetUsage(ctx, tn.id, id.ClientID{}); u.Storage.Used != 900 {
		t.Fatalf("usage = %d", u.Storage.Used)
	}
}

// ---- the limits themselves ------------------------------------------------------------------

func TestPutRejectsAClientOverrideAboveTheTenant(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tn := e.newTenant("acme", 1)
	e.setTenantQuotas(tn.id, db.Quotas{ConcurrentSessions: ptr(5)})
	_, err := e.svc.Put(ctx, tn.id, tn.clients[0], auth.Actor{}, db.Quotas{ConcurrentSessions: ptr(6), RequestsPerMinute: ptr(100)})
	if !isCode(err, errs.InvalidRequest) {
		t.Fatalf("err = %v", err)
	}
	q, err := e.svc.Get(ctx, tn.id, tn.clients[0])
	if err != nil || q.ConcurrentSessions != nil || !q.UpdatedAt.IsZero() {
		t.Fatalf("nothing should be stored: %+v, %v", q, err)
	}
	// Equal is fine, and a client limit where the tenant has none is fine too.
	if _, err := e.svc.Put(ctx, tn.id, tn.clients[0], auth.Actor{}, db.Quotas{ConcurrentSessions: ptr(5), RequestsPerMinute: ptr(100)}); err != nil {
		t.Fatal(err)
	}
	// Replacing removes what is not sent.
	got, err := e.svc.Put(ctx, tn.id, tn.clients[0], auth.Actor{}, db.Quotas{StorageBytes: ptr(int64(7))})
	if err != nil || got.ConcurrentSessions != nil || got.RequestsPerMinute != nil || *got.StorageBytes != 7 {
		t.Fatalf("replace: %+v, %v", got, err)
	}
}

// ---- request rate ---------------------------------------------------------------------------

func TestLimiterPerKeyWithClientOverrideAndCache(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tn := e.newTenant("acme", 2)
	lim := quota.NewLimiter(e.repos, nil, e.clk.Now)
	keyA := auth.Principal{TenantID: tn.id, ClientID: tn.clients[0], KeyID: id.New[id.APIKeyKind]()}
	keyA2 := auth.Principal{TenantID: tn.id, ClientID: tn.clients[0], KeyID: id.New[id.APIKeyKind]()}
	keyB := auth.Principal{TenantID: tn.id, ClientID: tn.clients[1], KeyID: id.New[id.APIKeyKind]()}

	// Unlimited by default.
	for range 500 {
		if ok, _ := lim.Allow(ctx, keyA); !ok {
			t.Fatal("refused with no limit")
		}
	}

	e.setTenantQuotas(tn.id, db.Quotas{RequestsPerMinute: ptr(60)})
	e.setClientQuotas(tn.id, tn.clients[1], db.Quotas{RequestsPerMinute: ptr(2)})
	e.clk.Set(e.clk.Now().Add(time.Minute)) // past the cache of the limits
	for i := range 60 {
		if ok, _ := lim.Allow(ctx, keyA); !ok {
			t.Fatalf("request %d refused inside the burst", i+1)
		}
	}
	ok, wait := lim.Allow(ctx, keyA)
	if ok || wait != time.Second {
		t.Fatalf("61st: ok=%v wait=%v", ok, wait)
	}
	// Another key of the same client has a bucket of its own.
	if ok, _ := lim.Allow(ctx, keyA2); !ok {
		t.Fatal("a second key shares the first key's bucket")
	}
	// The lower client override governs its key.
	lim.Allow(ctx, keyB)
	lim.Allow(ctx, keyB)
	if ok, wait := lim.Allow(ctx, keyB); ok || wait != 30*time.Second {
		t.Fatalf("override: ok=%v wait=%v", ok, wait)
	}
	// A changed limit is picked up after the cache expires, not before.
	e.setTenantQuotas(tn.id, db.Quotas{RequestsPerMinute: ptr(6000)})
	if ok, _ := lim.Allow(ctx, keyA); ok {
		t.Fatal("the new limit applied before the cache expired")
	}
	e.clk.Set(e.clk.Now().Add(20 * time.Second))
	if ok, _ := lim.Allow(ctx, keyA); !ok {
		t.Fatal("the new limit was not picked up")
	}
}
