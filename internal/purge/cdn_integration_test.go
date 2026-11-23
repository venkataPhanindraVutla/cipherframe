//go:build integration

package purge_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/purge"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// The CDN purge (ADR 0062, M10-1): queued with the tombstone, retried, outcome in the audit log.

type fakeCDNPurger struct {
	mu       sync.Mutex
	prefixes []string
	err      error
}

func (f *fakeCDNPurger) Purge(_ context.Context, prefix string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prefixes = append(f.prefixes, prefix)
	return f.err
}

// cdnPurger is a purger whose deletions queue asset.cdn_purge, like the worker's with a CDN.
func (r *rig) cdnPurger() *purge.Purger {
	r.t.Helper()
	reg := jobs.NewRegistry()
	if err := purge.DeclareCDN(reg); err != nil {
		r.t.Fatal(err)
	}
	q, err := jobs.NewQueue(r.pool, reg, jobs.Config{})
	if err != nil {
		r.t.Fatal(err)
	}
	p, err := purge.New(purge.Deps{
		Pool: r.pool, Source: r.buckets.Source, Delivery: r.buckets.Delivery, Keys: r.mgr, Signer: r.signer,
		Log: slog.New(slog.DiscardHandler), InFlightWait: time.Hour, CDNQueue: q,
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return p
}

func (r *rig) cdnJobs(a db.Asset) int {
	return r.count(`SELECT count(*) FROM river_job WHERE kind = $1 AND args->>'asset_id' = $2`, purge.CDNJobKind, a.ID.String())
}

func (r *rig) audits(a db.Asset, action string) int {
	return r.count(`SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = $2 AND target = $3`,
		a.TenantID.UUID(), action, a.ID.String())
}

func TestDeletionQueuesOneCDNPurgeAfterTheTombstone(t *testing.T) {
	r := newRig(t)
	a := r.seed(false).asset
	if err := r.run(r.cdnPurger(), a, db.DeletionRequested); err != nil {
		t.Fatal(err)
	}
	if n := r.cdnJobs(a); n != 1 {
		t.Fatalf("%d asset.cdn_purge jobs after the deletion, want 1", n)
	}
	// The job holds identifiers only: no URL, key or object key.
	var args string
	if err := r.pool.QueryRow(context.Background(), `SELECT args::text FROM river_job WHERE kind = $1`, purge.CDNJobKind).Scan(&args); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(args, "/") || strings.Contains(args, "http") {
		t.Fatalf("the job arguments hold more than identifiers: %s", args)
	}
	// A repeated deletion job finds the tombstone and queues nothing more.
	if err := r.run(r.cdnPurger(), a, db.DeletionRequested); err != nil {
		t.Fatal(err)
	}
	if n := r.cdnJobs(a); n != 1 {
		t.Fatalf("%d jobs after a repeat, want 1", n)
	}
}

func TestDeletionWithoutACDNQueuesNothing(t *testing.T) {
	r := newRig(t)
	a := r.seed(false).asset
	if err := r.run(r.purger, a, db.DeletionRequested); err != nil {
		t.Fatal(err)
	}
	if n := r.count(`SELECT count(*) FROM river_job WHERE kind = $1`, purge.CDNJobKind); n != 0 {
		t.Fatalf("%d CDN jobs without a CDN", n)
	}
}

func TestCDNPurgeJobPurgesTheDeliveryPrefixAndAudits(t *testing.T) {
	r := newRig(t)
	a := r.seed(false).asset
	fake := &fakeCDNPurger{}
	reg := jobs.NewRegistry()
	d := purge.CDNDeps{Pool: r.pool, Purger: fake, Log: slog.New(slog.DiscardHandler)}
	if err := purge.RegisterCDN(reg, d); err != nil {
		t.Fatal(err)
	}
	if err := purge.RunCDN(d, context.Background(), purge.CDNArgs{TenantID: a.TenantID, AssetID: a.ID}, 1, 10); err != nil {
		t.Fatal(err)
	}
	if len(fake.prefixes) != 1 || fake.prefixes[0] != keys.DeliveryPrefix(a.TenantID, a.ID) {
		t.Fatalf("purged %v, want the delivery prefix of the asset", fake.prefixes)
	}
	if n := r.audits(a, purge.AuditCDNPurged); n != 1 {
		t.Fatalf("%d purged audit events, want 1", n)
	}
}

func TestCDNPurgeJobRetriesAndAuditsTheFinalFailure(t *testing.T) {
	r := newRig(t)
	a := r.seed(false).asset
	fake := &fakeCDNPurger{err: errors.New("throttled")}
	d := purge.CDNDeps{Pool: r.pool, Purger: fake, Log: slog.New(slog.DiscardHandler)}
	args := purge.CDNArgs{TenantID: a.TenantID, AssetID: a.ID}

	// An early failure returns an error River retries, and writes nothing yet.
	err := purge.RunCDN(d, context.Background(), args, 1, 3)
	if err == nil || !jobs.Retryable(err) {
		t.Fatalf("first failure = %v, want a retryable error", err)
	}
	if r.audits(a, purge.AuditCDNPurgeFailed) != 0 || r.audits(a, purge.AuditCDNPurged) != 0 {
		t.Fatal("an attempt that will be retried wrote an audit event")
	}
	// The last attempt records the failure.
	if err := purge.RunCDN(d, context.Background(), args, 3, 3); err == nil {
		t.Fatal("the last failure was swallowed")
	}
	if n := r.audits(a, purge.AuditCDNPurgeFailed); n != 1 {
		t.Fatalf("%d failure audit events, want 1", n)
	}
	// An operator re-queuing the job after fixing the cause succeeds.
	fake.err = nil
	if err := purge.RunCDN(d, context.Background(), args, 1, 10); err != nil {
		t.Fatal(err)
	}
	if n := r.audits(a, purge.AuditCDNPurged); n != 1 {
		t.Fatalf("%d purged audit events, want 1", n)
	}
}
