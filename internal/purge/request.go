package purge

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
)

// Enqueuer inserts a job in the caller's transaction. *jobs.Queue implements it.
type Enqueuer interface {
	Enqueue(ctx context.Context, tx pgx.Tx, args jobs.Args, opts *jobs.EnqueueOpts) (int64, error)
}

// Requester starts deletions: the API's DELETE and the retention job both call Request.
type Requester struct {
	Pool  *pgxpool.Pool
	Queue Enqueuer
	// Now defaults to time.Now.
	Now func() time.Time
}

// NewRequester validates its arguments.
func NewRequester(pool *pgxpool.Pool, q Enqueuer) (*Requester, error) {
	if pool == nil || q == nil {
		return nil, errors.New("purge: a pool and a job queue are required")
	}
	return &Requester{Pool: pool, Queue: q, Now: time.Now}, nil
}

// Request marks the tenant's asset deleting and enqueues asset.delete in the same transaction, so
// either both happen or neither. It is idempotent: an asset that is already deleting or deleted is
// returned as it is. A deleting asset whose purge job is no longer in the queue (it was
// dead-lettered after exhausting its attempts) gets a new job, so repeating the call is how a stuck
// deletion is retried. actor is nil for the retention job. The asset of another tenant, or an
// unknown one, is not_found.
func (r *Requester) Request(ctx context.Context, tenant id.TenantID, asset id.AssetID, reason string, actor *auth.Actor) (db.Asset, error) {
	if !db.ValidDeletionReason(reason) {
		return db.Asset{}, errs.New(errs.InternalError, "An internal error occurred.")
	}
	now := r.Now().UTC()
	var out db.Asset
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return db.Asset{}, db.MapError(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }() // a no-op after Commit
	repos := db.New(tx)
	cur, err := repos.LockAsset(ctx, tenant, asset)
	if err != nil {
		return db.Asset{}, err
	}
	switch cur.State {
	case db.AssetDeleted:
		return cur, nil
	case db.AssetDeleting:
		active, aerr := ActiveJobs(ctx, r.Pool, asset, JobKind)
		if aerr != nil {
			return db.Asset{}, aerr
		}
		if active {
			return cur, nil
		}
		out = cur
	default:
		if out, err = repos.RequestAssetDeletion(ctx, tenant, asset, reason, now); err != nil {
			return db.Asset{}, err
		}
		ev := db.NewAuditEvent{TenantID: tenant, Action: AuditAssetExpire, Target: asset.String()}
		if actor != nil {
			ev = db.NewAuditEvent{TenantID: tenant, ClientID: actor.ClientID, APIKeyID: actor.KeyID, Action: AuditAssetDelete, Target: asset.String(), RequestID: actor.RequestID}
		}
		if _, err := repos.InsertAuditEvent(ctx, ev); err != nil {
			return db.Asset{}, err
		}
	}
	if _, err := r.Queue.Enqueue(ctx, tx, DeleteArgs{TenantID: tenant, AssetID: asset, Reason: out.DeletionReason}, nil); err != nil {
		return db.Asset{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return db.Asset{}, db.MapError(err)
	}
	return out, nil
}
