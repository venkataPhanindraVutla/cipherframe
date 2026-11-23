// Package rekey is the audited content-key re-key of one asset (M10-4, ADR 0068): every encrypted
// segment of every variant is decrypted with the old key and encrypted again under a fresh one, the
// integrity manifest is signed again, and the asset is switched to the new key and the old key
// destroyed, in one transaction.
//
// The new objects are written beside the old ones, under "k<generation>/" in the variant's HLS
// prefix (keys.VariantGenPrefix), so until the switch the asset is untouched and plays under the old
// key. A crash before the switch leaves only unregistered staging objects, which the retry removes.
// The old objects are deleted after the switch. Plaintext exists only in memory, one segment at a
// time, as in the pipeline (ADR 0027).
package rekey

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

// JobKind is the River job kind of the re-key. Do not rename it once jobs of that kind exist. The
// purge waits for jobs of this kind (package purge names it too).
const JobKind = "asset.rekey"

// Audit actions of a re-key. They carry the asset ID only: never a key, a key ID or an object key.
const (
	AuditRequested = "asset.rekey_requested"
	AuditCompleted = "asset.rekey_completed"
	AuditFailed    = "asset.rekey_failed"
)

// Args are the arguments of the asset.rekey job: identifiers only.
type Args struct {
	TenantID id.TenantID `json:"tenant_id"`
	AssetID  id.AssetID  `json:"asset_id"`
	// FromGeneration is the key generation the asset had when the re-key was requested, under the
	// asset lock. A run that finds the asset past it knows the switch already happened.
	FromGeneration int `json:"from_generation"`
}

// Kind implements jobs.Args.
func (Args) Kind() string { return JobKind }

// Enqueuer inserts a job in the caller's transaction. *jobs.Queue implements it.
type Enqueuer interface {
	Enqueue(ctx context.Context, tx pgx.Tx, args jobs.Args, opts *jobs.EnqueueOpts) (int64, error)
}

// Requester starts re-keys: the API's POST calls Request.
type Requester struct {
	Pool  *pgxpool.Pool
	Queue Enqueuer
	// Now defaults to time.Now.
	Now func() time.Time
}

// NewRequester validates its arguments.
func NewRequester(pool *pgxpool.Pool, q Enqueuer) (*Requester, error) {
	if pool == nil || q == nil {
		return nil, errors.New("rekey: a pool and a job queue are required")
	}
	return &Requester{Pool: pool, Queue: q, Now: time.Now}, nil
}

// Request queues the re-key of the tenant's asset and returns the job's ID. Under the asset lock it
// checks that the asset is ready (anything else is refused: not_found for a deleted one and for
// another tenant's, a conflict while it is being deleted or while masking is still running,
// asset_not_ready otherwise) and that no re-key of the asset is waiting, running or due to retry (a
// conflict), then writes the audit event and the job in one transaction.
func (r *Requester) Request(ctx context.Context, tenant id.TenantID, asset id.AssetID, actor auth.Actor) (int64, error) {
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return 0, db.MapError(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }() // a no-op after Commit
	repos := db.New(tx)
	cur, err := repos.LockAsset(ctx, tenant, asset)
	if err != nil {
		return 0, err
	}
	if err := rekeyable(cur); err != nil {
		return 0, err
	}
	var active bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM river_job
		WHERE kind = $1 AND args->>'asset_id' = $2
		  AND state IN ('available', 'pending', 'retryable', 'running', 'scheduled'))`,
		JobKind, asset.String()).Scan(&active); err != nil {
		return 0, db.MapError(err)
	}
	if active {
		return 0, errs.New(errs.Conflict, "A re-key of this asset is already in progress.")
	}
	if _, err := repos.InsertAuditEvent(ctx, db.NewAuditEvent{
		TenantID: tenant, ClientID: actor.ClientID, APIKeyID: actor.KeyID,
		Action: AuditRequested, Target: asset.String(), RequestID: actor.RequestID,
	}); err != nil {
		return 0, err
	}
	jobID, err := r.Queue.Enqueue(ctx, tx, Args{TenantID: tenant, AssetID: asset, FromGeneration: cur.KeyGeneration}, nil)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, db.MapError(err)
	}
	return jobID, nil
}

// rekeyable says whether the asset may be re-keyed now.
func rekeyable(a db.Asset) error {
	switch a.State {
	case db.AssetReady:
	case db.AssetDeleted:
		return errs.New(errs.NotFound, "No such asset.")
	case db.AssetDeleting:
		return errs.New(errs.Conflict, "The asset is being deleted.")
	default:
		return errs.New(errs.AssetNotReady, "Only a ready asset can be re-keyed.")
	}
	// The masked variant is published after the asset is ready (ADR 0036), under the key it creates
	// then; re-keying while that runs would leave it on the old key.
	if a.MaskFaces && a.MaskingState != db.MaskingReady && a.MaskingState != db.MaskingFailed {
		return errs.New(errs.Conflict, "The masked variant is still being made; re-key the asset when it is done.")
	}
	return nil
}
