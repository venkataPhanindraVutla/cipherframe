package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// DropSourceKind is the job kind that deletes the uploaded original of an asset created with
// keep_source off (H-3). Do not rename it once jobs of that kind exist.
const DropSourceKind = "asset.drop_source"

// AuditSourceDeleted is the audit action written when the original was deleted. It carries the
// asset ID only, never an object key.
const AuditSourceDeleted = "asset.source_deleted"

// DropSourceArgs are the arguments of the asset.drop_source job: identifiers only.
type DropSourceArgs struct {
	TenantID id.TenantID `json:"tenant_id"`
	AssetID  id.AssetID  `json:"asset_id"`
}

// Kind implements jobs.Args.
func (DropSourceArgs) Kind() string { return DropSourceKind }

// dropDue reports whether the original of a is to be deleted now: the asset was created with
// keep_source off, is ready, has not had it deleted yet and, when it masks faces, the masked variant
// is no longer pending (it is ready or failed; either way the masker has read the original).
// A failed, deleting or deleted asset is never due.
func dropDue(a db.Asset) bool {
	if a.KeepSource || a.State != db.AssetReady || a.SourceDeletedAt != nil {
		return false
	}
	return !a.MaskFaces || a.MaskingState == db.MaskingReady || a.MaskingState == db.MaskingFailed
}

// HandleDropSource works one asset.drop_source job. It is idempotent: it deletes everything under
// the asset's source prefix (the original, tus's .info and .part objects, multipart leftovers) and
// records the deletion once. The job is queued in the transaction in which the asset first becomes
// ready with masking settled (DBRepo), and checks that again here, so a stale or duplicate job does
// nothing.
func (p *Processor) HandleDropSource(ctx context.Context, job jobs.Job[DropSourceArgs]) error {
	tenant, assetID := job.Args.TenantID, job.Args.AssetID
	if tenant.IsZero() || assetID.IsZero() {
		return jobs.Cancel(errs.New(errs.InvalidRequest, "the job has no asset"))
	}
	log := p.Log.With(slog.String("job", DropSourceKind), slog.String("tenant_id", tenant.String()),
		slog.String("asset_id", assetID.String()), slog.Int("attempt", job.Attempt))
	asset, err := p.Repo.GetAsset(ctx, tenant, assetID)
	if err != nil {
		if isCode(err, errs.NotFound) {
			return nil // the asset is gone
		}
		return err
	}
	if !dropDue(asset) {
		log.InfoContext(ctx, "nothing to do", slog.String("state", string(asset.State)))
		return nil
	}
	var batch []string
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := p.Source.DeleteBatch(ctx, batch)
		batch = batch[:0]
		return err
	}
	for obj, err := range storage.ListAll(ctx, p.Source, keys.SourcePrefix(tenant, assetID)) {
		if err != nil {
			return fmt.Errorf("pipeline: list source objects: %w", err)
		}
		if batch = append(batch, obj.Key); len(batch) >= storage.MaxDeleteBatch {
			if err := flush(); err != nil {
				return fmt.Errorf("pipeline: delete source objects: %w", err)
			}
		}
	}
	if err := flush(); err != nil {
		return fmt.Errorf("pipeline: delete source objects: %w", err)
	}
	if _, err := p.Repo.RecordSourceDeleted(ctx, tenant, assetID, p.Now().UTC()); err != nil {
		return err
	}
	log.InfoContext(ctx, "source deleted")
	return nil
}

// enqueueDropSource queues asset.drop_source in tx when a is due, so the job exists exactly when
// the state change that made it due committed.
func (r *DBRepo) enqueueDropSource(ctx context.Context, tx pgx.Tx, a db.Asset) error {
	if !dropDue(a) {
		return nil
	}
	if r.queue == nil {
		return errors.New("pipeline: no job queue to delete the source of an asset")
	}
	_, err := r.queue.Enqueue(ctx, tx, DropSourceArgs{TenantID: a.TenantID, AssetID: a.ID}, nil)
	return err
}

// RecordSourceDeleted implements Repo: the deletion time and the audit event in one transaction.
func (r *DBRepo) RecordSourceDeleted(ctx context.Context, tenant id.TenantID, asset id.AssetID, at time.Time) (bool, error) {
	var recorded bool
	err := inTx(ctx, r.pool, func(_ pgx.Tx, repos *db.Repos) error {
		var err error
		if recorded, err = repos.MarkSourceDeleted(ctx, tenant, asset, at); err != nil || !recorded {
			return err
		}
		_, err = repos.InsertAuditEvent(ctx, db.NewAuditEvent{TenantID: tenant, Action: AuditSourceDeleted, Target: asset.String()})
		return err
	})
	return recorded, err
}
