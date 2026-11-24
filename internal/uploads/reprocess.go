package uploads

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
)

// AuditAssetReprocess is the audit action written when a failed asset is queued for processing again.
const AuditAssetReprocess = "asset.reprocess_requested"

// Reprocess runs the processing of a failed asset again from its stored original (H-4). Under the
// asset's row lock it checks that the asset is failed and that its original is still in the source
// bucket, moves it failed -> committed (clearing what the failed run left, see
// db.Repos.RequeueFailedAsset), and queues asset.process, and asset.mask for mask_faces, with the
// audit event, in one transaction. The lock and the conditional update make two concurrent calls
// start exactly one run: the second finds the asset committed.
//
// The content key is not touched: a failure never destroys it (only a purge does), and the pipeline
// reuses the asset's key on every retry, so the new run uses the same one. Partial output of the
// failed run is removed by the new run itself, which starts by deleting the variant's objects,
// artifact rows and manifest (pipeline.process, pipeline.mask).
func (s *Service) Reprocess(ctx context.Context, tenantID id.TenantID, actor Actor, assetID id.AssetID) (db.Asset, error) {
	var out db.Asset
	err := s.inTx(ctx, func(tx pgx.Tx, r *db.Repos) error {
		cur, err := r.LockAsset(ctx, tenantID, assetID)
		if err != nil {
			return err
		}
		switch cur.State {
		case db.AssetFailed:
		case db.AssetDeleted:
			return errs.New(errs.NotFound, "No such asset.")
		case db.AssetDeleting:
			return errs.New(errs.Conflict, "The asset is being deleted.")
		default:
			return errs.New(errs.AssetNotFailed, "Only a failed asset can be processed again.")
		}
		if err := s.checkSourcePresent(ctx, cur); err != nil {
			return err
		}
		// A job of the failed run that is still working (a masker that has not noticed the failure)
		// would race the new one.
		var active bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM river_job
			WHERE kind = ANY($1) AND args->>'asset_id' = $2
			  AND state IN ('available', 'pending', 'retryable', 'running', 'scheduled'))`,
			[]string{ProcessKind, MaskKind}, assetID.String()).Scan(&active); err != nil {
			return db.MapError(err)
		}
		if active {
			return errs.New(errs.Conflict, "A job of the earlier run is still working; try again in a moment.")
		}
		if out, err = r.RequeueFailedAsset(ctx, tenantID, assetID, s.now().UTC()); err != nil {
			return err
		}
		if err := s.audit(ctx, r, tenantID, actor, AuditAssetReprocess, assetID); err != nil {
			return err
		}
		if _, err := s.queue.Enqueue(ctx, tx, ProcessArgs{TenantID: tenantID, AssetID: assetID}, nil); err != nil {
			return err
		}
		if !out.MaskFaces {
			return nil
		}
		_, err = s.queue.Enqueue(ctx, tx, MaskArgs{TenantID: tenantID, AssetID: assetID}, nil)
		return err
	})
	if errors.Is(err, db.ErrStateChanged) {
		return db.Asset{}, errs.New(errs.AssetNotFailed, "Only a failed asset can be processed again.")
	}
	return out, err
}

// checkSourcePresent is source_unavailable unless the original is in the source bucket. The column
// is not enough: it only says the drop job ran, and an object can be missing for other reasons, so
// storage is asked. An aborted upload never had a complete original.
func (s *Service) checkSourcePresent(ctx context.Context, a db.Asset) error {
	gone := errs.New(errs.SourceUnavailable, "The original upload is no longer stored; upload the video again.")
	if a.SourceKey == "" || a.SourceDeletedAt != nil || a.FailureCode == FailureUploadAborted {
		return gone
	}
	if _, err := s.source.Head(ctx, a.SourceKey); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return gone
		}
		return storage.ToAppError(err)
	}
	return nil
}
