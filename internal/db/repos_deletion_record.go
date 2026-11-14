package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// DeletionRecord is a row of asset_deletion_records (ADR 0033, M6-3): the signed record that an
// asset was deleted. Envelope is the DSSE envelope as JSON; it holds no secret.
type DeletionRecord struct {
	AssetID       id.AssetID
	TenantID      id.TenantID
	Reason        string
	RequestedAt   time.Time
	CompletedAt   time.Time
	KeyID         string
	PayloadSHA256 []byte
	Envelope      []byte
}

func (d DeletionRecord) valid() bool {
	return ValidDeletionReason(d.Reason) && d.KeyID != "" && len(d.PayloadSHA256) == 32 && json.Valid(d.Envelope) &&
		!d.RequestedAt.IsZero() && !d.CompletedAt.IsZero()
}

// InsertDeletionRecord stores the record of an asset. A second record for the same asset is a bug
// and fails with a conflict. Call it in the transaction that completes the deletion.
func (r *Repos) InsertDeletionRecord(ctx context.Context, d DeletionRecord) error {
	tid, aid, err := assetKeys(d.TenantID, d.AssetID)
	if err != nil {
		return err
	}
	if !d.valid() {
		return errs.New(errs.InternalError, "An internal error occurred.")
	}
	return mapError(r.q.InsertAssetDeletionRecord(ctx, dbgen.InsertAssetDeletionRecordParams{
		AssetID: aid, TenantID: tid, Reason: d.Reason, RequestedAt: d.RequestedAt.UTC(), CompletedAt: d.CompletedAt.UTC(),
		KeyID: d.KeyID, PayloadSha256: d.PayloadSHA256, Envelope: d.Envelope,
	}))
}

// GetDeletionRecord returns the tenant's record for the asset, or not_found when there is none
// (the asset is not deleted, or belongs to another tenant).
func (r *Repos) GetDeletionRecord(ctx context.Context, tenantID id.TenantID, assetID id.AssetID) (DeletionRecord, error) {
	tid, aid, err := assetKeys(tenantID, assetID)
	if err != nil {
		return DeletionRecord{}, err
	}
	row, err := r.q.GetAssetDeletionRecord(ctx, dbgen.GetAssetDeletionRecordParams{TenantID: tid, AssetID: aid})
	if err != nil {
		return DeletionRecord{}, mapError(err)
	}
	return DeletionRecord{
		AssetID: assetID, TenantID: tenantID, Reason: row.Reason, RequestedAt: row.RequestedAt.UTC(), CompletedAt: row.CompletedAt.UTC(),
		KeyID: row.KeyID, PayloadSHA256: row.PayloadSha256, Envelope: row.Envelope,
	}, nil
}
