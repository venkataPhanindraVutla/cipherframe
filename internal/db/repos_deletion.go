package db

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// Why an asset is being deleted (assets.deletion_reason).
const (
	// DeletionRequested: an API call asked for it.
	DeletionRequested = "requested"
	// DeletionRetention: the asset's time-to-live ran out (M6-4).
	DeletionRetention = "retention"
)

// ValidDeletionReason reports whether reason is one of the two.
func ValidDeletionReason(reason string) bool {
	return reason == DeletionRequested || reason == DeletionRetention
}

// RequestAssetDeletion moves an asset from any live state to deleting, once, recording when and
// why. An asset that is already deleting or deleted is a conflict whose cause is ErrStateChanged,
// and nothing is written; callers that want idempotence read the asset and carry on.
func (r *Repos) RequestAssetDeletion(ctx context.Context, tenantID id.TenantID, assetID id.AssetID, reason string, at time.Time) (Asset, error) {
	tid, aid, err := assetKeys(tenantID, assetID)
	if err != nil {
		return Asset{}, err
	}
	if !ValidDeletionReason(reason) {
		return Asset{}, errs.New(errs.InternalError, "An internal error occurred.")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	row, err := r.q.RequestAssetDeletion(ctx, dbgen.RequestAssetDeletionParams{At: at, Reason: reason, TenantID: tid, ID: aid})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Asset{}, stateConflict()
		}
		return Asset{}, mapError(err)
	}
	return assetFromRow(row), nil
}

// CompleteAssetDeletion moves a deleting asset to deleted (the tombstone) and clears its source
// object references. Losing the race is a conflict whose cause is ErrStateChanged.
func (r *Repos) CompleteAssetDeletion(ctx context.Context, tenantID id.TenantID, assetID id.AssetID, at time.Time) (Asset, error) {
	tid, aid, err := assetKeys(tenantID, assetID)
	if err != nil {
		return Asset{}, err
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	row, err := r.q.CompleteAssetDeletion(ctx, dbgen.CompleteAssetDeletionParams{At: at, TenantID: tid, ID: aid})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Asset{}, stateConflict()
		}
		return Asset{}, mapError(err)
	}
	return assetFromRow(row), nil
}

// DeleteAssetArtifacts removes every registry row of the asset and returns how many there were.
// The objects are the caller's to delete first.
func (r *Repos) DeleteAssetArtifacts(ctx context.Context, assetID id.AssetID) (int64, error) {
	aid, err := requirePG(assetID)
	if err != nil {
		return 0, err
	}
	n, err := r.q.DeleteAssetArtifacts(ctx, aid)
	return n, mapError(err)
}

// DestroyedKey names a content key that was destroyed: its ID and variant, never the key.
type DestroyedKey struct {
	ID      id.ContentKeyID
	Variant keys.Variant
}

// DestroyContentKeys destroys every variant's content key row of the tenant's asset (the row is
// deleted, not flagged) and returns what it destroyed, ordered by key ID.
func (r *Repos) DestroyContentKeys(ctx context.Context, tenantID id.TenantID, assetID id.AssetID) ([]DestroyedKey, error) {
	tid, aid, err := assetKeys(tenantID, assetID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.DestroyContentKeysByAsset(ctx, dbgen.DestroyContentKeysByAssetParams{TenantID: tid, AssetID: aid})
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]DestroyedKey, len(rows))
	for i, row := range rows {
		out[i] = DestroyedKey{ID: fromPG[id.ContentKeyKind](row.ID), Variant: keys.Variant(row.Variant)}
	}
	slices.SortFunc(out, func(a, b DestroyedKey) int { return strings.Compare(a.ID.String(), b.ID.String()) })
	return out, nil
}
