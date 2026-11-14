package db

import (
	"context"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// KEKRef names the key-encryption key version that wrapped a content key.
type KEKRef struct {
	Provider string
	KeyID    string
	Version  string
}

func (k KEKRef) valid() bool { return k.Provider != "" && k.KeyID != "" && k.Version != "" }

// ContentKeyRow is a stored content key: only wrapped (encrypted) bytes plus the record of what
// wrapped them. It never holds a plaintext key.
type ContentKeyRow struct {
	ID              id.ContentKeyID
	AssetID         id.AssetID
	Variant         keys.Variant
	KEK             KEKRef
	EnvelopeVersion int
	Wrapped         []byte
	CreatedAt       time.Time
	RewrappedAt     *time.Time
}

// NewContentKeyRow is the input for CreateContentKey. The caller chooses the ID because the
// wrapped bytes are bound to it as associated data.
type NewContentKeyRow struct {
	ID              id.ContentKeyID
	AssetID         id.AssetID
	Variant         keys.Variant
	KEK             KEKRef
	EnvelopeVersion int
	Wrapped         []byte
}

// RewrapUpdate is the input for UpdateContentKeyWrapped.
type RewrapUpdate struct {
	ID              id.ContentKeyID
	From            KEKRef // the KEK the caller read; the update applies only while the row still names it
	To              KEKRef
	EnvelopeVersion int
	Wrapped         []byte
}

func contentKeyFromRow(r dbgen.ContentKey) ContentKeyRow {
	return ContentKeyRow{
		ID:      fromPG[id.ContentKeyKind](r.ID),
		AssetID: fromPG[id.AssetKind](r.AssetID),
		Variant: keys.Variant(r.Variant),
		KEK: KEKRef{
			Provider: r.Provider, KeyID: r.KekKeyID, Version: r.KekVersion,
		},
		EnvelopeVersion: int(r.EnvelopeVersion),
		Wrapped:         r.Wrapped,
		CreatedAt:       r.CreatedAt.UTC(),
		RewrappedAt:     utcPtr(r.RewrappedAt),
	}
}

// CreateContentKey inserts the content key row of an asset that belongs to tenantID. An asset of
// another tenant, or a missing one, returns not_found. A second key for the same asset and variant
// returns conflict (invariant I7).
func (r *Repos) CreateContentKey(ctx context.Context, tenantID id.TenantID, in NewContentKeyRow) (ContentKeyRow, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return ContentKeyRow{}, err
	}
	kid, err := requirePG(in.ID)
	if err != nil {
		return ContentKeyRow{}, err
	}
	aid, err := requirePG(in.AssetID)
	if err != nil {
		return ContentKeyRow{}, err
	}
	if !in.Variant.Valid() || !in.KEK.valid() || len(in.Wrapped) == 0 || in.EnvelopeVersion < 1 || in.EnvelopeVersion > 32767 {
		return ContentKeyRow{}, errs.New(errs.InvalidRequest, "invalid content key")
	}
	row, err := r.q.InsertContentKey(ctx, dbgen.InsertContentKeyParams{
		ID: kid, AssetID: aid, Variant: in.Variant.String(), TenantID: tid,
		Provider: in.KEK.Provider, KekKeyID: in.KEK.KeyID, KekVersion: in.KEK.Version,
		EnvelopeVersion: int16(in.EnvelopeVersion), //nolint:gosec // range checked above
		Wrapped:         in.Wrapped,
	})
	if err != nil {
		return ContentKeyRow{}, mapError(err)
	}
	return contentKeyFromRow(row), nil
}

// GetContentKey returns the content key row of one variant of the tenant's asset, or not_found.
func (r *Repos) GetContentKey(ctx context.Context, tenantID id.TenantID, assetID id.AssetID, variant keys.Variant) (ContentKeyRow, error) {
	if !variant.Valid() {
		return ContentKeyRow{}, errs.New(errs.InvalidRequest, "invalid variant")
	}
	tid, err := requirePG(tenantID)
	if err != nil {
		return ContentKeyRow{}, err
	}
	aid, err := requirePG(assetID)
	if err != nil {
		return ContentKeyRow{}, err
	}
	row, err := r.q.GetContentKeyByAsset(ctx, dbgen.GetContentKeyByAssetParams{TenantID: tid, AssetID: aid, Variant: variant.String()})
	if err != nil {
		return ContentKeyRow{}, mapError(err)
	}
	return contentKeyFromRow(row), nil
}

// DeleteContentKey destroys every variant's content key row of the tenant's asset and returns how
// many rows were deleted. The row is deleted, not flagged (invariant I5).
func (r *Repos) DeleteContentKey(ctx context.Context, tenantID id.TenantID, assetID id.AssetID) (int64, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return 0, err
	}
	aid, err := requirePG(assetID)
	if err != nil {
		return 0, err
	}
	n, err := r.q.DeleteContentKeyByAsset(ctx, dbgen.DeleteContentKeyByAssetParams{TenantID: tid, AssetID: aid})
	if err != nil {
		return 0, mapError(err)
	}
	return n, nil
}

// ListContentKeysForRewrap returns up to limit rows still wrapped under kek, in creation order,
// starting after the row with ID after (the zero ID for the first page). It spans all tenants: it
// serves the re-wrap job, which runs outside any tenant.
func (r *Repos) ListContentKeysForRewrap(ctx context.Context, kek KEKRef, after id.ContentKeyID, limit int) ([]ContentKeyRow, error) {
	if !kek.valid() || limit < 1 || limit > maxPage {
		return nil, errs.New(errs.InvalidRequest, "invalid page size or KEK")
	}
	rows, err := r.q.ListContentKeysForRewrap(ctx, dbgen.ListContentKeysForRewrapParams{
		Provider: kek.Provider, KekKeyID: kek.KeyID, KekVersion: kek.Version,
		AfterID: toPG(after), MaxRows: int32(limit), //nolint:gosec // bounded by maxPage
	})
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]ContentKeyRow, len(rows))
	for i, row := range rows {
		out[i] = contentKeyFromRow(row)
	}
	return out, nil
}

// UpdateContentKeyWrapped stores re-wrapped bytes. It reports false, without error, when the row
// no longer names u.From (another re-wrap or a deletion got there first).
func (r *Repos) UpdateContentKeyWrapped(ctx context.Context, u RewrapUpdate) (bool, error) {
	kid, err := requirePG(u.ID)
	if err != nil {
		return false, err
	}
	if !u.From.valid() || !u.To.valid() || len(u.Wrapped) == 0 || u.EnvelopeVersion < 1 || u.EnvelopeVersion > 32767 {
		return false, errs.New(errs.InvalidRequest, "invalid content key update")
	}
	n, err := r.q.UpdateContentKeyWrapped(ctx, dbgen.UpdateContentKeyWrappedParams{
		ID:       kid,
		Provider: u.To.Provider, KekKeyID: u.To.KeyID, KekVersion: u.To.Version,
		EnvelopeVersion: int16(u.EnvelopeVersion), //nolint:gosec // range checked above
		Wrapped:         u.Wrapped,
		OldProvider:     u.From.Provider, OldKekKeyID: u.From.KeyID, OldKekVersion: u.From.Version,
	})
	if err != nil {
		return false, mapError(err)
	}
	return n == 1, nil
}
