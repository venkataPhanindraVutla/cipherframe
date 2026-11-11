package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// ErrStateChanged is the cause of the conflict a compare-and-set returns when the row was no
// longer in the expected state. Test for it with errors.Is.
var ErrStateChanged = errors.New("db: asset is not in the expected state")

func stateConflict() error {
	return errs.Wrap(errs.Conflict, "The asset is not in a state that allows this operation.", ErrStateChanged)
}

// NewUploadAsset is the input for CreateUploadAsset. ID is chosen by the caller because the
// source key (and the object store's multipart upload) are derived before the row exists.
type NewUploadAsset struct {
	ID          id.AssetID
	TenantID    id.TenantID
	ClientID    id.ClientID
	SizeBytes   int64
	ContentType string // may be empty
	Method      UploadMethod
	SourceKey   string
	S3UploadID  string // empty for tus; set when the multipart upload was already created
	ExpiresAt   time.Time
}

// CreateUploadAsset inserts an asset in state created. The client must belong to the tenant,
// otherwise not_found is returned and nothing is written.
func (r *Repos) CreateUploadAsset(ctx context.Context, in NewUploadAsset) (Asset, error) {
	tid, cid, aid, err := createKeys(in)
	if err != nil {
		return Asset{}, err
	}
	if in.SizeBytes < 1 || !in.Method.Valid() || in.SourceKey == "" {
		return Asset{}, errs.New(errs.InvalidRequest, "invalid asset")
	}
	row, err := r.q.CreateUploadAsset(ctx, dbgen.CreateUploadAssetParams{
		ID: aid, SizeBytes: in.SizeBytes, ContentType: strPtr(in.ContentType), UploadMethod: string(in.Method),
		SourceKey: in.SourceKey, S3UploadID: strPtr(in.S3UploadID), UploadExpiresAt: in.ExpiresAt,
		ClientID: cid, TenantID: tid,
	})
	if err != nil {
		return Asset{}, mapError(err)
	}
	return assetFromRow(row), nil
}

func createKeys(in NewUploadAsset) (tid, cid, aid pgtype.UUID, err error) {
	if tid, err = requirePG(in.TenantID); err != nil {
		return tid, cid, aid, err
	}
	if cid, err = requirePG(in.ClientID); err != nil {
		return tid, cid, aid, err
	}
	aid, err = requirePG(in.ID)
	return tid, cid, aid, err
}

// LockAsset reads the asset and holds a row lock until the surrounding transaction ends. Use it
// inside Tx to serialise writers of one asset. Another tenant's asset is not_found.
func (r *Repos) LockAsset(ctx context.Context, tenantID id.TenantID, assetID id.AssetID) (Asset, error) {
	tid, aid, err := assetKeys(tenantID, assetID)
	if err != nil {
		return Asset{}, err
	}
	row, err := r.q.LockAsset(ctx, dbgen.LockAssetParams{TenantID: tid, ID: aid})
	if err != nil {
		return Asset{}, mapError(err)
	}
	return assetFromRow(row), nil
}

func assetKeys(tenantID id.TenantID, assetID id.AssetID) (tid, aid pgtype.UUID, err error) {
	if tid, err = requirePG(tenantID); err != nil {
		return tid, aid, err
	}
	aid, err = requirePG(assetID)
	return tid, aid, err
}

// ListAssetsPage returns up to limit of the tenant's assets (deleted ones excluded) in creation
// order, starting after the asset with ID after (the zero ID for the first page).
func (r *Repos) ListAssetsPage(ctx context.Context, tenantID id.TenantID, after id.AssetID, limit int) ([]Asset, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return nil, err
	}
	if limit < 1 || limit > maxPage {
		return nil, errs.New(errs.InvalidRequest, "invalid page size")
	}
	rows, err := r.q.ListAssetsPage(ctx, dbgen.ListAssetsPageParams{
		TenantID: tid, AfterID: toPG(after), MaxRows: int32(limit), //nolint:gosec // bounded by maxPage
	})
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]Asset, len(rows))
	for i, row := range rows {
		out[i] = assetFromRow(row)
	}
	return out, nil
}

// Transition describes one lifecycle change.
type Transition struct {
	From, To AssetState
	// FailureCode is recorded when To is failed; it must be a short lower_snake_case code and
	// never free text.
	FailureCode string
	At          time.Time
}

// TransitionAsset moves an asset along an edge of the lifecycle with a compare-and-set: the row
// changes only while it is still in t.From. An edge the lifecycle does not allow is an
// internal_error (a programming error); losing the race is a conflict whose cause is
// ErrStateChanged, and nothing is written.
func (r *Repos) TransitionAsset(ctx context.Context, tenantID id.TenantID, assetID id.AssetID, t Transition) (Asset, error) {
	tid, aid, err := assetKeys(tenantID, assetID)
	if err != nil {
		return Asset{}, err
	}
	if !t.From.Valid() || !t.To.Valid() || !t.From.CanTransitionTo(t.To) {
		return Asset{}, errs.New(errs.InternalError, "An internal error occurred.")
	}
	if t.At.IsZero() {
		t.At = time.Now().UTC()
	}
	row, err := r.q.TransitionAsset(ctx, dbgen.TransitionAssetParams{
		ToState: string(t.To), At: t.At, FailureCode: strPtr(t.FailureCode),
		TenantID: tid, ID: aid, FromState: string(t.From),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Asset{}, stateConflict()
		}
		return Asset{}, mapError(err)
	}
	return assetFromRow(row), nil
}

// StartTusUpload records the object store's multipart upload ID for a tus asset and moves it
// created -> uploading, once. When the asset is no longer in created (a second upload for the same
// asset), it returns a conflict whose cause is ErrStateChanged.
func (r *Repos) StartTusUpload(ctx context.Context, tenantID id.TenantID, assetID id.AssetID, uploadID string, at time.Time) (Asset, error) {
	tid, aid, err := assetKeys(tenantID, assetID)
	if err != nil {
		return Asset{}, err
	}
	if uploadID == "" {
		return Asset{}, errs.New(errs.InvalidRequest, "an upload ID is required")
	}
	row, err := r.q.StartTusUpload(ctx, dbgen.StartTusUploadParams{S3UploadID: uploadID, At: at, TenantID: tid, ID: aid})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Asset{}, stateConflict()
		}
		return Asset{}, mapError(err)
	}
	return assetFromRow(row), nil
}

// InsertUploadToken stores the hash of an upload token bound to an asset. An asset has at most
// one token; a second insert is a conflict.
func (r *Repos) InsertUploadToken(ctx context.Context, tenantID id.TenantID, assetID id.AssetID, hash []byte, expiresAt time.Time) error {
	tid, aid, err := assetKeys(tenantID, assetID)
	if err != nil {
		return err
	}
	if len(hash) != 32 {
		return errs.New(errs.InternalError, "An internal error occurred.")
	}
	return mapError(r.q.InsertUploadToken(ctx, dbgen.InsertUploadTokenParams{
		TokenHash: hash, AssetID: aid, TenantID: tid, ExpiresAt: expiresAt,
	}))
}

// GetUploadGrant looks a token up by its hash. An unknown token is not_found. The caller must
// check the expiry and the asset's state.
func (r *Repos) GetUploadGrant(ctx context.Context, hash []byte) (UploadGrant, error) {
	row, err := r.q.GetUploadGrant(ctx, hash)
	if err != nil {
		return UploadGrant{}, mapError(err)
	}
	return UploadGrant{Asset: assetFromRow(row.Asset), TokenExpiresAt: row.TokenExpiresAt.UTC()}, nil
}

// DeleteUploadTokens removes the asset's token, which ends its authority at once.
func (r *Repos) DeleteUploadTokens(ctx context.Context, assetID id.AssetID) error {
	aid, err := requirePG(assetID)
	if err != nil {
		return err
	}
	return mapError(r.q.DeleteUploadTokens(ctx, aid))
}

// RecordUploadPart stores (or replaces) a received part.
func (r *Repos) RecordUploadPart(ctx context.Context, assetID id.AssetID, p UploadPart) error {
	aid, err := requirePG(assetID)
	if err != nil {
		return err
	}
	if p.PartNumber < 1 || p.PartNumber > 10000 || p.ETag == "" || p.SizeBytes < 1 {
		return errs.New(errs.InvalidRequest, "invalid part")
	}
	return mapError(r.q.UpsertUploadPart(ctx, dbgen.UpsertUploadPartParams{
		AssetID: aid, PartNumber: int32(p.PartNumber), Etag: p.ETag, SizeBytes: p.SizeBytes, //nolint:gosec // 1..10000
	}))
}

// ListUploadParts returns the received parts in ascending part-number order.
func (r *Repos) ListUploadParts(ctx context.Context, assetID id.AssetID) ([]UploadPart, error) {
	aid, err := requirePG(assetID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListUploadParts(ctx, aid)
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]UploadPart, len(rows))
	for i, row := range rows {
		out[i] = UploadPart{PartNumber: int(row.PartNumber), ETag: row.Etag, SizeBytes: row.SizeBytes, CreatedAt: row.CreatedAt.UTC()}
	}
	return out, nil
}

// SumOtherUploadPartSizes returns the total size of the asset's received parts except part n.
func (r *Repos) SumOtherUploadPartSizes(ctx context.Context, assetID id.AssetID, n int) (int64, error) {
	aid, err := requirePG(assetID)
	if err != nil {
		return 0, err
	}
	total, err := r.q.SumOtherUploadPartSizes(ctx, dbgen.SumOtherUploadPartSizesParams{AssetID: aid, PartNumber: int32(n)}) //nolint:gosec // 1..10000
	return total, mapError(err)
}

// DeleteUploadParts forgets the asset's received parts.
func (r *Repos) DeleteUploadParts(ctx context.Context, assetID id.AssetID) error {
	aid, err := requirePG(assetID)
	if err != nil {
		return err
	}
	return mapError(r.q.DeleteUploadParts(ctx, aid))
}
