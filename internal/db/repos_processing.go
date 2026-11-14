package db

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// ArtifactKind says what a derived object is (the asset_artifacts.kind column).
type ArtifactKind string

// Artifact kinds.
const (
	ArtifactMaster   ArtifactKind = "master"
	ArtifactPlaylist ArtifactKind = "playlist"
	ArtifactInit     ArtifactKind = "init"
	ArtifactSegment  ArtifactKind = "segment"
	ArtifactPoster   ArtifactKind = "poster"
)

// Valid reports whether k is a known kind.
func (k ArtifactKind) Valid() bool {
	switch k {
	case ArtifactMaster, ArtifactPlaylist, ArtifactInit, ArtifactSegment, ArtifactPoster:
		return true
	}
	return false
}

// Artifact registers one object derived from an asset (invariant I6). Bucket is the bucket role
// ("source" or "delivery"), not the configured bucket name. SHA256 is the hash of the bytes as
// stored, so for an encrypted segment it covers the ciphertext.
type Artifact struct {
	AssetID   id.AssetID
	Kind      ArtifactKind
	Rendition string // empty for the master playlist
	Bucket    string
	ObjectKey string
	SizeBytes int64
	SHA256    []byte
	// Variant is "original" or "masked" (ADR 0036); empty means original.
	Variant   string
	CreatedAt time.Time
}

// Variants an artifact can belong to (asset_artifacts.variant).
const (
	VariantOriginal = "original"
	VariantMasked   = "masked"
)

func validVariant(v string) bool { return v == VariantOriginal || v == VariantMasked }

// RecordSource stores the SHA-256 and size the worker measured while streaming the source. It
// changes nothing, and returns a conflict, unless the asset is processing.
func (r *Repos) RecordSource(ctx context.Context, tenantID id.TenantID, assetID id.AssetID, sha256 []byte, size int64) error {
	tid, aid, err := assetKeys(tenantID, assetID)
	if err != nil {
		return err
	}
	if len(sha256) != 32 || size < 1 {
		return errs.New(errs.InternalError, "An internal error occurred.")
	}
	n, err := r.q.RecordAssetSource(ctx, dbgen.RecordAssetSourceParams{
		SourceSha256: sha256, SourceSizeBytes: size, At: time.Now().UTC(), TenantID: tid, ID: aid,
	})
	if err != nil {
		return mapError(err)
	}
	if n == 0 {
		return stateConflict()
	}
	return nil
}

// SetProgress records a 0-100 progress hint. It only moves forward and applies only while the
// asset is processing; anything else is silently ignored.
func (r *Repos) SetProgress(ctx context.Context, tenantID id.TenantID, assetID id.AssetID, percent int) error {
	tid, aid, err := assetKeys(tenantID, assetID)
	if err != nil {
		return err
	}
	if percent < 0 || percent > 100 {
		return errs.New(errs.InternalError, "An internal error occurred.")
	}
	_, err = r.q.SetAssetProgress(ctx, dbgen.SetAssetProgressParams{
		Progress: int16(percent), TenantID: tid, ID: aid, //nolint:gosec // 0..100
	})
	return mapError(err)
}

// ResetProgress sets the progress of a processing asset back to zero (a retry starts over).
func (r *Repos) ResetProgress(ctx context.Context, tenantID id.TenantID, assetID id.AssetID) error {
	tid, aid, err := assetKeys(tenantID, assetID)
	if err != nil {
		return err
	}
	return mapError(r.q.ResetAssetProgress(ctx, dbgen.ResetAssetProgressParams{TenantID: tid, ID: aid}))
}

// Completion is what a finished pipeline records on the asset.
type Completion struct {
	Duration time.Duration
	// Renditions is a JSON summary of the renditions produced; it must be valid JSON.
	Renditions []byte
	// Manifest, when set, is stored with the completion (ADR 0033). CompleteProcessing writes it
	// after the compare-and-set succeeds, so a caller that runs it in a transaction gets a ready
	// asset and its manifest together or neither.
	Manifest *AssetManifest
	At       time.Time
}

// CompleteProcessing moves the asset processing -> ready with a compare-and-set and records the
// duration and the renditions summary. Losing the race is a conflict whose cause is ErrStateChanged.
func (r *Repos) CompleteProcessing(ctx context.Context, tenantID id.TenantID, assetID id.AssetID, c Completion) (Asset, error) {
	tid, aid, err := assetKeys(tenantID, assetID)
	if err != nil {
		return Asset{}, err
	}
	if c.Duration <= 0 || len(c.Renditions) == 0 {
		return Asset{}, errs.New(errs.InternalError, "An internal error occurred.")
	}
	if c.At.IsZero() {
		c.At = time.Now().UTC()
	}
	ms := max(c.Duration.Milliseconds(), 1)
	row, err := r.q.CompleteAssetProcessing(ctx, dbgen.CompleteAssetProcessingParams{
		At: c.At, DurationMs: ms, Renditions: c.Renditions, TenantID: tid, ID: aid,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Asset{}, stateConflict()
		}
		return Asset{}, mapError(err)
	}
	if m := c.Manifest; m != nil {
		stored := *m
		stored.AssetID, stored.TenantID = assetID, tenantID
		if stored.CreatedAt.IsZero() {
			stored.CreatedAt = c.At
		}
		if err := r.InsertManifest(ctx, stored); err != nil {
			return Asset{}, err
		}
	}
	return assetFromRow(row), nil
}

// RecordArtifact registers (or re-registers) a derived object. An object key that already belongs
// to a different asset is not taken over.
func (r *Repos) RecordArtifact(ctx context.Context, a Artifact) error {
	aid, err := requirePG(a.AssetID)
	if err != nil {
		return err
	}
	if a.Variant == "" {
		a.Variant = VariantOriginal
	}
	if !a.Kind.Valid() || !validVariant(a.Variant) || (a.Bucket != "source" && a.Bucket != "delivery") || a.ObjectKey == "" ||
		a.SizeBytes < 0 || len(a.SHA256) != 32 {
		return errs.New(errs.InternalError, "An internal error occurred.")
	}
	return mapError(r.q.UpsertAssetArtifact(ctx, dbgen.UpsertAssetArtifactParams{
		AssetID: aid, Kind: string(a.Kind), Rendition: strPtr(a.Rendition), Bucket: a.Bucket,
		ObjectKey: a.ObjectKey, SizeBytes: a.SizeBytes, Sha256: a.SHA256, Variant: a.Variant,
	}))
}

// ListArtifacts returns every registered artifact of the asset, ordered by bucket and key.
func (r *Repos) ListArtifacts(ctx context.Context, assetID id.AssetID) ([]Artifact, error) {
	aid, err := requirePG(assetID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListAssetArtifacts(ctx, aid)
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]Artifact, len(rows))
	for i, row := range rows {
		out[i] = Artifact{
			AssetID: assetID, Kind: ArtifactKind(row.Kind), Rendition: strVal(row.Rendition), Bucket: row.Bucket,
			ObjectKey: row.ObjectKey, SizeBytes: row.SizeBytes, SHA256: row.Sha256, Variant: row.Variant, CreatedAt: row.CreatedAt.UTC(),
		}
	}
	return out, nil
}

// DeleteHLSArtifacts removes the playlist, init segment and media segment rows of one variant of the
// asset (what the processing job, or the masking job for "masked", produces again on a retry; a
// poster is kept) and returns how many there were. The objects themselves are the caller's to delete.
func (r *Repos) DeleteHLSArtifacts(ctx context.Context, assetID id.AssetID, variant string) (int64, error) {
	aid, err := requirePG(assetID)
	if err != nil {
		return 0, err
	}
	if !validVariant(variant) {
		return 0, errs.New(errs.InvalidRequest, "invalid variant")
	}
	n, err := r.q.DeleteAssetHLSArtifacts(ctx, dbgen.DeleteAssetHLSArtifactsParams{AssetID: aid, Variant: variant})
	return n, mapError(err)
}

// Masking states of an asset created with mask_faces (ADR 0036).
const (
	MaskingPending = "pending"
	MaskingReady   = "ready"
	MaskingFailed  = "failed"
)

// SetAssetMasking records the state of the asset's masked variant and, when known, the number of
// faces found (nil leaves it unknown). It is not_found for another tenant's asset and for one
// created without mask_faces.
func (r *Repos) SetAssetMasking(ctx context.Context, tenantID id.TenantID, assetID id.AssetID, state string, facesDetected *int, at time.Time) (Asset, error) {
	tid, aid, err := assetKeys(tenantID, assetID)
	if err != nil {
		return Asset{}, err
	}
	if state != MaskingPending && state != MaskingReady && state != MaskingFailed {
		return Asset{}, errs.New(errs.InvalidRequest, "invalid masking state")
	}
	var faces *int32
	if facesDetected != nil {
		if *facesDetected < 0 || *facesDetected > math.MaxInt32 {
			return Asset{}, errs.New(errs.InvalidRequest, "invalid faces count")
		}
		n := int32(*facesDetected) //nolint:gosec // range checked above
		faces = &n
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	row, err := r.q.SetAssetMasking(ctx, dbgen.SetAssetMaskingParams{
		MaskingState: state, FacesDetected: faces, At: at, TenantID: tid, ID: aid,
	})
	if err != nil {
		return Asset{}, mapError(err)
	}
	return assetFromRow(row), nil
}
