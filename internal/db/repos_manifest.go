package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// AssetManifest is a row of asset_manifests (ADR 0033): the signed integrity manifest of a ready
// asset. Envelope is the DSSE envelope as JSON; it holds no secret.
type AssetManifest struct {
	AssetID       id.AssetID
	TenantID      id.TenantID
	KeyID         string
	PayloadSHA256 []byte // SHA-256 of the decoded payload
	TopRoot       []byte // the top-level Merkle root named in the manifest
	Envelope      []byte
	CreatedAt     time.Time
}

func (m AssetManifest) valid() bool {
	return m.KeyID != "" && len(m.PayloadSHA256) == 32 && len(m.TopRoot) == 32 && json.Valid(m.Envelope)
}

// InsertManifest stores the manifest of an asset. It is a plain INSERT: a second manifest for the
// same asset is a bug and fails with a conflict. Call it in the transaction that completes the
// asset (see CompleteProcessing).
func (r *Repos) InsertManifest(ctx context.Context, m AssetManifest) error {
	tid, aid, err := assetKeys(m.TenantID, m.AssetID)
	if err != nil {
		return err
	}
	if !m.valid() {
		return errs.New(errs.InternalError, "An internal error occurred.")
	}
	if m.CreatedAt.IsZero() {
		m.CreatedAt = time.Now()
	}
	return mapError(r.q.InsertAssetManifest(ctx, dbgen.InsertAssetManifestParams{
		AssetID: aid, TenantID: tid, KeyID: m.KeyID, PayloadSha256: m.PayloadSHA256, TopRoot: m.TopRoot,
		Envelope: m.Envelope, CreatedAt: m.CreatedAt.UTC(),
	}))
}

// GetManifest returns the manifest of the asset, or a not-found error.
func (r *Repos) GetManifest(ctx context.Context, assetID id.AssetID) (AssetManifest, error) {
	aid, err := requirePG(assetID)
	if err != nil {
		return AssetManifest{}, err
	}
	row, err := r.q.GetAssetManifest(ctx, aid)
	if err != nil {
		return AssetManifest{}, mapError(err)
	}
	return AssetManifest{
		AssetID: assetID, TenantID: fromPG[id.TenantKind](row.TenantID), KeyID: row.KeyID,
		PayloadSHA256: row.PayloadSha256, TopRoot: row.TopRoot, Envelope: row.Envelope, CreatedAt: row.CreatedAt.UTC(),
	}, nil
}

// DeleteManifest removes the asset's manifest and reports whether there was one. A processing
// retry calls it before it builds a new manifest.
func (r *Repos) DeleteManifest(ctx context.Context, assetID id.AssetID) (bool, error) {
	aid, err := requirePG(assetID)
	if err != nil {
		return false, err
	}
	n, err := r.q.DeleteAssetManifest(ctx, aid)
	return n > 0, mapError(err)
}

// ArtifactMatch is a registered HLS object found by its hash. ObjectKey is a storage key: it
// locates the object inside the delivery bucket and must not leave the server.
type ArtifactMatch struct {
	AssetID   id.AssetID
	Variant   string
	ObjectKey string
}

// FindArtifactsBySHA256 returns up to 20 HLS objects of the tenant's ready assets whose stored
// bytes hash to sum, oldest first.
func (r *Repos) FindArtifactsBySHA256(ctx context.Context, tenantID id.TenantID, sum []byte) ([]ArtifactMatch, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.FindTenantArtifactsBySHA256(ctx, dbgen.FindTenantArtifactsBySHA256Params{TenantID: tid, Sha256: sum})
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]ArtifactMatch, len(rows))
	for i, row := range rows {
		out[i] = ArtifactMatch{AssetID: fromPG[id.AssetKind](row.AssetID), Variant: row.Variant, ObjectKey: row.ObjectKey}
	}
	return out, nil
}
