package db

import (
	"context"
	"errors"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// ErrManifestChanged is returned by ReplaceManifest when the stored manifest is not the one the
// replacement was built from. The caller reads the manifest again and rebuilds.
var ErrManifestChanged = errors.New("db: the manifest changed since it was read")

// Origins of a subtitle track.
const (
	SubtitleUpload = "upload"
	SubtitleImport = "import"
)

// Subtitle is a row of asset_subtitles (ADR 0044): the metadata of one WebVTT track. The track's
// bytes are in the delivery bucket at keys.Subtitle and registered in asset_artifacts.
type Subtitle struct {
	ID         id.SubtitleID
	AssetID    id.AssetID
	TenantID   id.TenantID
	Language   string // BCP 47
	Label      string
	Default    bool
	Origin     string
	CueCount   int
	DurationMS int64 // the asset's duration when the track was added
	SizeBytes  int64
	SHA256     []byte
	CreatedAt  time.Time
}

func subtitleFromRow(r dbgen.AssetSubtitle) Subtitle {
	return Subtitle{
		ID: fromPG[id.SubtitleKind](r.ID), AssetID: fromPG[id.AssetKind](r.AssetID), TenantID: fromPG[id.TenantKind](r.TenantID),
		Language: r.Language, Label: r.Label, Default: r.IsDefault, Origin: r.Origin, CueCount: int(r.CueCount),
		DurationMS: r.DurationMs, SizeBytes: r.SizeBytes, SHA256: r.Sha256, CreatedAt: r.CreatedAt.UTC(),
	}
}

// InsertSubtitle stores a track. A track that is the default takes the flag from the asset's
// current default, so call it in the transaction that holds the asset lock (LockAsset).
func (r *Repos) InsertSubtitle(ctx context.Context, s Subtitle) (Subtitle, error) {
	tid, aid, err := assetKeys(s.TenantID, s.AssetID)
	if err != nil {
		return Subtitle{}, err
	}
	sid, err := requirePG(s.ID)
	if err != nil {
		return Subtitle{}, err
	}
	if (s.Origin != SubtitleUpload && s.Origin != SubtitleImport) || s.CueCount < 1 || s.CueCount > 1<<30 ||
		s.DurationMS < 1 || s.SizeBytes < 1 || len(s.SHA256) != 32 || s.Language == "" || s.Label == "" {
		return Subtitle{}, errs.New(errs.InternalError, "An internal error occurred.")
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now()
	}
	if s.Default {
		if err := r.q.ClearAssetSubtitleDefault(ctx, aid); err != nil {
			return Subtitle{}, mapError(err)
		}
	}
	row, err := r.q.InsertAssetSubtitle(ctx, dbgen.InsertAssetSubtitleParams{
		ID: sid, AssetID: aid, TenantID: tid, Language: s.Language, Label: s.Label, IsDefault: s.Default,
		Origin: s.Origin, CueCount: int32(s.CueCount), //nolint:gosec // range checked above
		DurationMs: s.DurationMS, SizeBytes: s.SizeBytes, Sha256: s.SHA256, CreatedAt: s.CreatedAt.UTC(),
	})
	if err != nil {
		return Subtitle{}, mapError(err)
	}
	return subtitleFromRow(row), nil
}

// ListSubtitles returns the tenant's asset's tracks in creation order (no tracks is an empty list,
// also for another tenant's asset).
func (r *Repos) ListSubtitles(ctx context.Context, tenantID id.TenantID, assetID id.AssetID) ([]Subtitle, error) {
	tid, aid, err := assetKeys(tenantID, assetID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListAssetSubtitles(ctx, dbgen.ListAssetSubtitlesParams{TenantID: tid, AssetID: aid})
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]Subtitle, len(rows))
	for i, row := range rows {
		out[i] = subtitleFromRow(row)
	}
	return out, nil
}

// GetSubtitle returns one track, or not_found (also for another tenant's or asset's).
func (r *Repos) GetSubtitle(ctx context.Context, tenantID id.TenantID, assetID id.AssetID, trackID id.SubtitleID) (Subtitle, error) {
	tid, aid, err := assetKeys(tenantID, assetID)
	if err != nil {
		return Subtitle{}, err
	}
	sid, err := requirePG(trackID)
	if err != nil {
		return Subtitle{}, err
	}
	row, err := r.q.GetAssetSubtitle(ctx, dbgen.GetAssetSubtitleParams{TenantID: tid, AssetID: aid, ID: sid})
	if err != nil {
		return Subtitle{}, mapError(err)
	}
	return subtitleFromRow(row), nil
}

// DeleteSubtitle removes one track's row and reports whether there was one.
func (r *Repos) DeleteSubtitle(ctx context.Context, tenantID id.TenantID, assetID id.AssetID, trackID id.SubtitleID) (bool, error) {
	tid, aid, err := assetKeys(tenantID, assetID)
	if err != nil {
		return false, err
	}
	sid, err := requirePG(trackID)
	if err != nil {
		return false, err
	}
	n, err := r.q.DeleteAssetSubtitle(ctx, dbgen.DeleteAssetSubtitleParams{TenantID: tid, AssetID: aid, ID: sid})
	return n > 0, mapError(err)
}

// DeleteAssetSubtitles removes every track row of the asset (the purge).
func (r *Repos) DeleteAssetSubtitles(ctx context.Context, assetID id.AssetID) (int64, error) {
	aid, err := requirePG(assetID)
	if err != nil {
		return 0, err
	}
	n, err := r.q.DeleteAssetSubtitles(ctx, aid)
	return n, mapError(err)
}

// DeleteArtifact removes the registry row of one object.
func (r *Repos) DeleteArtifact(ctx context.Context, assetID id.AssetID, bucket, objectKey string) error {
	aid, err := requirePG(assetID)
	if err != nil {
		return err
	}
	_, err = r.q.DeleteAssetArtifactByKey(ctx, dbgen.DeleteAssetArtifactByKeyParams{AssetID: aid, Bucket: bucket, ObjectKey: objectKey})
	return mapError(err)
}

// ReplaceManifest swaps the asset's manifest for m (re-signed, same asset) in the caller's
// transaction: the old row, and with it its timestamp token, goes. base is the payload hash of the
// manifest m was built from; if the stored manifest no longer has it, ErrManifestChanged is
// returned and nothing changes, so a re-sign never drops what another writer added meanwhile.
func (r *Repos) ReplaceManifest(ctx context.Context, m AssetManifest, base []byte) error {
	cur, err := r.GetManifest(ctx, m.AssetID)
	if err != nil {
		return err
	}
	if string(cur.PayloadSHA256) != string(base) {
		return ErrManifestChanged
	}
	if _, err := r.DeleteManifest(ctx, m.AssetID); err != nil {
		return err
	}
	return r.InsertManifest(ctx, m)
}
