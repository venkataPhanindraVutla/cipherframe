package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// The four corners a brand logo can sit in (ADR 0049).
const (
	CornerTopLeft     = "top_left"
	CornerTopRight    = "top_right"
	CornerBottomLeft  = "bottom_left"
	CornerBottomRight = "bottom_right"
)

// ValidCorner reports whether c is one of the four corners.
func ValidCorner(c string) bool {
	switch c {
	case CornerTopLeft, CornerTopRight, CornerBottomLeft, CornerBottomRight:
		return true
	}
	return false
}

// Opacity bounds of a brand logo, in percent.
const (
	MinLogoOpacity = 10
	MaxLogoOpacity = 100
)

// LogoVersion is the metadata of one immutable stored logo image (the bytes are at keys.BrandLogo).
type LogoVersion struct {
	ID            id.LogoVersionID
	TenantID      id.TenantID
	SHA256        []byte
	SizeBytes     int
	Width, Height int
	CreatedAt     time.Time
}

// TenantLogo is a tenant's current logo: a version and how it is placed. Enabled says whether new
// assets get it.
type TenantLogo struct {
	LogoVersion
	Corner         string
	OpacityPercent int
	Enabled        bool
	UpdatedAt      time.Time
}

// LogoPin is what one asset is transcoded with, fixed when its first processing job starts. A zero
// VersionID means the asset has no logo.
type LogoPin struct {
	VersionID      id.LogoVersionID
	SHA256         []byte
	Corner         string
	OpacityPercent int
}

// HasLogo reports whether the asset is transcoded with a logo.
func (p LogoPin) HasLogo() bool { return !p.VersionID.IsZero() }

func validPlacement(corner string, opacity int) error {
	if !ValidCorner(corner) || opacity < MinLogoOpacity || opacity > MaxLogoOpacity {
		return errs.New(errs.InternalError, "An internal error occurred.")
	}
	return nil
}

// LockBrand holds the tenant's brand lock until the transaction ends. Logo writes, the removal of
// old versions and the pinning of an asset all take it, so a version an asset is about to pin cannot
// be removed under it.
func (r *Repos) LockBrand(ctx context.Context, tenantID id.TenantID) error {
	if tenantID.IsZero() {
		return errs.New(errs.InvalidRequest, "a required identifier is missing")
	}
	return mapError(r.q.LockBrand(ctx, "cipherframe.brand:"+tenantID.String()))
}

// InsertLogoVersion stores the metadata of a new version.
func (r *Repos) InsertLogoVersion(ctx context.Context, v LogoVersion) error {
	vid, err := requirePG(v.ID)
	if err != nil {
		return err
	}
	tid, err := requirePG(v.TenantID)
	if err != nil {
		return err
	}
	_, err = r.q.InsertLogoVersion(ctx, dbgen.InsertLogoVersionParams{
		ID: vid, TenantID: tid, Sha256: v.SHA256, SizeBytes: int32(v.SizeBytes), //nolint:gosec // bounded by the table's checks
		Width: int32(v.Width), Height: int32(v.Height), CreatedAt: v.CreatedAt.UTC(), //nolint:gosec // bounded by the table's checks
	})
	return mapError(err)
}

// GetTenantLogo returns the tenant's current logo, or not_found when it has none.
func (r *Repos) GetTenantLogo(ctx context.Context, tenantID id.TenantID) (TenantLogo, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return TenantLogo{}, err
	}
	row, err := r.q.GetTenantLogo(ctx, tid)
	if err != nil {
		return TenantLogo{}, mapError(err)
	}
	return TenantLogo{
		LogoVersion: LogoVersion{
			ID: fromPG[id.LogoVersionKind](row.VersionID), TenantID: tenantID, SHA256: row.Sha256,
			SizeBytes: int(row.SizeBytes), Width: int(row.Width), Height: int(row.Height), CreatedAt: row.VersionCreatedAt.UTC(),
		},
		Corner: row.Corner, OpacityPercent: int(row.OpacityPercent), Enabled: row.Enabled, UpdatedAt: row.UpdatedAt.UTC(),
	}, nil
}

// SetTenantLogo makes version the tenant's current logo with the given placement.
func (r *Repos) SetTenantLogo(ctx context.Context, tenantID id.TenantID, version id.LogoVersionID, corner string, opacity int, enabled bool, at time.Time) error {
	tid, err := requirePG(tenantID)
	if err != nil {
		return err
	}
	vid, err := requirePG(version)
	if err != nil {
		return err
	}
	if err := validPlacement(corner, opacity); err != nil {
		return err
	}
	return mapError(r.q.UpsertTenantLogo(ctx, dbgen.UpsertTenantLogoParams{
		TenantID: tid, VersionID: vid, Corner: corner, OpacityPercent: int32(opacity), Enabled: enabled, UpdatedAt: at.UTC(), //nolint:gosec // 10 to 100
	}))
}

// UpdateTenantLogoPlacement changes the current logo's placement and enabled flag. It is not_found
// when the tenant has no logo.
func (r *Repos) UpdateTenantLogoPlacement(ctx context.Context, tenantID id.TenantID, corner string, opacity int, enabled bool, at time.Time) error {
	tid, err := requirePG(tenantID)
	if err != nil {
		return err
	}
	if err := validPlacement(corner, opacity); err != nil {
		return err
	}
	n, err := r.q.UpdateTenantLogoPlacement(ctx, dbgen.UpdateTenantLogoPlacementParams{
		TenantID: tid, Corner: corner, OpacityPercent: int32(opacity), Enabled: enabled, UpdatedAt: at.UTC(), //nolint:gosec // 10 to 100
	})
	if err != nil {
		return mapError(err)
	}
	if n == 0 {
		return errs.New(errs.NotFound, "The tenant has no brand logo.")
	}
	return nil
}

// DeleteTenantLogo removes the current logo setting (not the stored versions) and reports whether
// there was one.
func (r *Repos) DeleteTenantLogo(ctx context.Context, tenantID id.TenantID) (bool, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return false, err
	}
	n, err := r.q.DeleteTenantLogo(ctx, tid)
	return n > 0, mapError(err)
}

// ListUnusedLogoVersions returns the versions that may be removed: not current, and not needed by an
// asset that is still being processed or masked. Call it under LockBrand.
func (r *Repos) ListUnusedLogoVersions(ctx context.Context, tenantID id.TenantID) ([]id.LogoVersionID, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListUnusedLogoVersions(ctx, tid)
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]id.LogoVersionID, len(rows))
	for i, row := range rows {
		out[i] = fromPG[id.LogoVersionKind](row)
	}
	return out, nil
}

// DeleteLogoVersion removes one version's metadata row.
func (r *Repos) DeleteLogoVersion(ctx context.Context, tenantID id.TenantID, version id.LogoVersionID) error {
	tid, err := requirePG(tenantID)
	if err != nil {
		return err
	}
	vid, err := requirePG(version)
	if err != nil {
		return err
	}
	_, err = r.q.DeleteLogoVersion(ctx, dbgen.DeleteLogoVersionParams{TenantID: tid, ID: vid})
	return mapError(err)
}

func pinFromRow(row dbgen.AssetLogoPin) LogoPin {
	pin := LogoPin{VersionID: fromPG[id.LogoVersionKind](row.VersionID), SHA256: row.Sha256}
	if row.Corner != nil {
		pin.Corner = *row.Corner
	}
	if row.OpacityPercent != nil {
		pin.OpacityPercent = int(*row.OpacityPercent)
	}
	return pin
}

// PinAssetLogo fixes what the asset is transcoded with, from the tenant's current logo, unless an
// earlier call already did, and returns the pin. Call it under LockBrand in one transaction.
func (r *Repos) PinAssetLogo(ctx context.Context, tenantID id.TenantID, assetID id.AssetID, at time.Time) (LogoPin, error) {
	tid, aid, err := assetKeys(tenantID, assetID)
	if err != nil {
		return LogoPin{}, err
	}
	if err := r.q.PinAssetLogo(ctx, dbgen.PinAssetLogoParams{At: at.UTC(), TenantID: tid, AssetID: aid}); err != nil {
		return LogoPin{}, mapError(err)
	}
	row, err := r.q.GetAssetLogoPin(ctx, dbgen.GetAssetLogoPinParams{TenantID: tid, AssetID: aid})
	if errors.Is(err, pgx.ErrNoRows) {
		return LogoPin{}, errs.New(errs.NotFound, "No such asset.")
	}
	if err != nil {
		return LogoPin{}, mapError(err)
	}
	return pinFromRow(row), nil
}

// GetAssetLogoPin returns the asset's pin; ok is false while the asset has not been pinned.
func (r *Repos) GetAssetLogoPin(ctx context.Context, tenantID id.TenantID, assetID id.AssetID) (LogoPin, bool, error) {
	tid, aid, err := assetKeys(tenantID, assetID)
	if err != nil {
		return LogoPin{}, false, err
	}
	row, err := r.q.GetAssetLogoPin(ctx, dbgen.GetAssetLogoPinParams{TenantID: tid, AssetID: aid})
	if errors.Is(err, pgx.ErrNoRows) {
		return LogoPin{}, false, nil
	}
	if err != nil {
		return LogoPin{}, false, mapError(err)
	}
	return pinFromRow(row), true, nil
}
