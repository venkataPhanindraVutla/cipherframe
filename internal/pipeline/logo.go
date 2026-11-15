package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/venkataPhanindraVutla/cipherframe/internal/branding"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// FailureLogoUnavailable: the logo the asset was pinned to cannot be used any more (its object is
// gone or is not the file that was hashed). Retrying cannot help, and publishing the asset without
// its logo would break the promise that every asset of the tenant carries it.
const FailureLogoUnavailable = "logo_unavailable"

// logoFile is the raw RGBA file inside the job's private directory.
const logoFile = "logo.rgba"

// jobLogo is the brand logo of one job: what to hand to FFmpeg and what to record in the manifest.
type jobLogo struct {
	spec     *media.LogoSpec
	manifest *manifest.Logo
}

// pinLogo fixes the asset's logo (ADR 0049) and prepares it for FFmpeg. The first job of an asset to
// get here, the original's or the masked variant's, records the tenant's current logo on the asset
// (db.LogoPin); every later job and every retry reads that record back, so both variants and all
// attempts of one asset use the same version. An asset with no logo gives nil.
//
// The stored PNG is checked against the pinned SHA-256, decoded by Go (branding.Raw) and written as
// raw RGBA into dir, so FFmpeg is never handed a file the tenant influenced.
func (p *Processor) pinLogo(ctx context.Context, asset db.Asset, dir string) (*jobLogo, error) {
	pin, err := p.Repo.PinLogo(ctx, asset.TenantID, asset.ID)
	if err != nil {
		return nil, err
	}
	if !pin.HasLogo() {
		return nil, nil
	}
	rc, _, err := p.Delivery.Get(ctx, keys.BrandLogo(asset.TenantID, pin.VersionID), nil)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, permanent(FailureLogoUnavailable, errors.New("the pinned logo object is missing"))
	}
	if err != nil {
		return nil, fmt.Errorf("pipeline: get the logo: %w", err)
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, branding.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("pipeline: read the logo: %w", err)
	}
	if sum := sha256.Sum256(data); !bytes.Equal(sum[:], pin.SHA256) {
		return nil, permanent(FailureLogoUnavailable, errors.New("the stored logo is not the one that was pinned"))
	}
	pix, w, h, err := branding.Raw(data)
	if err != nil {
		return nil, permanent(FailureLogoUnavailable, errors.New("the stored logo cannot be decoded"))
	}
	path := filepath.Join(dir, logoFile)
	if err := os.WriteFile(path, pix, 0o600); err != nil {
		return nil, fmt.Errorf("pipeline: write the logo: %w", err)
	}
	return &jobLogo{
		spec: &media.LogoSpec{Path: path, Width: w, Height: h, Corner: pin.Corner, OpacityPercent: pin.OpacityPercent},
		manifest: &manifest.Logo{
			SHA256: hex.EncodeToString(pin.SHA256), Version: pin.VersionID.String(), Corner: pin.Corner,
			OpacityPercent: pin.OpacityPercent, WidthPercent: media.LogoWidthPercent,
		},
	}, nil
}

func (l *jobLogo) mediaSpec() *media.LogoSpec {
	if l == nil {
		return nil
	}
	return l.spec
}

func (l *jobLogo) manifestLogo() *manifest.Logo {
	if l == nil {
		return nil
	}
	return l.manifest
}
