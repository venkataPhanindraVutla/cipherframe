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

// OverlaySettings are a tenant's overlay watermark policy (ADR 0043, 0048). A tenant without a
// stored row uses DefaultOverlaySettings. UpdatedAt is the zero time for the defaults.
type OverlaySettings struct {
	Enabled bool
	// Template uses only {session_code}, {date} and {time}; overlay.ValidateTemplate checks it.
	Template string
	// Opacity is in [0.05, 0.8]; FontSizeFraction is the text height as a fraction of the video
	// height; Color is #RRGGBB in upper case.
	Opacity          float64
	FontSizeFraction float64
	Color            string
	UpdatedAt        time.Time
}

// DefaultOverlaySettings is off, with a subtle default style.
func DefaultOverlaySettings() OverlaySettings {
	return OverlaySettings{Template: "{session_code} {date} {time} UTC", Opacity: 0.25, FontSizeFraction: 0.03, Color: "#FFFFFF"}
}

func overlayFromRow(r dbgen.OverlaySetting) OverlaySettings {
	return OverlaySettings{
		Enabled: r.Enabled, Template: r.Template, Opacity: r.Opacity, FontSizeFraction: r.FontSizeFraction,
		Color: r.Color, UpdatedAt: r.UpdatedAt.UTC(),
	}
}

// GetOverlaySettings returns the tenant's overlay settings, or the defaults when none are stored.
func (r *Repos) GetOverlaySettings(ctx context.Context, tenantID id.TenantID) (OverlaySettings, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return OverlaySettings{}, err
	}
	row, err := r.q.GetOverlaySettings(ctx, tid)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultOverlaySettings(), nil
	}
	if err != nil {
		return OverlaySettings{}, mapError(err)
	}
	return overlayFromRow(row), nil
}

// PutOverlaySettings replaces the tenant's overlay settings.
func (r *Repos) PutOverlaySettings(ctx context.Context, tenantID id.TenantID, s OverlaySettings, at time.Time) (OverlaySettings, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return OverlaySettings{}, err
	}
	row, err := r.q.UpsertOverlaySettings(ctx, dbgen.UpsertOverlaySettingsParams{
		TenantID: tid, Enabled: s.Enabled, Template: s.Template, Opacity: s.Opacity,
		FontSizeFraction: s.FontSizeFraction, Color: s.Color, At: at,
	})
	if err != nil {
		return OverlaySettings{}, mapError(err)
	}
	return overlayFromRow(row), nil
}

// OverlayCodeMatch is a session found by its overlay code.
type OverlayCodeMatch struct {
	AssetID    id.AssetID
	ViewerID   string
	AuthMethod string
	State      string
	CreatedAt  time.Time
	// SessionFingerprint is the one the access trail shows on every row of the session.
	SessionFingerprint string
}

// FindSessionsByOverlayCode returns the tenant's sessions with the code, newest first (at most
// 20; a code is 40 bits, so a second match is rare but possible).
func (r *Repos) FindSessionsByOverlayCode(ctx context.Context, tenantID id.TenantID, code string) ([]OverlayCodeMatch, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.FindSessionsByOverlayCode(ctx, dbgen.FindSessionsByOverlayCodeParams{TenantID: tid, Code: code})
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]OverlayCodeMatch, len(rows))
	for i, x := range rows {
		out[i] = OverlayCodeMatch{
			AssetID: fromPG[id.AssetKind](x.AssetID), ViewerID: x.ViewerID, AuthMethod: x.AuthMethod, State: x.State,
			CreatedAt: x.CreatedAt.UTC(), SessionFingerprint: x.SessionFingerprint,
		}
	}
	return out, nil
}

// ClearOverlayCodesBefore forgets the overlay code of up to batch sessions created before cutoff
// and returns how many it cleared. Call it until it returns less than batch.
func (r *Repos) ClearOverlayCodesBefore(ctx context.Context, cutoff time.Time, batch int) (int64, error) {
	if batch < 1 {
		return 0, errs.New(errs.InvalidRequest, "invalid batch size")
	}
	n, err := r.q.ClearOverlayCodesBefore(ctx, dbgen.ClearOverlayCodesBeforeParams{Cutoff: cutoff.UTC(), Batch: int32(batch)}) //nolint:gosec // bounded by the caller
	return n, mapError(err)
}
