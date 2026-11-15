package playback

import (
	"context"
	"strings"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/overlay"
)

// AuditOverlayUpdate is the audit action written when a tenant's overlay settings change.
const AuditOverlayUpdate = "overlay_settings.update"

// Overlay is what a session response carries when the tenant turned the overlay on (ADR 0048).
// It holds nothing about the viewer: the template is the tenant's own static text, with the
// session code already substituted; the player substitutes {date} and {time}.
type Overlay struct {
	Template         string
	SessionCode      string
	Opacity          float64
	FontSizeFraction float64
	Color            string
	// Seed is the drift seed (overlay.Seed); the drift constants are fixed by the algorithm.
	Seed string
}

// newOverlay builds the overlay of a session, or nil when the tenant has it off.
func newOverlay(set db.OverlaySettings, sid id.SessionID, code string) *Overlay {
	if !set.Enabled {
		return nil
	}
	return &Overlay{
		Template: strings.ReplaceAll(set.Template, overlay.PlaceholderCode, code), SessionCode: code,
		Opacity: set.Opacity, FontSizeFraction: set.FontSizeFraction, Color: set.Color, Seed: overlay.Seed(sid),
	}
}

// GetOverlaySettings returns the tenant's effective overlay settings.
func (s *Service) GetOverlaySettings(ctx context.Context, tenantID id.TenantID) (db.OverlaySettings, error) {
	return s.repos.GetOverlaySettings(ctx, tenantID)
}

// PutOverlaySettings validates and replaces the tenant's overlay settings and records an audit
// event. The change applies to sessions created afterwards.
func (s *Service) PutOverlaySettings(ctx context.Context, tenantID id.TenantID, actor auth.Actor, in db.OverlaySettings) (db.OverlaySettings, error) {
	if f := overlay.ValidateSettings(in); len(f) > 0 {
		return db.OverlaySettings{}, errs.Invalid("The overlay settings are invalid.", f)
	}
	var out db.OverlaySettings
	err := db.Tx(ctx, s.pool, func(tx *db.Repos) error {
		var err error
		if out, err = tx.PutOverlaySettings(ctx, tenantID, in, s.now().UTC()); err != nil {
			return err
		}
		_, err = tx.InsertAuditEvent(ctx, db.NewAuditEvent{
			TenantID: tenantID, ClientID: actor.ClientID, APIKeyID: actor.KeyID,
			Action: AuditOverlayUpdate, Target: tenantID.String(), RequestID: actor.RequestID,
		})
		return err
	})
	return out, err
}

// FindOverlayCode maps a leaked overlay code back to the tenant's sessions. A malformed code is
// invalid_request; an unknown one, or one past the retention window, is an empty list.
func (s *Service) FindOverlayCode(ctx context.Context, tenantID id.TenantID, code string) ([]db.OverlayCodeMatch, error) {
	code = strings.ToUpper(strings.TrimSpace(code))
	if !overlay.ValidCode(code) {
		return nil, errs.Invalid("The request is invalid.", []errs.FieldError{{Field: "code", Message: "must be 8 characters from A-Z and 2-9, without I and O"}})
	}
	return s.repos.FindSessionsByOverlayCode(ctx, tenantID, code)
}
