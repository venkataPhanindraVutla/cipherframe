package api

import (
	"context"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/overlay"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
)

func overlaySettingsOut(s db.OverlaySettings) gen.OverlaySettings {
	out := gen.OverlaySettings{
		Enabled: s.Enabled, Template: s.Template, Opacity: s.Opacity, FontSizeFraction: s.FontSizeFraction, Color: s.Color,
	}
	if !s.UpdatedAt.IsZero() {
		t := s.UpdatedAt
		out.UpdatedAt = &t
	}
	return out
}

// overlaySettingsIn converts a PUT body; each missing field is a field error. The values are
// validated by the service.
func overlaySettingsIn(b *gen.OverlaySettingsInput) (db.OverlaySettings, error) {
	var missing []errs.FieldError
	need := func(name string, present bool) {
		if !present {
			missing = append(missing, errs.FieldError{Field: name, Message: "is required"})
		}
	}
	need("enabled", b.Enabled != nil)
	need("template", b.Template != nil)
	need("opacity", b.Opacity != nil)
	need("font_size_fraction", b.FontSizeFraction != nil)
	need("color", b.Color != nil)
	if len(missing) > 0 {
		return db.OverlaySettings{}, errs.Invalid("The overlay settings are incomplete.", missing)
	}
	return db.OverlaySettings{
		Enabled: *b.Enabled, Template: *b.Template, Opacity: *b.Opacity, FontSizeFraction: *b.FontSizeFraction, Color: *b.Color,
	}, nil
}

// GetOverlaySettings returns the caller's tenant's effective overlay settings.
func (s *server) GetOverlaySettings(ctx context.Context, _ gen.GetOverlaySettingsRequestObject) (gen.GetOverlaySettingsResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.playbackService()
	if err != nil {
		return nil, err
	}
	set, err := svc.GetOverlaySettings(ctx, p.TenantID)
	if err != nil {
		return nil, err
	}
	return gen.GetOverlaySettings200JSONResponse{Body: overlaySettingsOut(set), Headers: gen.GetOverlaySettings200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// UpdateOverlaySettings replaces every overlay setting of the caller's tenant.
func (s *server) UpdateOverlaySettings(ctx context.Context, req gen.UpdateOverlaySettingsRequestObject) (gen.UpdateOverlaySettingsResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.playbackService()
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errs.New(errs.InvalidRequest, "A request body is required.")
	}
	in, err := overlaySettingsIn(req.Body)
	if err != nil {
		return nil, err
	}
	set, err := svc.PutOverlaySettings(ctx, p.TenantID, actor, in)
	if err != nil {
		return nil, err
	}
	return gen.UpdateOverlaySettings200JSONResponse{Body: overlaySettingsOut(set), Headers: gen.UpdateOverlaySettings200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// LookupOverlayCode maps an overlay code back to the caller's tenant's sessions.
func (s *server) LookupOverlayCode(ctx context.Context, req gen.LookupOverlayCodeRequestObject) (gen.LookupOverlayCodeResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.playbackService()
	if err != nil {
		return nil, err
	}
	matches, err := svc.FindOverlayCode(ctx, p.TenantID, req.Code)
	if err != nil {
		return nil, err
	}
	out := gen.OverlayCodeLookup{Sessions: make([]gen.OverlayCodeSession, len(matches))}
	for i, m := range matches {
		out.Sessions[i] = gen.OverlayCodeSession{
			AssetId: m.AssetID.String(), ViewerId: m.ViewerID, AuthMethod: gen.OverlayCodeSessionAuthMethod(m.AuthMethod),
			State: gen.OverlayCodeSessionState(m.State), CreatedAt: m.CreatedAt, SessionFingerprint: m.SessionFingerprint,
		}
	}
	return gen.LookupOverlayCode200JSONResponse{Body: out, Headers: gen.LookupOverlayCode200ResponseHeaders{CacheControl: noStore, XRequestId: requestID(ctx)}}, nil
}

// overlayOut is the overlay member of a session response; nil when the tenant has it off.
func overlayOut(o *playback.Overlay) *gen.PlaybackOverlay {
	if o == nil {
		return nil
	}
	out := &gen.PlaybackOverlay{Template: o.Template, SessionCode: o.SessionCode}
	out.Style.Opacity, out.Style.FontSizeFraction, out.Style.Color = o.Opacity, o.FontSizeFraction, o.Color
	out.Drift.Algorithm, out.Drift.Seed = overlay.Algorithm, o.Seed
	out.Drift.PeriodSeconds, out.Drift.Margin = overlay.PeriodSeconds, overlay.Margin
	return out
}
