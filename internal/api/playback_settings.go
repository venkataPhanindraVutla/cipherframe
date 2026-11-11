package api

import (
	"context"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

// settingsOut converts settings field by field. updated_at is absent while the defaults apply.
func settingsOut(s db.PlaybackSettings) gen.PlaybackSettings {
	out := gen.PlaybackSettings{
		TokenTtlSeconds:          s.TokenTTLSeconds,
		HeartbeatIntervalSeconds: s.HeartbeatIntervalSeconds,
		IdleTimeoutSeconds:       s.IdleTimeoutSeconds,
		SessionMaxSeconds:        s.SessionMaxSeconds,
		MaxSessionsPerViewer:     s.MaxSessionsPerViewer,
		KeyFetchesPerToken:       s.KeyFetchesPerToken,
		KeyRequestsPerMinute:     s.KeyRequestsPerMinute,
		AllowedOrigins:           append([]string{}, s.AllowedOrigins...),
		TokenInUrl:               s.TokenInURL,
	}
	if !s.UpdatedAt.IsZero() {
		t := s.UpdatedAt
		out.UpdatedAt = &t
	}
	return out
}

// settingsIn converts a PUT body. Every field is required; each missing one is a field error, and
// no other validation runs until none is missing (the zero value of a missing field would only
// produce misleading range errors).
func settingsIn(b *gen.PlaybackSettingsInput) (db.PlaybackSettings, error) {
	var missing []errs.FieldError
	need := func(name string, present bool) {
		if !present {
			missing = append(missing, errs.FieldError{Field: name, Message: "is required"})
		}
	}
	num := func(name string, p *int) int {
		need(name, p != nil)
		if p == nil {
			return 0
		}
		return *p
	}
	out := db.PlaybackSettings{
		TokenTTLSeconds:          num("token_ttl_seconds", b.TokenTtlSeconds),
		HeartbeatIntervalSeconds: num("heartbeat_interval_seconds", b.HeartbeatIntervalSeconds),
		IdleTimeoutSeconds:       num("idle_timeout_seconds", b.IdleTimeoutSeconds),
		SessionMaxSeconds:        num("session_max_seconds", b.SessionMaxSeconds),
		MaxSessionsPerViewer:     num("max_sessions_per_viewer", b.MaxSessionsPerViewer),
		KeyFetchesPerToken:       num("key_fetches_per_token", b.KeyFetchesPerToken),
		KeyRequestsPerMinute:     num("key_requests_per_minute", b.KeyRequestsPerMinute),
	}
	need("allowed_origins", b.AllowedOrigins != nil)
	if b.AllowedOrigins != nil {
		out.AllowedOrigins = *b.AllowedOrigins
	}
	need("token_in_url", b.TokenInUrl != nil)
	if b.TokenInUrl != nil {
		out.TokenInURL = *b.TokenInUrl
	}
	if len(missing) > 0 {
		return db.PlaybackSettings{}, errs.Invalid("The playback settings are incomplete.", missing)
	}
	return out, nil
}

// GetPlaybackSettings returns the caller's tenant's effective playback settings.
func (s *server) GetPlaybackSettings(ctx context.Context, _ gen.GetPlaybackSettingsRequestObject) (gen.GetPlaybackSettingsResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.playbackService()
	if err != nil {
		return nil, err
	}
	set, err := svc.GetSettings(ctx, p.TenantID)
	if err != nil {
		return nil, err
	}
	return gen.GetPlaybackSettings200JSONResponse{Body: settingsOut(set), Headers: gen.GetPlaybackSettings200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// UpdatePlaybackSettings replaces every playback setting of the caller's tenant.
func (s *server) UpdatePlaybackSettings(ctx context.Context, req gen.UpdatePlaybackSettingsRequestObject) (gen.UpdatePlaybackSettingsResponseObject, error) {
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
	in, err := settingsIn(req.Body)
	if err != nil {
		return nil, err
	}
	set, err := svc.PutSettings(ctx, p.TenantID, actor, in)
	if err != nil {
		return nil, err
	}
	return gen.UpdatePlaybackSettings200JSONResponse{Body: settingsOut(set), Headers: gen.UpdatePlaybackSettings200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}
