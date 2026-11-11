package api

import (
	"context"
	"encoding/json"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
)

// The admin endpoints of the viewer-authorization providers (ADR 0029, 0031). None of them ever
// returns the callback secret except the rotation, once; none logs a key, a URL or a secret.

func jwtKeyOut(k db.PlaybackJWTKey) gen.PlaybackJwtKey {
	return gen.PlaybackJwtKey{Kid: k.Kid, Alg: gen.PlaybackJwtKeyAlg(k.Alg), CreatedAt: k.CreatedAt}
}

func orNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func authOut(v playback.AuthView) gen.PlaybackAuth {
	c := v.Config
	out := gen.PlaybackAuth{
		JwtEnabled: c.JWTEnabled, JwtIssuer: c.JWTIssuer, JwtAudiences: append([]string{}, c.JWTAudiences...),
		JwtJwksUrl: orNil(c.JWKSURL), JwtViewerClaim: c.JWTViewerClaim, JwtKeys: make([]gen.PlaybackJwtKey, 0, len(v.Keys)),
		CallbackEnabled: c.CallbackEnabled, CallbackUrl: orNil(c.CallbackURL),
		CallbackSecretConfigured: v.SecretConfigured, CallbackSecretVersion: c.CallbackSecretVersion,
		CallbackSecretRotatedAt: c.CallbackSecretRotatedAt, CallbackPreviousSecretValidUntil: v.PreviousSecretValidUntil,
	}
	for _, k := range v.Keys {
		out.JwtKeys = append(out.JwtKeys, jwtKeyOut(k))
	}
	if !c.UpdatedAt.IsZero() {
		t := c.UpdatedAt
		out.UpdatedAt = &t
	}
	return out
}

// authIn converts a PUT body. The two switches are required; every other field left out takes its
// default.
func authIn(b *gen.PlaybackAuthInput) (db.PlaybackAuth, error) {
	var missing []errs.FieldError
	if b.JwtEnabled == nil {
		missing = append(missing, errs.FieldError{Field: "jwt_enabled", Message: "is required"})
	}
	if b.CallbackEnabled == nil {
		missing = append(missing, errs.FieldError{Field: "callback_enabled", Message: "is required"})
	}
	if len(missing) > 0 {
		return db.PlaybackAuth{}, errs.Invalid("The playback authorization settings are incomplete.", missing)
	}
	out := db.PlaybackAuth{JWTEnabled: *b.JwtEnabled, CallbackEnabled: *b.CallbackEnabled, JWTViewerClaim: db.DefaultViewerClaim}
	if b.JwtIssuer != nil {
		out.JWTIssuer = *b.JwtIssuer
	}
	if b.JwtAudiences != nil {
		out.JWTAudiences = *b.JwtAudiences
	}
	if b.JwtJwksUrl != nil {
		out.JWKSURL = *b.JwtJwksUrl
	}
	if b.JwtViewerClaim != nil {
		out.JWTViewerClaim = *b.JwtViewerClaim
	}
	if b.CallbackUrl != nil {
		out.CallbackURL = *b.CallbackUrl
	}
	return out, nil
}

// GetPlaybackAuth returns the caller's tenant's authorization settings.
func (s *server) GetPlaybackAuth(ctx context.Context, _ gen.GetPlaybackAuthRequestObject) (gen.GetPlaybackAuthResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.playbackService()
	if err != nil {
		return nil, err
	}
	v, err := svc.GetAuth(ctx, p.TenantID)
	if err != nil {
		return nil, err
	}
	return gen.GetPlaybackAuth200JSONResponse{Body: authOut(v), Headers: gen.GetPlaybackAuth200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// UpdatePlaybackAuth replaces the caller's tenant's authorization settings.
func (s *server) UpdatePlaybackAuth(ctx context.Context, req gen.UpdatePlaybackAuthRequestObject) (gen.UpdatePlaybackAuthResponseObject, error) {
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
	in, err := authIn(req.Body)
	if err != nil {
		return nil, err
	}
	v, err := svc.PutAuth(ctx, p.TenantID, actor, in)
	if err != nil {
		return nil, err
	}
	return gen.UpdatePlaybackAuth200JSONResponse{Body: authOut(v), Headers: gen.UpdatePlaybackAuth200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// PutPlaybackJwtKey stores a public JWK for the caller's tenant.
func (s *server) PutPlaybackJwtKey(ctx context.Context, req gen.PutPlaybackJwtKeyRequestObject) (gen.PutPlaybackJwtKeyResponseObject, error) {
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
	// The body is the JWK. The generated type keeps members it does not know (a private "d", for
	// one) so the service can refuse them.
	raw, err := json.Marshal(req.Body)
	if err != nil {
		return nil, errs.New(errs.InvalidRequest, "The request body is invalid.")
	}
	k, err := svc.PutJWTKey(ctx, p.TenantID, actor, req.Kid, raw)
	if err != nil {
		return nil, err
	}
	return gen.PutPlaybackJwtKey200JSONResponse{Body: jwtKeyOut(k), Headers: gen.PutPlaybackJwtKey200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// DeletePlaybackJwtKey deletes an uploaded key of the caller's tenant.
func (s *server) DeletePlaybackJwtKey(ctx context.Context, req gen.DeletePlaybackJwtKeyRequestObject) (gen.DeletePlaybackJwtKeyResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.playbackService()
	if err != nil {
		return nil, err
	}
	if err := svc.DeleteJWTKey(ctx, p.TenantID, actor, req.Kid); err != nil {
		return nil, err
	}
	return gen.DeletePlaybackJwtKey204Response{Headers: gen.DeletePlaybackJwtKey204ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// RotatePlaybackCallbackSecret makes a new callback secret and returns it once.
func (s *server) RotatePlaybackCallbackSecret(ctx context.Context, _ gen.RotatePlaybackCallbackSecretRequestObject) (gen.RotatePlaybackCallbackSecretResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.playbackService()
	if err != nil {
		return nil, err
	}
	r, err := svc.RotateCallbackSecret(ctx, p.TenantID, actor)
	if err != nil {
		return nil, err
	}
	return gen.RotatePlaybackCallbackSecret200JSONResponse{
		Body:    gen.RotatedCallbackSecret{Secret: r.Secret.Reveal(), Version: r.Version, PreviousValidUntil: r.PreviousValidUntil},
		Headers: gen.RotatePlaybackCallbackSecret200ResponseHeaders{CacheControl: noStore, XRequestId: requestID(ctx)},
	}, nil
}
