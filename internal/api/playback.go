package api

import (
	"context"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// playbackService returns the playback service, or dependency_unavailable when the process runs
// without one.
func (s *server) playbackService() (*playback.Service, error) {
	if s.playback == nil {
		return nil, errs.New(errs.DependencyUnavailable, "Playback is not available.")
	}
	return s.playback, nil
}

// CreatePlaybackSession starts a playback session on a ready asset of the caller's tenant. The
// response holds the playback token and, when the tenant opted in, a manifest URL that carries it,
// so it is never cached and nothing in it is logged.
func (s *server) CreatePlaybackSession(ctx context.Context, req gen.CreatePlaybackSessionRequestObject) (gen.CreatePlaybackSessionResponseObject, error) {
	p, _, err := caller(ctx)
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
	aid, err := id.Parse[id.AssetKind](req.Body.AssetId)
	if err != nil {
		return nil, errs.Invalid("The request is invalid.", []errs.FieldError{{Field: "asset_id", Message: "must be an asset ID"}})
	}
	in := playback.CreateInput{TenantID: p.TenantID, ClientID: p.ClientID, AssetID: aid, ViewerID: req.Body.ViewerId}
	if req.Body.Variant != nil {
		in.Variant = keys.Variant(*req.Body.Variant)
	}
	c, err := svc.CreateSession(ctx, in)
	if err != nil {
		return nil, err
	}
	return gen.CreatePlaybackSession201JSONResponse{
		Body: gen.CreatedPlaybackSession{
			SessionId:                c.SessionID.String(),
			Variant:                  gen.Variant(c.Variant),
			Token:                    c.Token.Reveal(),
			TokenExpiresAt:           c.TokenExpiresAt,
			HeartbeatIntervalSeconds: c.HeartbeatIntervalSeconds,
			SessionExpiresAt:         c.SessionExpiresAt,
			ManifestUrl:              c.ManifestURL.Reveal(),
			TokenTransport:           gen.CreatedPlaybackSessionTokenTransport(c.TokenTransport),
		},
		Headers: gen.CreatePlaybackSession201ResponseHeaders{CacheControl: noStore, XRequestId: requestID(ctx)},
	}, nil
}
