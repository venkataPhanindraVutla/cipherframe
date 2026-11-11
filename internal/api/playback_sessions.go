package api

import (
	"context"
	"errors"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
)

// The session IDs of these routes arrive in the path in the clear; the service looks them up by
// their SHA-256 hash, scoped to the caller's tenant. They are never logged and never echoed in an
// error: a malformed one is the same 404 as an unknown one.

func errNoSuchSession() error { return errs.New(errs.NotFound, "No such playback session.") }

func sessionStatusOut(sid string, st playback.SessionStatus) gen.PlaybackSessionStatus {
	out := gen.PlaybackSessionStatus{
		SessionId: sid, AssetId: st.AssetID.String(), ViewerId: st.ViewerID,
		State:     gen.PlaybackSessionStatusState(st.State),
		CreatedAt: st.CreatedAt, LastHeartbeatAt: st.LastHeartbeatAt, SessionExpiresAt: st.SessionExpiresAt,
		EndedAt: st.EndedAt, RevokedAt: st.RevokedAt,
	}
	if st.RevokeReason != "" {
		out.RevokeReason = &st.RevokeReason
	}
	return out
}

// GetPlaybackSession reports the status of one session of the caller's tenant.
func (s *server) GetPlaybackSession(ctx context.Context, req gen.GetPlaybackSessionRequestObject) (gen.GetPlaybackSessionResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.playbackService()
	if err != nil {
		return nil, err
	}
	sid, err := id.ParseSession(req.SessionId)
	if err != nil {
		return nil, errNoSuchSession()
	}
	st, err := svc.GetSession(ctx, p.TenantID, sid)
	if err != nil {
		return nil, notFoundAs(err, errNoSuchSession)
	}
	return gen.GetPlaybackSession200JSONResponse{
		Body: sessionStatusOut(req.SessionId, st), Headers: gen.GetPlaybackSession200ResponseHeaders{XRequestId: requestID(ctx)},
	}, nil
}

// RevokePlaybackSession revokes one session of the caller's tenant.
func (s *server) RevokePlaybackSession(ctx context.Context, req gen.RevokePlaybackSessionRequestObject) (gen.RevokePlaybackSessionResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.playbackService()
	if err != nil {
		return nil, err
	}
	sid, err := id.ParseSession(req.SessionId)
	if err != nil {
		return nil, errNoSuchSession()
	}
	reason := ""
	if req.Body != nil && req.Body.Reason != nil {
		reason = *req.Body.Reason
	}
	st, err := svc.RevokeSession(ctx, p.TenantID, actor, sid, reason)
	if err != nil {
		return nil, notFoundAs(err, errNoSuchSession)
	}
	return gen.RevokePlaybackSession200JSONResponse{
		Body: sessionStatusOut(req.SessionId, st), Headers: gen.RevokePlaybackSession200ResponseHeaders{XRequestId: requestID(ctx)},
	}, nil
}

// RevokePlaybackSessions revokes the caller's active sessions that match a viewer and/or an asset.
func (s *server) RevokePlaybackSessions(ctx context.Context, req gen.RevokePlaybackSessionsRequestObject) (gen.RevokePlaybackSessionsResponseObject, error) {
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
	var asset id.AssetID
	if req.Body.AssetId != nil {
		if asset, err = id.Parse[id.AssetKind](*req.Body.AssetId); err != nil {
			return nil, errs.Invalid("The request is invalid.", []errs.FieldError{{Field: "asset_id", Message: "must be an asset ID"}})
		}
	}
	viewer, reason := "", ""
	if req.Body.ViewerId != nil {
		viewer = *req.Body.ViewerId
		if viewer == "" {
			return nil, errs.Invalid("The request is invalid.", []errs.FieldError{{Field: "viewer_id", Message: "must be 1 to 128 characters"}})
		}
	}
	if req.Body.Reason != nil {
		reason = *req.Body.Reason
	}
	n, err := svc.RevokeSessions(ctx, p.TenantID, actor, viewer, asset, reason)
	if err != nil {
		return nil, err
	}
	return gen.RevokePlaybackSessions200JSONResponse{
		Body: gen.RevokedPlaybackSessions{Revoked: int(n)}, Headers: gen.RevokePlaybackSessions200ResponseHeaders{XRequestId: requestID(ctx)},
	}, nil
}

// notFoundAs replaces a not_found error with mk() (one message, nothing from the cause) and leaves
// every other error as it is.
func notFoundAs(err error, mk func() error) error {
	var e *errs.Error
	if errors.As(err, &e) && e.Code == errs.NotFound {
		return mk()
	}
	return err
}
