package edge

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/httpx"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
)

// The session lifecycle routes (ADR 0028): heartbeat and end.
//
// Both go through the playback guard like the playlists (token, transport, CORS, tenant settings)
// but skip its session-row read (authorizeStateless): each one enforces the session's state inside
// the single statement that changes it, so there is no window between "checked" and "updated".
//
// Edge signs the tokens a heartbeat returns. That adds no exposure: the symmetric HMAC key already
// lives in edge, which verifies every token it serves (ADR 0028).

const (
	// minHeartbeatGap is the floor of the spacing enforced between two heartbeats.
	minHeartbeatGap = 5 * time.Second
	// heartbeatGapDivisor: the spacing is a quarter of the heartbeat interval, so a player that
	// beats on schedule is never close to the line.
	heartbeatGapDivisor = 4
)

// heartbeatMinGap is the shortest accepted time between two heartbeats of a session:
// max(heartbeat_interval / 4, 5 s).
func heartbeatMinGap(intervalSeconds int) time.Duration {
	return max(time.Duration(intervalSeconds)*time.Second/heartbeatGapDivisor, minHeartbeatGap)
}

// HeartbeatPlayback keeps the session alive and returns a fresh token.
func (s *server) HeartbeatPlayback(ctx context.Context, _ gen.HeartbeatPlaybackRequestObject) (gen.HeartbeatPlaybackResponseObject, error) {
	g, err := grantOf(ctx)
	if err != nil {
		return nil, err
	}
	p := s.play
	if p == nil {
		return nil, errs.New(errs.DependencyUnavailable, "Playback is not available.")
	}
	now := p.now().UTC().Truncate(time.Microsecond)
	set := g.settings
	idle := time.Duration(set.IdleTimeoutSeconds) * time.Second

	row, outcome, retry, err := p.store.HeartbeatPlaybackSession(ctx, g.tenant, db.SessionHash(g.session), g.asset, now, idle, heartbeatMinGap(set.HeartbeatIntervalSeconds))
	if err != nil {
		return nil, unauthIfNotFound(err)
	}
	switch outcome {
	case db.HeartbeatUnusable:
		return nil, errPlaybackUnauthenticated()
	case db.HeartbeatTooSoon:
		wait := retryAfter(retry)
		httpx.Logger(ctx).LogAttrs(ctx, slog.LevelWarn, "heartbeat rate limited",
			slog.String("session", fingerprint(g.session)), slog.Int("retry_after", wait))
		rid := requestID(ctx)
		pr := errs.ToProblem(errs.New(errs.RateLimited, "Heartbeats are too frequent. Retry after the time given."), rid)
		return gen.HeartbeatPlayback429ApplicationProblemPlusJSONResponse{
			Body: gen.Problem{
				Code: gen.ProblemCode(pr.Code), Detail: pr.Detail, RequestId: pr.RequestID, Retryable: pr.Retryable,
				Status: pr.Status, Title: pr.Title, Type: pr.Type,
			},
			Headers: gen.HeartbeatPlayback429ResponseHeaders{RetryAfter: wait, XRequestId: rid},
		}, nil
	}

	expiry := now.Add(time.Duration(set.TokenTTLSeconds) * time.Second)
	if expiry.After(row.ExpiresAt) {
		expiry = row.ExpiresAt
	}
	p.access.RecordHeartbeat(p.accessEvent(ctx, g, db.AccessHeartbeat))
	tok, err := p.keyring.Sign(token.Claims{
		SessionID: g.session.String(), AssetID: g.asset.String(), TenantID: g.tenant.String(),
		Scopes: token.ScopeManifest | token.ScopeKey | token.ScopeSegment, Variant: row.Variant.String(),
		IssuedAt: now, Expiry: expiry,
	})
	if err != nil {
		return nil, errs.Wrap(errs.InternalError, "An internal error occurred.", err)
	}
	return gen.HeartbeatPlayback200JSONResponse{
		Body: gen.PlaybackHeartbeat{
			Token: tok, TokenExpiresAt: expiry.Truncate(time.Second),
			HeartbeatIntervalSeconds: set.HeartbeatIntervalSeconds, SessionExpiresAt: row.ExpiresAt,
		},
		Headers: gen.HeartbeatPlayback200ResponseHeaders{
			CacheControl: playlistCacheControl, ReferrerPolicy: noReferrer, XRequestId: requestID(ctx),
		},
	}, nil
}

// EndPlayback ends the session. It is idempotent: whatever state the session is in, the answer is
// 204, and only an active session changes.
func (s *server) EndPlayback(ctx context.Context, _ gen.EndPlaybackRequestObject) (gen.EndPlaybackResponseObject, error) {
	g, err := grantOf(ctx)
	if err != nil {
		return nil, err
	}
	p := s.play
	if p == nil {
		return nil, errs.New(errs.DependencyUnavailable, "Playback is not available.")
	}
	changed, err := p.store.EndPlaybackSession(ctx, g.tenant, db.SessionHash(g.session), p.now().UTC().Truncate(time.Microsecond))
	if err != nil {
		return nil, err
	}
	if changed { // repeating an end changes nothing and is not logged again
		p.access.Record(p.accessEvent(ctx, g, db.AccessEnd))
	}
	return gen.EndPlayback204Response{Headers: gen.EndPlayback204ResponseHeaders{
		CacheControl: playlistCacheControl, XRequestId: requestID(ctx),
	}}, nil
}

func (g guarded) HeartbeatPlayback(w http.ResponseWriter, r *http.Request, sessionID gen.PlaySessionId, params gen.HeartbeatPlaybackParams) {
	g.play.authorizeStateless(w, r, sessionID, token.ScopeManifest, func(r *http.Request) {
		g.ServerInterface.HeartbeatPlayback(w, r, sessionID, params)
	})
}

func (g guarded) EndPlayback(w http.ResponseWriter, r *http.Request, sessionID gen.PlaySessionId, params gen.EndPlaybackParams) {
	g.play.authorizeStateless(w, r, sessionID, token.ScopeManifest, func(r *http.Request) {
		g.ServerInterface.EndPlayback(w, r, sessionID, params)
	})
}
