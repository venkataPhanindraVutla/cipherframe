package edge

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/anomaly"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/httpx"
)

// The key endpoint (ADR 0027, 0028): GET /v1/play/{session_id}/key returns the raw AES-128 content
// key of the session's asset.
//
// What runs, in this order:
//
//  1. The guard (authorize): token with scope key, session in the path, tenant settings, CORS, and
//     the session row read from the database on this request (never cached): active, before its
//     maximum age, not idle, and for the asset in the token. A revocation applies at once.
//  2. The asset must still be ready: an asset that was deleted or never finished is the same
//     generic 401 as a bad token.
//  3. The per-session window: this request is counted in the session's fixed one-minute window,
//     whatever happens next. Rejected requests are counted too, so a client that keeps hammering
//     stays rejected until the window ends. Past key_requests_per_minute the answer is 429, and
//     the request that first crosses the line raises one key_rate event (once per session per
//     10 minutes, see package anomaly).
//  4. The per-token bound: one atomic statement takes one of the token's key_fetches_per_token
//     fetches, or finds none left. None left is a 429 and, once per token, a key_replay event
//     (once per session per 10 minutes). Both events apply the tenant's auto-revoke policy.
//  5. The session is marked as having been served the key (the segments_without_key signal needs
//     it), then the key service unwraps the content key. A fetch is taken in step 4 BEFORE this call,
//     which is what makes the bound exact under concurrency (a count taken afterwards could be
//     passed by every request that was already in flight). A request that then gets no key, because
//     the key service or the database failed, gives its fetch back: only successful key responses
//     count toward the per-token bound, so an outage does not use up a viewer's fetches.
//
// Errors that are an outage (key service, database) are 503 dependency_unavailable, never 401 or
// 404 (I11). The key, the token and the full session ID are never logged.

// The fixed headers of a key response, and two bounds.
const (
	keyCacheControl = "no-store, private"
	keyPragma       = "no-cache"
	// releaseTimeout bounds giving a fetch back after a failed key lookup, which must happen even
	// when the client has gone.
	releaseTimeout = 3 * time.Second
	// keyWindow is the length of the per-session window of key requests.
	keyWindow = time.Minute
)

// GetPlaybackKey serves the session's content key.
func (s *server) GetPlaybackKey(ctx context.Context, _ gen.GetPlaybackKeyRequestObject) (gen.GetPlaybackKeyResponseObject, error) {
	g, err := grantOf(ctx)
	if err != nil {
		return nil, err
	}
	p := s.play
	if p == nil || p.keyStore == nil || p.keys == nil {
		return nil, errs.New(errs.DependencyUnavailable, "Playback is not available.")
	}
	now := p.now()
	hash := db.SessionHash(g.session)

	// 2. The asset.
	asset, err := p.keyStore.GetAsset(ctx, g.tenant, g.asset)
	if err != nil {
		return nil, unauthIfNotFound(err)
	}
	if asset.State != db.AssetReady {
		p.access.RecordKeyDenied(p.accessEvent(ctx, g, db.AccessKeyDenied))
		return nil, errPlaybackUnauthenticated()
	}

	// 3. The per-session window.
	start, n, err := p.keyStore.BumpPlaybackKeyWindow(ctx, g.tenant, hash, now)
	if err != nil {
		return nil, unauthIfNotFound(err)
	}
	if limit := g.settings.KeyRequestsPerMinute; n > limit {
		if n == limit+1 { // the first request past the line: one event per window
			p.anomalies.Raise(ctx, anomaly.Signal{
				Tenant: g.tenant, Asset: g.asset, Session: hash, Kind: db.EventKeyRate, At: now,
				Detail: map[string]int64{"limit": int64(limit)},
			})
		}
		retry := retryAfter(start.Add(keyWindow).Sub(now))
		p.logRateLimited(ctx, g, db.EventKeyRate, retry)
		p.access.RecordKeyDenied(p.accessEvent(ctx, g, db.AccessKeyDenied))
		return rateLimited(ctx, "Too many key requests for this session. Retry after the time given.", retry), nil
	}

	// 4. The per-token bound.
	limit := g.settings.KeyFetchesPerToken
	ok, err := p.keyStore.ReservePlaybackKeyFetch(ctx, g.tokenHash, hash, g.tokenExpiry, limit)
	if err != nil {
		return nil, err
	}
	if !ok {
		p.recordReplay(ctx, g, limit, now)
		// This token will not get the key again. The heartbeat returns a fresh one.
		retry := max(g.settings.HeartbeatIntervalSeconds, 1)
		p.logRateLimited(ctx, g, db.EventKeyReplay, retry)
		p.access.RecordKeyDenied(p.accessEvent(ctx, g, db.AccessKeyDenied))
		return rateLimited(ctx, "This playback token has used its key fetches. Request a new token with a heartbeat.", retry), nil
	}

	// The session has now been served the key (the segments_without_key signal reads this). It is
	// recorded BEFORE the key is read, so a viewer that got the key is never counted as one that
	// did not: at worst an outage after this point hides a scraper, which is the safe direction.
	if err := p.keyStore.MarkPlaybackKeyServed(ctx, g.tenant, hash, now); err != nil {
		p.release(ctx, g)
		return nil, unauthIfNotFound(err)
	}

	// 5. The key service.
	key, err := p.keys.Get(ctx, g.tenant, g.asset, g.variant)
	if err != nil {
		p.release(ctx, g)
		return nil, unauthIfNotFound(err)
	}
	buf := key.Bytes()
	key.Zero()
	p.access.Record(p.accessEvent(ctx, g, db.AccessKey))
	return gen.GetPlaybackKey200ApplicationoctetStreamResponse{
		Body:          &keyBody{r: bytes.NewReader(buf), buf: buf},
		ContentLength: int64(len(buf)),
		Headers: gen.GetPlaybackKey200ResponseHeaders{
			CacheControl: keyCacheControl, Pragma: keyPragma, ReferrerPolicy: noReferrer, XRequestId: requestID(ctx),
		},
	}, nil
}

// unauthIfNotFound turns a database or key-store "not found" into the generic playback 401 (the
// session, the asset or the key is gone) and leaves every other error, outages included, as is.
func unauthIfNotFound(err error) error {
	var e *errs.Error
	if errors.As(err, &e) && e.Code == errs.NotFound {
		return errPlaybackUnauthenticated()
	}
	return err
}

// retryAfter rounds a wait up to whole seconds, at least 1.
func retryAfter(d time.Duration) int {
	return max(int((d+time.Second-1)/time.Second), 1)
}

// rateLimited is the 429 response with its Retry-After.
func rateLimited(ctx context.Context, detail string, retry int) gen.GetPlaybackKeyResponseObject {
	rid := requestID(ctx)
	pr := errs.ToProblem(errs.New(errs.RateLimited, detail), rid)
	return gen.GetPlaybackKey429ApplicationProblemPlusJSONResponse{
		Body: gen.Problem{
			Code: gen.ProblemCode(pr.Code), Detail: pr.Detail, RequestId: pr.RequestID, Retryable: pr.Retryable,
			Status: pr.Status, Title: pr.Title, Type: pr.Type,
		},
		Headers: gen.GetPlaybackKey429ResponseHeaders{RetryAfter: retry, XRequestId: rid},
	}
}

// release gives back the fetch taken for a request that produced no key. A failure to do so is
// logged (the fetch stays used, which only makes the bound stricter).
func (p *Playback) release(ctx context.Context, g grant) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseTimeout)
	defer cancel()
	if err := p.keyStore.ReleasePlaybackKeyFetch(rctx, g.tokenHash); err != nil {
		httpx.Logger(ctx).LogAttrs(ctx, slog.LevelWarn, "key fetch not released",
			slog.String("session", fingerprint(g.session)), slog.String("code", errCode(err)))
	}
}

// recordReplay raises the key_replay event for a token over its bound, once per token (the mark),
// and then at most once per session per window.
func (p *Playback) recordReplay(ctx context.Context, g grant, limit int, now time.Time) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseTimeout)
	defer cancel()
	hash, first, err := p.keyStore.MarkKeyReplay(rctx, g.tokenHash, now)
	if err != nil {
		httpx.Logger(ctx).LogAttrs(ctx, slog.LevelWarn, "key anomaly event not recorded",
			slog.String("session", fingerprint(g.session)), slog.String("kind", db.EventKeyReplay), slog.String("code", errCode(err)))
		return
	}
	if !first {
		return
	}
	p.anomalies.Raise(ctx, anomaly.Signal{
		Tenant: g.tenant, Asset: g.asset, Session: hash, Kind: db.EventKeyReplay, At: now,
		Detail: map[string]int64{"limit": int64(limit)},
	})
}

func (p *Playback) logRateLimited(ctx context.Context, g grant, kind string, retry int) {
	httpx.Logger(ctx).LogAttrs(ctx, slog.LevelWarn, "key request rate limited",
		slog.String("session", fingerprint(g.session)), slog.String("kind", kind), slog.Int("retry_after", retry))
}

// errCode returns the registered code of err, for logs: never its text, which may name internals.
func errCode(err error) string {
	var e *errs.Error
	if errors.As(err, &e) {
		return string(e.Code)
	}
	return "unknown"
}

// keyBody is the response body: the 16 key bytes, cleared when the response is finished (the
// generated handler closes it after copying). Best effort: the HTTP server may hold its own copy
// in a write buffer for a moment.
type keyBody struct {
	r   *bytes.Reader
	buf []byte
}

func (k *keyBody) Read(p []byte) (int, error) { return k.r.Read(p) }

func (k *keyBody) Close() error {
	clear(k.buf)
	return nil
}
