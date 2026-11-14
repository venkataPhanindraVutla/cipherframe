package edge

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/accesslog"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/httpx"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth"
)

// Browser-started playback sessions (ADR 0029, 0031): POST /v1/play/tenants/{tenant_id}/sessions.
//
// The viewer's browser asks for a session; the embedding application authorises it with a JWT it
// signed or with a signed callback Cipherframe makes to it. Either way the session is then created
// by playback.Service, exactly as for an API-key call, so the limits, the settings and the answer
// are the same.
//
// What is cached and what is not:
//
//   - The tenant's playback settings (CORS origins) and its JWT configuration with its uploaded
//     keys come through small caches of 30 seconds, like the other playback settings.
//   - The callback configuration and secret are read for every callback. A secret rotation or a
//     disabled callback therefore applies at once, and the secret is unwrapped only for the length
//     of one request. Callback answers are never cached.
//
// Failure rules (invariant I11):
//
//   - everything that is the viewer's or the tenant's doing (no configuration, a method that is
//     off, a bad token, a callback that times out, refuses or answers badly, a replayed jti) is the
//     same generic 401;
//   - everything that is Cipherframe's own failure (the database, the key provider that wraps the
//     callback secret) is a 5xx, never a denial and never a grant.
//
// Nothing here logs a token, a ticket, a secret or a URL.

const (
	// msgViewerUnauthenticated is the detail of every authorization failure.
	msgViewerUnauthenticated = "The request could not be authorized."
	// viewerBodyMax caps the request body: an asset ID, a method and a ticket of up to 2048 bytes.
	viewerBodyMax = 8 << 10
	// sessionsPath is the suffix of the route after the tenant ID.
	sessionsSuffix = "/sessions"
	tenantsPrefix  = playPrefix + "tenants/"
)

// SessionCreator creates a playback session. *playback.Service implements it.
type SessionCreator interface {
	CreateSession(ctx context.Context, in playback.CreateInput) (playback.Created, error)
}

// ViewerStore is what the browser-session route reads and writes besides PlaybackStore.
// *db.Repos implements it.
type ViewerStore interface {
	GetAsset(ctx context.Context, tenantID id.TenantID, assetID id.AssetID) (db.Asset, error)
	GetPlaybackAuth(ctx context.Context, tenantID id.TenantID) (db.PlaybackAuth, error)
	ListPlaybackJWTKeys(ctx context.Context, tenantID id.TenantID) ([]db.PlaybackJWTKey, error)
	ClaimPlaybackJWTID(ctx context.Context, tenantID id.TenantID, jti string, expiresAt time.Time) (bool, error)
}

// SecretOpener unwraps a stored callback secret. *viewerauth.SecretBox implements it.
type SecretOpener interface {
	Open(ctx context.Context, tenant id.TenantID, version int, envelope []byte) ([]byte, error)
}

// ViewerDeps are the collaborators of the browser-session route.
type ViewerDeps struct {
	Sessions SessionCreator
	Store    ViewerStore
	Secrets  SecretOpener
	Verifier *viewerauth.Verifier
	Callback *viewerauth.Authorizer
}

func (d *ViewerDeps) complete() bool {
	return d != nil && d.Sessions != nil && d.Store != nil && d.Secrets != nil && d.Verifier != nil && d.Callback != nil
}

// viewerConfig is a tenant's JWT configuration and uploaded keys, as cached.
type viewerConfig struct {
	auth db.PlaybackAuth
	keys map[string]viewerauth.PublicKey
}

// viewerConfigFor returns the tenant's JWT configuration from the cache, or reads it. A stored key
// that no longer parses is left out: the key fails closed.
func (p *Playback) viewerConfigFor(ctx context.Context, tenant id.TenantID) (viewerConfig, error) {
	key := tenant.String()
	if c, ok := p.viewerCfg.get(key); ok {
		return c, nil
	}
	a, err := p.viewer.Store.GetPlaybackAuth(ctx, tenant)
	if err != nil {
		return viewerConfig{}, err
	}
	rows, err := p.viewer.Store.ListPlaybackJWTKeys(ctx, tenant)
	if err != nil {
		return viewerConfig{}, err
	}
	c := viewerConfig{auth: a, keys: make(map[string]viewerauth.PublicKey, len(rows))}
	for _, r := range rows {
		if pk, err := viewerauth.ParseStoredJWK(r.Kid, r.Alg, r.JWK); err == nil {
			c.keys[r.Kid] = pk
		}
	}
	p.viewerCfg.put(key, c)
	return c, nil
}

type bearerKey struct{}

// CreateBrowserPlaybackSession authorises the viewer and creates the session.
func (s *server) CreateBrowserPlaybackSession(ctx context.Context, req gen.CreateBrowserPlaybackSessionRequestObject) (gen.CreateBrowserPlaybackSessionResponseObject, error) {
	p := s.play
	if p == nil || !p.viewer.complete() {
		return nil, errs.New(errs.DependencyUnavailable, "Playback is not available.")
	}
	tenant, err := id.Parse[id.TenantKind](req.TenantId)
	if err != nil {
		return nil, errPlaybackNotFound()
	}
	if req.Body == nil {
		return nil, errs.New(errs.InvalidRequest, "A request body is required.")
	}
	asset, err := id.Parse[id.AssetKind](req.Body.AssetId)
	if err != nil {
		return nil, errs.Invalid("The request is invalid.", []errs.FieldError{{Field: "asset_id", Message: "must be an asset ID"}})
	}

	// decided is the variant the embedding application chose (the JWT claim, or the default it was
	// told in the callback). Empty means the asset's default. The viewer never chooses (ADR 0036).
	var viewer, method string
	var decided keys.Variant
	switch req.Body.Method {
	case gen.Jwt:
		method = db.AuthMethodJWT
		bearer, _ := ctx.Value(bearerKey{}).(string)
		viewer, decided, err = p.authorizeJWT(ctx, tenant, asset, bearer)
	case gen.Callback:
		method = db.AuthMethodCallback
		ticket := ""
		if req.Body.Ticket != nil {
			ticket = *req.Body.Ticket
		}
		if n := len(ticket); n < 1 || n > viewerauth.MaxTicketBytes {
			return nil, errs.Invalid("The request is invalid.", []errs.FieldError{{Field: "ticket", Message: "is required for the callback method: 1 to 2048 bytes"}})
		}
		viewer, decided, err = p.authorizeCallback(ctx, tenant, asset, ticket)
	default:
		return nil, errs.Invalid("The request is invalid.", []errs.FieldError{{Field: "method", Message: "must be jwt or callback"}})
	}
	if err != nil {
		var e *errs.Error
		if errors.As(err, &e) && e.Code == errs.Unauthenticated {
			httpx.Logger(ctx).LogAttrs(ctx, slog.LevelDebug, "viewer session refused",
				slog.String("method", method), slog.String("tenant", tenant.String()), slog.String("reason", denyReason(err)))
			// No viewer ID: the authorization failed, so nothing vouches for one.
			p.access.RecordSessionDenied(accesslog.Event{
				TenantID: tenant, AssetID: asset, AuthMethod: method, Kind: db.AccessSessionDenied, At: p.now(),
				RequestID: requestID(ctx), Client: accesslog.ClientFrom(ctx),
			})
		}
		return nil, err
	}

	if req.Body.Variant != nil {
		// Only a check, after authorization so a refusal reveals nothing to an unauthorised caller.
		if decided == "" {
			if decided, err = p.defaultVariant(ctx, tenant, asset); err != nil {
				return nil, err
			}
		}
		if keys.Variant(*req.Body.Variant) != decided {
			return nil, errs.New(errs.Forbidden, "The variant is decided by the embedding application, not the viewer.")
		}
	}

	c, err := p.viewer.Sessions.CreateSession(ctx, playback.CreateInput{
		TenantID: tenant, AuthMethod: method, AssetID: asset, Variant: decided, ViewerID: viewer,
	})
	if err != nil {
		return nil, err
	}
	return gen.CreateBrowserPlaybackSession201JSONResponse{
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
		Headers: gen.CreateBrowserPlaybackSession201ResponseHeaders{CacheControl: playlistCacheControl, XRequestId: requestID(ctx)},
	}, nil
}

// denyCause is the cause of a 401: why, from a closed set. The client sees only the generic
// detail; the reason goes to the debug log.
type denyCause struct{ reason string }

func (d denyCause) Error() string { return "denied: " + d.reason }

func denied(reason string) error {
	return errs.Wrap(errs.Unauthenticated, msgViewerUnauthenticated, denyCause{reason: reason})
}

func denyReason(err error) string {
	var d denyCause
	if errors.As(err, &d) {
		return d.reason
	}
	return ""
}

// defaultVariant is the variant a session on the asset gets when nobody chose: the original for an
// asset that does not exist (the session creation then answers not_found).
func (p *Playback) defaultVariant(ctx context.Context, tenant id.TenantID, asset id.AssetID) (keys.Variant, error) {
	a, err := p.viewer.Store.GetAsset(ctx, tenant, asset)
	if err != nil {
		var e *errs.Error
		if errors.As(err, &e) && e.Code == errs.NotFound {
			return keys.Original, nil
		}
		return "", err
	}
	return playback.DefaultVariant(a), nil
}

// authorizeJWT verifies the viewer's token and makes its jti single-use. It returns the viewer ID
// and the token's variant claim ("" when it has none).
func (p *Playback) authorizeJWT(ctx context.Context, tenant id.TenantID, asset id.AssetID, bearer string) (string, keys.Variant, error) {
	cfg, err := p.viewerConfigFor(ctx, tenant)
	if err != nil {
		return "", "", err // our own failure: never a denial
	}
	if !cfg.auth.JWTEnabled {
		return "", "", denied("jwt_off")
	}
	if bearer == "" {
		return "", "", denied("no_token")
	}
	v, err := p.viewer.Verifier.Verify(ctx, tenant.String(), viewerauth.JWTConfig{
		Issuer: cfg.auth.JWTIssuer, Audiences: cfg.auth.JWTAudiences, JWKSURL: cfg.auth.JWKSURL,
		ViewerClaim: cfg.auth.JWTViewerClaim, Uploaded: cfg.keys,
	}, bearer, asset.String())
	if err != nil {
		return "", "", denied(viewerauth.ReasonOf(err))
	}
	variant := keys.Variant(v.Variant)
	if variant != "" && !variant.Valid() {
		return "", "", denied(viewerauth.ReasonVariant)
	}
	// Single use: the jti is kept until the token could no longer verify (exp plus the skew
	// allowance). The first caller wins; a replay is a denial. A database failure is not.
	first, err := p.viewer.Store.ClaimPlaybackJWTID(ctx, tenant, v.JTI, v.Expiry.Add(viewerauth.ClockSkew).UTC())
	if err != nil {
		return "", "", err
	}
	if !first {
		return "", "", denied("jti_replay")
	}
	return v.Viewer, variant, nil
}

// authorizeCallback asks the tenant's callback. The configuration is read fresh, and the secrets
// are unwrapped for this one request only. The callback is told the variant the session would get,
// the asset's default, and so approves that specific variant. It returns the viewer ID and that
// variant.
func (p *Playback) authorizeCallback(ctx context.Context, tenant id.TenantID, asset id.AssetID, ticket string) (string, keys.Variant, error) {
	a, err := p.viewer.Store.GetPlaybackAuth(ctx, tenant)
	if err != nil {
		return "", "", err
	}
	if !a.CallbackEnabled || a.CallbackURL == "" || a.CallbackSecretVersion == 0 || len(a.CallbackSecretEnvelope) == 0 {
		return "", "", denied("callback_off")
	}
	variant, err := p.defaultVariant(ctx, tenant, asset)
	if err != nil {
		return "", "", err
	}
	secrets, err := p.callbackSecrets(ctx, tenant, a)
	if err != nil {
		return "", "", err
	}
	defer func() {
		for _, s := range secrets {
			clear(s)
		}
	}()
	viewer, err := p.viewer.Callback.Authorize(ctx, a.CallbackURL, secrets, viewerauth.CallbackRequest{
		TenantID: tenant.String(), AssetID: asset.String(), Variant: variant.String(), Ticket: ticket, RequestID: requestID(ctx),
	})
	if err != nil {
		return "", "", denied(viewerauth.ReasonOf(err))
	}
	return viewer, variant, nil
}

// callbackSecrets unwraps the current secret, and the previous one while it is still within its
// 24 hour overlap. Failing to unwrap the current one is Cipherframe's own failure: 503, not a
// denial. A previous secret that does not unwrap is left out (the current one still signs).
func (p *Playback) callbackSecrets(ctx context.Context, tenant id.TenantID, a db.PlaybackAuth) ([][]byte, error) {
	cur, err := p.viewer.Secrets.Open(ctx, tenant, a.CallbackSecretVersion, a.CallbackSecretEnvelope)
	if err != nil {
		httpx.Logger(ctx).LogAttrs(ctx, slog.LevelError, "callback secret could not be unwrapped",
			slog.String("tenant", tenant.String()), slog.String("kind", kms.KindOf(err).String()))
		return nil, errs.Wrap(errs.DependencyUnavailable, "Authorization is temporarily unavailable.", err)
	}
	secrets := [][]byte{cur}
	if _, ok := playback.PreviousSecretValidUntil(a, p.now()); ok {
		if prev, err := p.viewer.Secrets.Open(ctx, tenant, a.CallbackSecretPrevVersion, a.CallbackSecretPrevEnvelope); err == nil {
			secrets = append(secrets, prev)
		} else {
			httpx.Logger(ctx).LogAttrs(ctx, slog.LevelWarn, "previous callback secret could not be unwrapped",
				slog.String("tenant", tenant.String()), slog.String("kind", kms.KindOf(err).String()))
		}
	}
	return secrets, nil
}

// CreateBrowserPlaybackSession is the guarded entry: it adds CORS for the tenant's allowed origins
// (the tenant is in the path), makes every answer no-store, bounds the body and hands the bearer
// credential to the handler.
func (g guarded) CreateBrowserPlaybackSession(w http.ResponseWriter, r *http.Request, tenantID gen.TenantIdPath) {
	h := w.Header()
	h.Set("Cache-Control", playlistCacheControl)
	h.Set("Referrer-Policy", noReferrer)
	h.Add("Vary", "Origin")
	p := g.play
	if p == nil || !p.viewer.complete() {
		writeAuthError(w, r, errs.New(errs.DependencyUnavailable, "Playback is not available."))
		return
	}
	tenant, err := id.Parse[id.TenantKind](tenantID)
	if err != nil {
		writeAuthError(w, r, errPlaybackNotFound())
		return
	}
	set, err := p.tenantSettings(r.Context(), tenant)
	if err != nil {
		writeAuthError(w, r, err)
		return
	}
	applyCORS(w, r, set)

	ctx := r.Context()
	if hdr := r.Header.Values("Authorization"); len(hdr) == 1 {
		if tok, ok := auth.BearerToken(hdr[0]); ok {
			ctx = context.WithValue(ctx, bearerKey{}, tok)
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, viewerBodyMax)
	g.ServerInterface.CreateBrowserPlaybackSession(w, r.WithContext(ctx), tenantID)
}

// tenantRouteID reports whether path is the browser-session route and returns the tenant ID text.
func tenantRouteID(path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, tenantsPrefix)
	if !ok {
		return "", false
	}
	tid, ok := strings.CutSuffix(rest, sessionsSuffix)
	if !ok || tid == "" || strings.Contains(tid, "/") {
		return "", false
	}
	return tid, true
}

// preflightTenant answers the CORS preflight of the browser-session route. It is a 204 in every
// case; the CORS headers are added only when the Origin is exactly one the tenant allows.
func (p *Playback) preflightTenant(w http.ResponseWriter, r *http.Request, rawTenant string) {
	h := w.Header()
	h.Add("Vary", "Origin")
	h.Add("Vary", "Access-Control-Request-Method")
	h.Add("Vary", "Access-Control-Request-Headers")
	if p != nil && r.Header.Get("Origin") != "" {
		if tenant, err := id.Parse[id.TenantKind](rawTenant); err == nil {
			// A lookup failure means no CORS headers, never an error.
			if set, err := p.tenantSettings(r.Context(), tenant); err == nil && applyCORS(w, r, set) {
				h.Set("Access-Control-Allow-Methods", "POST, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				h.Set("Access-Control-Max-Age", "600")
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
