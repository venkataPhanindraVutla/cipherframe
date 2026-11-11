package edge

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/httpx"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// playPrefix is the path prefix of every session-scoped playback route.
const playPrefix = "/v1/play/"

func errPlaybackUnauthenticated() error {
	return errs.New(errs.Unauthenticated, msgPlaybackUnauthenticated)
}

func errPlaybackNotFound() error { return errs.New(errs.NotFound, "No such resource.") }

// playGate is the middleware in front of the router for the playback routes. It does two things
// before anything else can look at the request:
//
//  1. Path hygiene. A path under /v1/play/ that holds a percent escape, a backslash, an empty
//     segment or a "." or ".." segment is a 404. No legitimate path has any of them (a session ID,
//     a rendition and a file name are plain ASCII), and refusing them here means an encoded slash
//     or a traversal attempt never reaches a handler, let alone the object store. The standard
//     library's router would otherwise answer a raw ".." with a redirect.
//  2. CORS preflight. An OPTIONS request for one of the three routes is answered here, because a
//     preflight carries no token. It is a 204 in every case; the CORS headers are added only when
//     the Origin is exactly one the session's tenant allows.
func playGate(p *Playback) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, playPrefix) {
				next.ServeHTTP(w, r)
				return
			}
			if !cleanPlayPath(r) {
				httpx.WriteProblem(w, r, errPlaybackNotFound())
				return
			}
			if r.Method == http.MethodOptions {
				if sid, ok := playRouteSession(r.URL.Path); ok {
					p.preflight(w, r, sid)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// cleanPlayPath reports whether the path of r is free of everything that has no place in a
// playback path.
func cleanPlayPath(r *http.Request) bool {
	if strings.ContainsAny(r.URL.EscapedPath(), "%\\") {
		return false
	}
	for _, seg := range strings.Split(strings.TrimPrefix(r.URL.Path, playPrefix), "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// playRouteSession reports whether path is one of the three playback routes (by shape; the
// rendition and file are checked by the allowlists) and returns its session ID.
func playRouteSession(path string) (id.SessionID, bool) {
	parts := strings.Split(strings.TrimPrefix(path, playPrefix), "/")
	switch {
	case len(parts) == 2 && parts[1] == "master.m3u8":
	case len(parts) == 3:
		if _, err := keys.ParseRendition(parts[1]); err != nil {
			return id.SessionID{}, false
		}
		if parts[2] != "media.m3u8" && parts[2] != "init.mp4" && !reSegmentFile.MatchString(parts[2]) {
			return id.SessionID{}, false
		}
	default:
		return id.SessionID{}, false
	}
	sid, err := id.ParseSession(parts[0])
	return sid, err == nil
}

// preflight answers a CORS preflight.
func (p *Playback) preflight(w http.ResponseWriter, r *http.Request, sid id.SessionID) {
	h := w.Header()
	h.Add("Vary", "Origin")
	h.Add("Vary", "Access-Control-Request-Method")
	h.Add("Vary", "Access-Control-Request-Headers")
	if p.corsForSession(w, r, sid) {
		h.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Authorization")
		h.Set("Access-Control-Max-Age", "600")
	}
	w.WriteHeader(http.StatusNoContent)
}

// corsForSession adds Access-Control-Allow-Origin when the request has an Origin that the tenant
// owning the session allows. It finds the tenant through the session cache, so it is for requests
// that have no verified token. A lookup failure means no CORS headers, never an error. It reports
// whether the header was added.
func (p *Playback) corsForSession(w http.ResponseWriter, r *http.Request, sid id.SessionID) bool {
	if p == nil || r.Header.Get("Origin") == "" {
		return false
	}
	tenant, found, err := p.tenantOfSession(r.Context(), db.SessionHash(sid))
	if err != nil || !found {
		return false
	}
	set, err := p.tenantSettings(r.Context(), tenant)
	if err != nil {
		return false
	}
	return applyCORS(w, r, set)
}

// applyCORS adds Access-Control-Allow-Origin when the request's Origin is, byte for byte, one of
// the tenant's allowed origins. A request without an Origin (a native player, a same-origin page)
// and an unknown origin get nothing: the browser then blocks the cross-origin read, and no error
// body says why. Credentials are never allowed: tokens are not cookies.
func applyCORS(w http.ResponseWriter, r *http.Request, set db.PlaybackSettings) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || !slices.Contains(set.AllowedOrigins, origin) {
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	return true
}

// playbackToken extracts the token from the request, by ADR 0030: Authorization: Bearer by
// default, or the query parameter t. Both together, or t twice, is a 400. fromQuery reports which.
func playbackToken(r *http.Request) (tok string, fromQuery bool, err error) {
	hdr := r.Header.Values("Authorization")
	q, hasQuery := r.URL.Query()["t"]
	switch {
	case len(hdr) > 0 && hasQuery:
		return "", false, errs.New(errs.InvalidRequest, "Send the playback token in the Authorization header or in the t parameter, not both.")
	case len(q) > 1:
		return "", false, errs.New(errs.InvalidRequest, "The request is malformed.")
	case len(hdr) > 0:
		if len(hdr) != 1 {
			return "", false, errPlaybackUnauthenticated()
		}
		t, ok := auth.BearerToken(hdr[0])
		if !ok {
			return "", false, errPlaybackUnauthenticated()
		}
		return t, false, nil
	case hasQuery:
		return q[0], true, nil
	default:
		return "", false, errPlaybackUnauthenticated()
	}
}

// authorize is the guard of the playback routes. It runs before the generated strict handler and
// either answers the request itself or passes it on with a grant in its context.
//
//  1. path values: a malformed session ID is a 404 (no token is involved, nothing is revealed);
//  2. the token: header or t (ADR 0030), verified statelessly for the scope the route needs;
//  3. the session in the token must be the session in the path (constant-time comparison);
//  4. the tenant's settings (cached): t is accepted only with token_in_url, and the Origin is
//     checked for CORS;
//  5. playlists only (scope manifest): the session row must be active, unexpired and not idle.
//
// Every token or session failure is the same 401. A segment request never reads the session row.
func (p *Playback) authorize(w http.ResponseWriter, r *http.Request, rawSession string, need token.Scope, next func(*http.Request)) {
	h := w.Header()
	h.Add("Vary", "Origin")
	h.Set("Referrer-Policy", noReferrer)
	fail := func(err error) { writeAuthError(w, r, err) }

	if p == nil {
		fail(errs.New(errs.DependencyUnavailable, "Playback is not available."))
		return
	}
	sid, err := id.ParseSession(rawSession)
	if err != nil {
		fail(errPlaybackNotFound())
		return
	}
	// deny answers a failure for which the tenant is not known yet from a verified token: CORS
	// headers are still added, through the session cache, so a browser player can read the 401 and
	// refresh its token instead of seeing an opaque network error.
	deny := func(err error) {
		p.corsForSession(w, r, sid)
		fail(err)
	}

	tok, fromQuery, err := playbackToken(r)
	if err != nil {
		deny(err)
		return
	}
	claims, err := p.keyring.Open(tok, p.now(), need)
	if err != nil || subtle.ConstantTimeCompare([]byte(claims.SessionID), []byte(rawSession)) != 1 {
		deny(errPlaybackUnauthenticated())
		return
	}
	tenant, terr := id.Parse[id.TenantKind](claims.TenantID)
	asset, aerr := id.Parse[id.AssetKind](claims.AssetID)
	if terr != nil || aerr != nil {
		deny(errPlaybackUnauthenticated())
		return
	}

	set, err := p.tenantSettings(r.Context(), tenant)
	if err != nil {
		fail(err)
		return
	}
	applyCORS(w, r, set)
	if fromQuery && !set.TokenInURL {
		fail(errPlaybackUnauthenticated())
		return
	}

	if need.Has(token.ScopeManifest) {
		row, err := p.store.GetPlaybackSession(r.Context(), tenant, db.SessionHash(sid))
		if err != nil {
			var e *errs.Error
			if errors.As(err, &e) && e.Code == errs.NotFound {
				err = errPlaybackUnauthenticated()
			}
			fail(err)
			return
		}
		if row.AssetID != asset || !sessionUsable(row, set, p.now()) {
			fail(errPlaybackUnauthenticated())
			return
		}
	}

	g := grant{tenant: tenant, asset: asset, session: sid}
	if set.TokenInURL {
		g.urlToken = tok
	}
	next(r.WithContext(withGrant(r.Context(), g)))
}

// sessionUsable is the stateful session check of a playlist request: active, before its maximum
// age, and with a heartbeat within the idle timeout (the same rules as CountActivePlaybackSessions).
func sessionUsable(s db.PlaybackSession, set db.PlaybackSettings, now time.Time) bool {
	idle := time.Duration(set.IdleTimeoutSeconds) * time.Second
	return s.State == db.PlaybackActive && now.Before(s.ExpiresAt) && now.Before(s.LastHeartbeatAt.Add(idle))
}

// The three guarded routes. The generated wrapper has already bound the path values.

func (g guarded) GetPlaybackMaster(w http.ResponseWriter, r *http.Request, sessionID gen.PlaySessionId, params gen.GetPlaybackMasterParams) {
	g.play.authorize(w, r, sessionID, token.ScopeManifest, func(r *http.Request) {
		g.ServerInterface.GetPlaybackMaster(w, r, sessionID, params)
	})
}

func (g guarded) GetPlaybackMedia(w http.ResponseWriter, r *http.Request, sessionID gen.PlaySessionId, rendition gen.PlayRendition, params gen.GetPlaybackMediaParams) {
	if !validRendition(rendition) {
		writeAuthError(w, r, errPlaybackNotFound())
		return
	}
	g.play.authorize(w, r, sessionID, token.ScopeManifest, func(r *http.Request) {
		g.ServerInterface.GetPlaybackMedia(w, r, sessionID, rendition, params)
	})
}

func (g guarded) GetPlaybackSegment(w http.ResponseWriter, r *http.Request, sessionID gen.PlaySessionId, rendition gen.PlayRendition, file gen.PlayFile, params gen.GetPlaybackSegmentParams) {
	if !validRendition(rendition) || (file != "init.mp4" && !reSegmentFile.MatchString(file)) {
		writeAuthError(w, r, errPlaybackNotFound())
		return
	}
	g.play.authorize(w, r, sessionID, token.ScopeSegment, func(r *http.Request) {
		g.ServerInterface.GetPlaybackSegment(w, r, sessionID, rendition, file, params)
	})
}

func validRendition(s string) bool {
	_, err := keys.ParseRendition(s)
	return err == nil
}
