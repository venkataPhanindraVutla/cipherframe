package edge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/accesslog"
	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/hls"
	"github.com/venkataPhanindraVutla/cipherframe/internal/httpx"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// Session-scoped playback (ADR 0027, 0028, 0030): playlists rewritten per session, and encrypted
// segments proxied from the delivery bucket.
//
// How the pieces fit:
//
//   - Tokens carry the session, asset and tenant (internal/playback/token), so a segment request
//     is checked and its object key built from the token alone, with no database round trip.
//   - What a token cannot say is the tenant's settings: whether "?t=" is allowed (token_in_url)
//     and which browser origins get CORS headers. Edge reads them from the database through a
//     small in-process cache (playbackCacheTTL, bounded), so the steady-state cost of a segment
//     is zero queries and a settings change takes at most playbackCacheTTL to apply. A CORS
//     preflight carries no token, so the tenant is found from the session in the path, through
//     a second small cache of (session -> tenant). That mapping never changes.
//   - Playlist requests also read the session row (never cached), so a revoked, ended, expired or
//     idle session cannot fetch new playlists. A revoked session still fetches segments until its
//     token expires: the segments are unreadable without the key, and the key endpoint (play_key.go)
//     checks the session on every fetch.

const (
	playbackCacheTTL = 30 * time.Second
	// settingsCacheMax and sessionCacheMax bound the caches. A tenant entry is a few hundred
	// bytes; a session entry is a hash and a tenant ID.
	settingsCacheMax = 1024
	sessionCacheMax  = 4096
	// maxPlaylistBytes bounds how much of a stored playlist is read to rewrite. A four-hour
	// rendition with six-second segments is about 240 KB.
	maxPlaylistBytes = 4 << 20

	segmentCacheControl  = "private, max-age=300"
	playlistCacheControl = "no-store"
	noReferrer           = "no-referrer"

	// The detail of every playback authentication failure: one sentence for every cause.
	msgPlaybackUnauthenticated = "The playback token is missing, invalid or expired."
)

// PlaybackStore is what the playback routes read from the database. *db.Repos implements it.
type PlaybackStore interface {
	GetPlaybackSettings(ctx context.Context, tenantID id.TenantID) (db.PlaybackSettings, error)
	GetPlaybackSession(ctx context.Context, tenantID id.TenantID, hash []byte) (db.PlaybackSession, error)
	PlaybackSessionTenant(ctx context.Context, hash []byte) (id.TenantID, error)
	HeartbeatPlaybackSession(ctx context.Context, tenantID id.TenantID, hash []byte, assetID id.AssetID, now time.Time, idle, minGap time.Duration) (db.PlaybackSession, db.HeartbeatOutcome, time.Duration, error)
	EndPlaybackSession(ctx context.Context, tenantID id.TenantID, hash []byte, now time.Time) (bool, error)
}

// KeyStore is what the key endpoint needs besides PlaybackStore: the asset state and the
// database-backed bounds and anomaly events (ADR 0028). *db.Repos implements it.
type KeyStore interface {
	GetAsset(ctx context.Context, tenantID id.TenantID, assetID id.AssetID) (db.Asset, error)
	BumpPlaybackKeyWindow(ctx context.Context, tenantID id.TenantID, sessionHash []byte, now time.Time) (time.Time, int, error)
	ReservePlaybackKeyFetch(ctx context.Context, tokenHash, sessionHash []byte, expires time.Time, limit int) (bool, error)
	ReleasePlaybackKeyFetch(ctx context.Context, tokenHash []byte) error
	RecordKeyReplay(ctx context.Context, tenantID id.TenantID, assetID id.AssetID, tokenHash []byte, limit int, now time.Time) (bool, error)
	InsertPlaybackEvent(ctx context.Context, in db.NewPlaybackEvent) error
}

// ContentKeyReader unwraps an asset's content key. *contentkey.Manager implements it.
type ContentKeyReader interface {
	Get(ctx context.Context, tenant id.TenantID, asset id.AssetID) (contentkey.ContentKey, error)
}

// PlaybackDeps are the collaborators of Playback.
type PlaybackDeps struct {
	Keyring *token.Keyring
	Store   PlaybackStore
	// Delivery is the delivery bucket; only it can presign reads (I4).
	Delivery storage.DeliveryStore
	// KeyStore and ContentKeys serve the key endpoint. Without both it answers 503
	// dependency_unavailable (the server always provides them for the edge role).
	KeyStore    KeyStore
	ContentKeys ContentKeyReader
	// Viewer serves the browser-session route, POST /v1/play/tenants/{tenant_id}/sessions (ADR
	// 0031). Without it that route answers 503 dependency_unavailable.
	Viewer *ViewerDeps
	// Access records the access trail (master playlists, keys, heartbeats, ends, segment counts).
	// Nil records nothing.
	Access *accesslog.Recorder
	// Now defaults to time.Now.
	Now func() time.Time
}

// Playback serves the session-scoped playlist and segment routes. Without one the routes answer
// 503 dependency_unavailable.
type Playback struct {
	keyring  *token.Keyring
	store    PlaybackStore
	delivery storage.DeliveryStore
	keyStore KeyStore
	keys     ContentKeyReader
	viewer   *ViewerDeps
	access   *accesslog.Recorder
	now      func() time.Time

	settings  *ttlCache[string, db.PlaybackSettings]
	viewerCfg *ttlCache[string, viewerConfig]
	sessions  *ttlCache[[sha256.Size]byte, sessionTenant]
}

// sessionTenant is a cached answer to "which tenant owns this session": found is false for a
// session that does not exist, so repeated requests for a made-up session do not each hit the
// database.
type sessionTenant struct {
	tenant id.TenantID
	found  bool
}

// NewPlayback builds a Playback.
func NewPlayback(d PlaybackDeps) (*Playback, error) {
	if d.Keyring == nil || d.Store == nil || d.Delivery == nil {
		return nil, errors.New("edge: playback needs a token keyring, a store and the delivery bucket")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Playback{
		keyring: d.Keyring, store: d.Store, delivery: d.Delivery, keyStore: d.KeyStore, keys: d.ContentKeys, viewer: d.Viewer, access: d.Access, now: d.Now,
		settings:  newTTLCache[string, db.PlaybackSettings](settingsCacheMax, playbackCacheTTL, d.Now),
		viewerCfg: newTTLCache[string, viewerConfig](settingsCacheMax, playbackCacheTTL, d.Now),
		sessions:  newTTLCache[[sha256.Size]byte, sessionTenant](sessionCacheMax, playbackCacheTTL, d.Now),
	}, nil
}

// fingerprint is a short, one-way label for a session ID, safe to log: the first four bytes of its
// SHA-256 in hex. The session ID itself is never logged.
func fingerprint(s id.SessionID) string {
	h := sha256.Sum256([]byte(s.String()))
	return hex.EncodeToString(h[:4])
}

// accessEvent is an access-trail event of a granted request: the session by hash only, the request
// ID, and the requester's address and user agent (stored only if the tenant allows it). The viewer
// is filled in by the access-log writer from the session row.
func (p *Playback) accessEvent(ctx context.Context, g grant, kind string) accesslog.Event {
	return accesslog.Event{
		TenantID: g.tenant, AssetID: g.asset, SessionHash: db.SessionHash(g.session), Kind: kind, At: p.now(),
		RequestID: requestID(ctx), Client: accesslog.ClientFrom(ctx),
	}
}

// tenantSettings returns the tenant's settings from the cache, or reads them.
func (p *Playback) tenantSettings(ctx context.Context, tenant id.TenantID) (db.PlaybackSettings, error) {
	key := tenant.String()
	if s, ok := p.settings.get(key); ok {
		return s, nil
	}
	s, err := p.store.GetPlaybackSettings(ctx, tenant)
	if err != nil {
		return db.PlaybackSettings{}, err
	}
	p.settings.put(key, s)
	return s, nil
}

// tenantOfSession finds the tenant that owns a session (a cache, then the database). A database
// failure is returned and not cached.
func (p *Playback) tenantOfSession(ctx context.Context, hash []byte) (id.TenantID, bool, error) {
	var key [sha256.Size]byte
	copy(key[:], hash)
	if st, ok := p.sessions.get(key); ok {
		return st.tenant, st.found, nil
	}
	tenant, err := p.store.PlaybackSessionTenant(ctx, hash)
	if err != nil {
		var e *errs.Error
		if errors.As(err, &e) && e.Code == errs.NotFound {
			p.sessions.put(key, sessionTenant{})
			return id.TenantID{}, false, nil
		}
		return id.TenantID{}, false, err
	}
	p.sessions.put(key, sessionTenant{tenant: tenant, found: true})
	return tenant, true, nil
}

// grant is what the guard learned from a verified request and the handlers need.
type grant struct {
	tenant  id.TenantID
	asset   id.AssetID
	session id.SessionID
	// urlToken is the token to put in rewritten URIs: set only when the tenant has token_in_url on.
	urlToken string
	// settings are the tenant's settings the guard used (the key bounds come from here).
	settings db.PlaybackSettings
	// tokenHash is the SHA-256 of the request's token text and tokenExpiry its expiry: what the
	// key endpoint counts fetches under. The token itself is not kept.
	tokenHash   []byte
	tokenExpiry time.Time
}

type grantKey struct{}

func withGrant(ctx context.Context, g grant) context.Context {
	return context.WithValue(ctx, grantKey{}, g)
}

func grantOf(ctx context.Context) (grant, error) {
	g, ok := ctx.Value(grantKey{}).(grant)
	if !ok { // the guard always sets it; fail closed
		return grant{}, errs.New(errs.Unauthenticated, msgPlaybackUnauthenticated)
	}
	return g, nil
}

// fileKey maps the {file} path value to an object key and a content type. It returns false for
// anything but the init segment and numbered media segments.
var reSegmentFile = regexp.MustCompile(`^seg-(0|[1-9][0-9]{0,8})\.m4s$`)

func segmentObject(g grant, rend keys.Rendition, file string) (key, contentType string, ok bool) {
	if file == "init.mp4" {
		return keys.InitSegment(g.tenant, g.asset, rend), "video/mp4", true
	}
	m := reSegmentFile.FindStringSubmatch(file)
	if m == nil {
		return "", "", false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return "", "", false
	}
	return keys.Segment(g.tenant, g.asset, rend, n), "video/iso.segment", true
}

// maxPresignTTL is the longest lifetime of a presigned segment URL (ADR 0032).
const maxPresignTTL = 10 * time.Minute

var (
	errPresignFailed = errors.New("edge: presigning failed")
	errPresignName   = errors.New("edge: unexpected segment name")
)

// presignTTL is how long a presigned URL lives for a token that expires at exp: until then, but at
// most maxPresignTTL. It reports false when under a second is left, because storage cannot sign
// for less and the player could not use it.
func presignTTL(exp, now time.Time) (time.Duration, bool) {
	ttl := min(exp.Sub(now), maxPresignTTL)
	if ttl < time.Second {
		return 0, false
	}
	// Whole seconds, rounded down, so a URL never outlives the token.
	return ttl.Truncate(time.Second), true
}

// readPlaylist reads a stored playlist, at most maxPlaylistBytes, and closes it.
func (p *Playback) readPlaylist(ctx context.Context, key string) (string, error) {
	rc, _, err := p.delivery.Get(ctx, key, nil)
	if err != nil {
		return "", storage.ToAppError(err)
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, maxPlaylistBytes+1))
	if err != nil {
		return "", storage.ToAppError(storage.Sanitize("get", keys.Delivery, err))
	}
	if len(b) > maxPlaylistBytes {
		return "", errs.New(errs.InternalError, "An internal error occurred.")
	}
	return string(b), nil
}

// rewriteFailed logs that a stored playlist was refused and returns the client-facing error. The
// log line names the session by fingerprint and never quotes the playlist.
func rewriteFailed(ctx context.Context, g grant, err error) error {
	httpx.Logger(ctx).LogAttrs(ctx, slog.LevelError, "stored playlist refused",
		slog.String("session", fingerprint(g.session)), slog.String("error", err.Error()))
	return errs.New(errs.InternalError, "An internal error occurred.")
}

// playlistResponseHeaders are the headers every playlist carries.
func playlistHeaders(ctx context.Context) gen.GetPlaybackMaster200ResponseHeaders {
	return gen.GetPlaybackMaster200ResponseHeaders{
		CacheControl: playlistCacheControl, ReferrerPolicy: noReferrer, XRequestId: requestID(ctx),
	}
}

// GetPlaybackMaster serves the session's master playlist.
func (s *server) GetPlaybackMaster(ctx context.Context, _ gen.GetPlaybackMasterRequestObject) (gen.GetPlaybackMasterResponseObject, error) {
	g, err := grantOf(ctx)
	if err != nil {
		return nil, err
	}
	src, err := s.play.readPlaylist(ctx, keys.Master(g.tenant, g.asset))
	if err != nil {
		return nil, err
	}
	out, err := hls.RewriteMaster(src, g.urlToken)
	if err != nil {
		return nil, rewriteFailed(ctx, g, err)
	}
	// One row per master fetch. Media playlists and segments are not logged one by one (I10).
	s.play.access.Record(s.play.accessEvent(ctx, g, db.AccessPlaylist))
	return gen.GetPlaybackMaster200ApplicationvndAppleMpegurlResponse{
		Body: strings.NewReader(out), ContentLength: int64(len(out)), Headers: playlistHeaders(ctx),
	}, nil
}

// GetPlaybackMedia serves one rendition's media playlist.
func (s *server) GetPlaybackMedia(ctx context.Context, req gen.GetPlaybackMediaRequestObject) (gen.GetPlaybackMediaResponseObject, error) {
	g, err := grantOf(ctx)
	if err != nil {
		return nil, err
	}
	rend, err := keys.ParseRendition(req.Rendition)
	if err != nil {
		return nil, errs.New(errs.NotFound, "No such resource.")
	}
	src, err := s.play.readPlaylist(ctx, keys.Playlist(g.tenant, g.asset, rend))
	if err != nil {
		return nil, err
	}
	var segURI hls.SegmentURIFunc
	if g.settings.Delivery == db.DeliveryPresigned {
		ttl, ok := presignTTL(g.tokenExpiry, s.play.now())
		if !ok { // the token is about to expire: a URL that lives that short is no use
			return nil, errs.New(errs.Unauthenticated, msgPlaybackUnauthenticated)
		}
		segURI = func(name string) (string, error) {
			key, _, ok := segmentObject(g, rend, name)
			if !ok {
				return "", errPresignName
			}
			r, err := s.play.delivery.PresignGet(ctx, key, ttl)
			if err != nil {
				// storage errors carry no URL or key; still report only that signing failed.
				return "", errPresignFailed
			}
			return r.URL, nil
		}
	}
	out, err := hls.RewriteMediaWith(src, g.urlToken, segURI)
	if errors.Is(err, errPresignFailed) {
		return nil, errs.New(errs.DependencyUnavailable, "Storage is temporarily unavailable.")
	}
	if err != nil {
		return nil, rewriteFailed(ctx, g, err)
	}
	h := playlistHeaders(ctx)
	return gen.GetPlaybackMedia200ApplicationvndAppleMpegurlResponse{
		Body: strings.NewReader(out), ContentLength: int64(len(out)),
		Headers: gen.GetPlaybackMedia200ResponseHeaders(h),
	}, nil
}

// GetPlaybackSegment streams an init or media segment from the delivery bucket. The body is copied
// with io.Copy by the generated code, so memory use does not depend on the segment size.
func (s *server) GetPlaybackSegment(ctx context.Context, req gen.GetPlaybackSegmentRequestObject) (gen.GetPlaybackSegmentResponseObject, error) {
	g, err := grantOf(ctx)
	if err != nil {
		return nil, err
	}
	rend, err := keys.ParseRendition(req.Rendition)
	if err != nil {
		return nil, errs.New(errs.NotFound, "No such resource.")
	}
	key, contentType, ok := segmentObject(g, rend, req.File)
	if !ok {
		return nil, errs.New(errs.NotFound, "No such resource.")
	}
	rc, info, err := s.play.delivery.Get(ctx, key, nil)
	if err != nil {
		// Only a positively identified missing object is a 404 (I11): an outage is a 503.
		return nil, storage.ToAppError(err)
	}
	// Only a count per session is kept: never which segment, rendition or position.
	s.play.access.CountSegment(g.tenant, g.asset, db.SessionHash(g.session))
	h := gen.GetPlaybackSegment200ResponseHeaders{
		CacheControl: segmentCacheControl, ReferrerPolicy: noReferrer, XRequestId: requestID(ctx),
	}
	if contentType == "video/mp4" {
		return gen.GetPlaybackSegment200Videomp4Response{Body: rc, ContentLength: info.Size, Headers: h}, nil
	}
	return gen.GetPlaybackSegment200VideoisoSegmentResponse{Body: rc, ContentLength: info.Size, Headers: h}, nil
}
