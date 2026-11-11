package db

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// PlaybackSettings are a tenant's playback parameters (ADR 0028, 0030). A tenant without a stored
// row uses DefaultPlaybackSettings. UpdatedAt is the zero time for the defaults.
type PlaybackSettings struct {
	TokenTTLSeconds          int
	HeartbeatIntervalSeconds int
	IdleTimeoutSeconds       int
	SessionMaxSeconds        int
	MaxSessionsPerViewer     int // 0 means unlimited
	KeyFetchesPerToken       int
	KeyRequestsPerMinute     int
	AllowedOrigins           []string
	TokenInURL               bool
	// Delivery is DeliveryProxy or DeliveryPresigned (ADR 0032).
	Delivery  string
	UpdatedAt time.Time
}

// The delivery strategies (ADR 0032).
const (
	DeliveryProxy     = "proxy"
	DeliveryPresigned = "presigned"
)

// DefaultPlaybackSettings returns the settings of a tenant that has none stored. They equal the
// column defaults of the playback_settings table; a test keeps the two in step.
func DefaultPlaybackSettings() PlaybackSettings {
	return PlaybackSettings{
		TokenTTLSeconds:          600,
		HeartbeatIntervalSeconds: 60,
		IdleTimeoutSeconds:       300,
		SessionMaxSeconds:        14400,
		MaxSessionsPerViewer:     3,
		KeyFetchesPerToken:       20,
		KeyRequestsPerMinute:     30,
		AllowedOrigins:           []string{},
		Delivery:                 DeliveryProxy,
	}
}

// Playback session states.
const (
	PlaybackActive  = "active"
	PlaybackRevoked = "revoked"
	PlaybackEnded   = "ended"
)

// PlaybackSession is the stored form of a session. The session ID is not part of it: only its
// hash is stored (see SessionHash).
type PlaybackSession struct {
	IDHash   []byte
	TenantID id.TenantID
	// ClientID is the API client that made the session; it is the zero ID unless AuthMethod is
	// AuthMethodAPIKey.
	ClientID        id.ClientID
	AuthMethod      string
	AssetID         id.AssetID
	ViewerID        string
	State           string
	CreatedAt       time.Time
	LastHeartbeatAt time.Time
	ExpiresAt       time.Time
	EndedAt         *time.Time
	RevokedAt       *time.Time
	RevokeReason    string
}

// How a playback session was authorised (ADR 0029, 0031). The playback_sessions table enforces
// that a session has a client exactly when its method is AuthMethodAPIKey.
const (
	AuthMethodAPIKey   = "api_key"
	AuthMethodJWT      = "jwt"
	AuthMethodCallback = "callback"
)

// SessionHash returns the SHA-256 of the session ID's text form. It is the primary key of
// playback_sessions: the ID is a capability, so the table never holds it.
func SessionHash(s id.SessionID) []byte {
	h := sha256.Sum256([]byte(s.String()))
	return h[:]
}

func settingsFromRow(r dbgen.PlaybackSetting) PlaybackSettings {
	return PlaybackSettings{
		TokenTTLSeconds:          int(r.TokenTtlSeconds),
		HeartbeatIntervalSeconds: int(r.HeartbeatIntervalSeconds),
		IdleTimeoutSeconds:       int(r.IdleTimeoutSeconds),
		SessionMaxSeconds:        int(r.SessionMaxSeconds),
		MaxSessionsPerViewer:     int(r.MaxSessionsPerViewer),
		KeyFetchesPerToken:       int(r.KeyFetchesPerToken),
		KeyRequestsPerMinute:     int(r.KeyRequestsPerMinute),
		AllowedOrigins:           append([]string{}, r.AllowedOrigins...),
		TokenInURL:               r.TokenInUrl,
		Delivery:                 r.Delivery,
		UpdatedAt:                r.UpdatedAt.UTC(),
	}
}

func sessionFromRow(r dbgen.PlaybackSession) PlaybackSession {
	return PlaybackSession{
		IDHash:          slices.Clone(r.IDHash),
		TenantID:        fromPG[id.TenantKind](r.TenantID),
		ClientID:        fromPG[id.ClientKind](r.ClientID),
		AuthMethod:      r.AuthMethod,
		AssetID:         fromPG[id.AssetKind](r.AssetID),
		ViewerID:        r.ViewerID,
		State:           r.State,
		CreatedAt:       r.CreatedAt.UTC(),
		LastHeartbeatAt: r.LastHeartbeatAt.UTC(),
		ExpiresAt:       r.ExpiresAt.UTC(),
		EndedAt:         utcPtr(r.EndedAt),
		RevokedAt:       utcPtr(r.RevokedAt),
		RevokeReason:    strVal(r.RevokeReason),
	}
}

// GetPlaybackSettings returns the tenant's settings, or the defaults when it has none stored.
func (r *Repos) GetPlaybackSettings(ctx context.Context, tenantID id.TenantID) (PlaybackSettings, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return PlaybackSettings{}, err
	}
	row, err := r.q.GetPlaybackSettings(ctx, tid)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultPlaybackSettings(), nil
	}
	if err != nil {
		return PlaybackSettings{}, mapError(err)
	}
	return settingsFromRow(row), nil
}

// PutPlaybackSettings replaces every setting of the tenant. The caller validates first; the
// table's CHECK constraints are the backstop and surface as internal_error.
func (r *Repos) PutPlaybackSettings(ctx context.Context, tenantID id.TenantID, s PlaybackSettings, at time.Time) (PlaybackSettings, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return PlaybackSettings{}, err
	}
	origins := s.AllowedOrigins
	if origins == nil {
		origins = []string{}
	}
	//nolint:gosec // every value is range-checked by the caller and by the table's CHECKs
	row, err := r.q.UpsertPlaybackSettings(ctx, dbgen.UpsertPlaybackSettingsParams{
		TenantID:                 tid,
		TokenTtlSeconds:          int32(s.TokenTTLSeconds),
		HeartbeatIntervalSeconds: int32(s.HeartbeatIntervalSeconds),
		IdleTimeoutSeconds:       int32(s.IdleTimeoutSeconds),
		SessionMaxSeconds:        int32(s.SessionMaxSeconds),
		MaxSessionsPerViewer:     int32(s.MaxSessionsPerViewer),
		KeyFetchesPerToken:       int32(s.KeyFetchesPerToken),
		KeyRequestsPerMinute:     int32(s.KeyRequestsPerMinute),
		AllowedOrigins:           origins,
		TokenInUrl:               s.TokenInURL,
		Delivery:                 s.Delivery,
		At:                       at,
	})
	if err != nil {
		return PlaybackSettings{}, mapError(err)
	}
	return settingsFromRow(row), nil
}

// LockPlaybackViewer takes a transaction-scoped advisory lock for one (tenant, viewer), so the
// count-then-insert of a new session cannot interleave with another one. Use it inside Tx.
func (r *Repos) LockPlaybackViewer(ctx context.Context, tenantID id.TenantID, viewerID string) error {
	if tenantID.IsZero() || viewerID == "" {
		return errs.New(errs.InvalidRequest, "a required identifier is missing")
	}
	return mapError(r.q.LockPlaybackViewer(ctx, "cipherframe.playback_viewer:"+tenantID.String()+":"+viewerID))
}

// EndStalePlaybackSessions marks the viewer's active sessions that are idle past idle, or past
// their expiry, as ended, and returns how many it ended.
func (r *Repos) EndStalePlaybackSessions(ctx context.Context, tenantID id.TenantID, viewerID string, now time.Time, idle time.Duration) (int64, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return 0, err
	}
	n, err := r.q.EndStalePlaybackSessions(ctx, dbgen.EndStalePlaybackSessionsParams{
		Now: now, TenantID: tid, ViewerID: viewerID, IdleSeconds: int32(idle / time.Second), //nolint:gosec // bounded by the settings range
	})
	return n, mapError(err)
}

// CountActivePlaybackSessions counts the viewer's sessions that are active, not idle past idle and
// not expired at now.
func (r *Repos) CountActivePlaybackSessions(ctx context.Context, tenantID id.TenantID, viewerID string, now time.Time, idle time.Duration) (int, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return 0, err
	}
	n, err := r.q.CountActivePlaybackSessions(ctx, dbgen.CountActivePlaybackSessionsParams{
		TenantID: tid, ViewerID: viewerID, Now: now, IdleSeconds: int32(idle / time.Second), //nolint:gosec // bounded by the settings range
	})
	if err != nil {
		return 0, mapError(err)
	}
	return int(n), nil
}

// NewPlaybackSession is the input for InsertPlaybackSession.
type NewPlaybackSession struct {
	ID       id.SessionID
	TenantID id.TenantID
	// ClientID is required for AuthMethodAPIKey and must be the zero ID for the other methods.
	ClientID id.ClientID
	// AuthMethod is one of the AuthMethod constants; empty means AuthMethodAPIKey.
	AuthMethod string
	AssetID    id.AssetID
	ViewerID   string
	Now        time.Time
	ExpiresAt  time.Time
}

// InsertPlaybackSession stores an active session under the hash of its ID. The asset must belong
// to the tenant and be ready; otherwise it returns a conflict whose cause is ErrStateChanged and
// writes nothing.
func (r *Repos) InsertPlaybackSession(ctx context.Context, in NewPlaybackSession) (PlaybackSession, error) {
	tid, err := requirePG(in.TenantID)
	if err != nil {
		return PlaybackSession{}, err
	}
	if in.AuthMethod == "" {
		in.AuthMethod = AuthMethodAPIKey
	}
	var cid pgtype.UUID
	switch in.AuthMethod {
	case AuthMethodAPIKey:
		if cid, err = requirePG(in.ClientID); err != nil {
			return PlaybackSession{}, err
		}
	case AuthMethodJWT, AuthMethodCallback:
		if !in.ClientID.IsZero() {
			return PlaybackSession{}, errs.New(errs.InvalidRequest, "invalid playback session")
		}
	default:
		return PlaybackSession{}, errs.New(errs.InvalidRequest, "invalid playback session")
	}
	aid, err := requirePG(in.AssetID)
	if err != nil {
		return PlaybackSession{}, err
	}
	if in.ID.IsZero() || in.ViewerID == "" || !in.ExpiresAt.After(in.Now) {
		return PlaybackSession{}, errs.New(errs.InvalidRequest, "invalid playback session")
	}
	row, err := r.q.InsertPlaybackSession(ctx, dbgen.InsertPlaybackSessionParams{
		IDHash: SessionHash(in.ID), ClientID: cid, AuthMethod: in.AuthMethod, ViewerID: in.ViewerID, Now: in.Now,
		ExpiresAt: in.ExpiresAt, AssetID: aid, TenantID: tid,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PlaybackSession{}, stateConflict()
		}
		return PlaybackSession{}, mapError(err)
	}
	return sessionFromRow(row), nil
}

// GetPlaybackSession reads a session of the tenant by the hash of its ID. Heartbeat and revoke
// (later tasks) and tests use it.
func (r *Repos) GetPlaybackSession(ctx context.Context, tenantID id.TenantID, hash []byte) (PlaybackSession, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return PlaybackSession{}, err
	}
	row, err := r.q.GetPlaybackSession(ctx, dbgen.GetPlaybackSessionParams{TenantID: tid, IDHash: hash})
	if err != nil {
		return PlaybackSession{}, mapError(err)
	}
	return sessionFromRow(row), nil
}

// PlaybackSessionTenant returns the tenant of the session with the given ID hash, or a not_found
// error. Edge uses it where it has only the session from a request path (a CORS preflight carries
// no token), to find the tenant's allowed origins.
func (r *Repos) PlaybackSessionTenant(ctx context.Context, hash []byte) (id.TenantID, error) {
	tid, err := r.q.GetPlaybackSessionTenant(ctx, hash)
	if err != nil {
		return id.TenantID{}, mapError(err)
	}
	return fromPG[id.TenantKind](tid), nil
}
