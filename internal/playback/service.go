// Package playback holds the control-plane logic for playback (ADR 0028, 0030): creating playback
// sessions, and reading and replacing a tenant's playback settings.
//
// A session ID and a playback token are capabilities. This package never logs either, and the
// database stores only the hash of the session ID (see db.SessionHash).
package playback

import (
	"context"
	"errors"
	"net/url"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
)

// Token transports reported to the caller (ADR 0030).
const (
	TransportHeader = "header"
	TransportURL    = "url"
)

// MaxViewerIDChars is the longest viewer ID, in characters.
const MaxViewerIDChars = 128

// Audit action written when settings change (the audit_events.action column). Session creation is
// not audited: it is high volume and the session row is its own record.
const AuditSettingsUpdate = "playback_settings.update"

// Deps are the collaborators of a Service.
type Deps struct {
	Pool    *pgxpool.Pool
	Keyring *token.Keyring
	// EdgeURL is the public base URL of the edge listener, without a trailing slash.
	EdgeURL string
	// Now defaults to time.Now.
	Now func() time.Time
}

// Service implements the playback operations of the API. Safe for concurrent use.
type Service struct {
	pool    *pgxpool.Pool
	repos   *db.Repos
	keyring *token.Keyring
	edge    string
	now     func() time.Time
}

// NewService builds a Service.
func NewService(d Deps) (*Service, error) {
	if d.Pool == nil || d.Keyring == nil {
		return nil, errors.New("playback: a pool and a token keyring are required")
	}
	if d.EdgeURL == "" {
		return nil, errors.New("playback: the edge public URL is required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Service{pool: d.Pool, repos: db.New(d.Pool), keyring: d.Keyring, edge: d.EdgeURL, now: d.Now}, nil
}

// CreateInput is the input of CreateSession.
type CreateInput struct {
	TenantID id.TenantID
	ClientID id.ClientID
	AssetID  id.AssetID
	// ViewerID is the embedding application's pseudonymous ID for the viewer.
	ViewerID string
}

// Created is the result of CreateSession. Token and ManifestURL are redacted in every printed
// form: the manifest URL carries the token when the tenant has token_in_url on.
type Created struct {
	SessionID                id.SessionID
	Token                    config.Secret
	TokenExpiresAt           time.Time
	HeartbeatIntervalSeconds int
	SessionExpiresAt         time.Time
	ManifestURL              config.Secret
	TokenTransport           string
}

// ValidateViewerID checks a viewer ID: 1 to 128 characters, valid UTF-8, printable, no control
// characters.
func ValidateViewerID(v string) error {
	n := utf8.RuneCountInString(v)
	if n < 1 || n > MaxViewerIDChars || !utf8.ValidString(v) {
		return errors.New("must be 1 to 128 characters")
	}
	for _, r := range v {
		if r == unicode.ReplacementChar || !unicode.IsPrint(r) {
			return errors.New("must contain only printable characters, without control characters")
		}
	}
	return nil
}

// CreateSession starts a playback session on a ready asset of the tenant (ADR 0028).
//
// It checks the asset, then, in one transaction holding an advisory lock on the (tenant, viewer)
// pair, ends that viewer's idle or expired sessions, counts the active ones against the tenant's
// limit, and inserts the new session. The lock makes the limit exact under concurrency. The token
// is signed before the transaction so a signing failure leaves no row behind.
func (s *Service) CreateSession(ctx context.Context, in CreateInput) (Created, error) {
	if err := ValidateViewerID(in.ViewerID); err != nil {
		return Created{}, errs.Invalid("The request is invalid.", []errs.FieldError{{Field: "viewer_id", Message: err.Error()}})
	}
	set, err := s.repos.GetPlaybackSettings(ctx, in.TenantID)
	if err != nil {
		return Created{}, err
	}
	asset, err := s.repos.GetAsset(ctx, in.TenantID, in.AssetID)
	if err != nil {
		// Only a real "not found" may become one (I11): a database failure stays a failure.
		var e *errs.Error
		if errors.As(err, &e) && e.Code == errs.NotFound {
			return Created{}, errs.New(errs.NotFound, "No such asset.")
		}
		return Created{}, err
	}
	if asset.State == db.AssetDeleted {
		// Another tenant's asset, a deleted one and an unknown one all look the same.
		return Created{}, errs.New(errs.NotFound, "No such asset.")
	}
	if asset.State != db.AssetReady {
		return Created{}, errs.New(errs.AssetNotReady, "The asset is not ready for playback.")
	}

	sid, err := id.NewSession()
	if err != nil {
		return Created{}, errs.Wrap(errs.InternalError, "An internal error occurred.", err)
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	sessionExpires := now.Add(time.Duration(set.SessionMaxSeconds) * time.Second)
	tokenExpires := now.Add(time.Duration(set.TokenTTLSeconds) * time.Second)
	if tokenExpires.After(sessionExpires) {
		tokenExpires = sessionExpires
	}
	tok, err := s.keyring.Sign(token.Claims{
		SessionID: sid.String(), AssetID: asset.ID.String(),
		Scopes:   token.ScopeManifest | token.ScopeKey | token.ScopeSegment,
		IssuedAt: now, Expiry: tokenExpires,
	})
	if err != nil {
		return Created{}, errs.Wrap(errs.InternalError, "An internal error occurred.", err)
	}

	idle := time.Duration(set.IdleTimeoutSeconds) * time.Second
	err = db.Tx(ctx, s.pool, func(tx *db.Repos) error {
		if err := tx.LockPlaybackViewer(ctx, in.TenantID, in.ViewerID); err != nil {
			return err
		}
		if _, err := tx.EndStalePlaybackSessions(ctx, in.TenantID, in.ViewerID, now, idle); err != nil {
			return err
		}
		if set.MaxSessionsPerViewer > 0 {
			n, err := tx.CountActivePlaybackSessions(ctx, in.TenantID, in.ViewerID, now, idle)
			if err != nil {
				return err
			}
			if n >= set.MaxSessionsPerViewer {
				return errs.New(errs.SessionLimit, "The viewer already has the maximum number of active playback sessions.")
			}
		}
		_, err := tx.InsertPlaybackSession(ctx, db.NewPlaybackSession{
			ID: sid, TenantID: in.TenantID, ClientID: in.ClientID, AssetID: asset.ID,
			ViewerID: in.ViewerID, Now: now, ExpiresAt: sessionExpires,
		})
		if errors.Is(err, db.ErrStateChanged) { // the asset stopped being ready since the check above
			return errs.New(errs.AssetNotReady, "The asset is not ready for playback.")
		}
		return err
	})
	if err != nil {
		return Created{}, err
	}

	manifest := s.edge + "/v1/play/" + sid.String() + "/master.m3u8"
	transport := TransportHeader
	if set.TokenInURL {
		manifest += "?t=" + url.QueryEscape(tok)
		transport = TransportURL
	}
	return Created{
		SessionID: sid, Token: config.NewSecret(tok), TokenExpiresAt: tokenExpires.Truncate(time.Second),
		HeartbeatIntervalSeconds: set.HeartbeatIntervalSeconds, SessionExpiresAt: sessionExpires,
		ManifestURL: config.NewSecret(manifest), TokenTransport: transport,
	}, nil
}

// GetSettings returns the tenant's effective settings: its stored ones, or the defaults.
func (s *Service) GetSettings(ctx context.Context, tenantID id.TenantID) (db.PlaybackSettings, error) {
	return s.repos.GetPlaybackSettings(ctx, tenantID)
}

// PutSettings validates and replaces every setting of the tenant, and records an audit event.
// Invalid settings return invalid_request with one field error per problem.
func (s *Service) PutSettings(ctx context.Context, tenantID id.TenantID, actor auth.Actor, in db.PlaybackSettings) (db.PlaybackSettings, error) {
	if fields := ValidateSettings(in); len(fields) > 0 {
		return db.PlaybackSettings{}, errs.Invalid("The playback settings are invalid.", fields)
	}
	var out db.PlaybackSettings
	err := db.Tx(ctx, s.pool, func(tx *db.Repos) error {
		var err error
		if out, err = tx.PutPlaybackSettings(ctx, tenantID, in, s.now().UTC()); err != nil {
			return err
		}
		_, err = tx.InsertAuditEvent(ctx, db.NewAuditEvent{
			TenantID: tenantID, ClientID: actor.ClientID, APIKeyID: actor.KeyID,
			Action: AuditSettingsUpdate, Target: tenantID.String(), RequestID: actor.RequestID,
		})
		return err
	})
	return out, err
}
