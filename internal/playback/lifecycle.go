package playback

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// Audit actions written when sessions are revoked (the audit_events.action column). A single
// revoke is recorded when it changes the session; a bulk revoke when it revokes at least one.
// Repeating a revoke that finds nothing to do writes nothing.
const (
	AuditSessionRevoke      = "playback_session.revoke"
	AuditSessionRevokeBulk  = "playback_sessions.revoke"
	MaxRevokeReasonChars    = 200
	auditSessionLabelBytes  = 8
	auditSessionTargetLabel = "session:"
)

// SessionStatus is a session as the status endpoint reports it. It never holds a token, and not
// the session ID either: the caller has that.
type SessionStatus struct {
	AssetID          id.AssetID
	ViewerID         string
	State            string
	CreatedAt        time.Time
	LastHeartbeatAt  time.Time
	SessionExpiresAt time.Time
	EndedAt          *time.Time
	RevokedAt        *time.Time
	RevokeReason     string
}

// ValidateRevokeReason checks a revoke reason: at most 200 characters, valid UTF-8, printable, no
// control characters. Empty is valid (no reason).
func ValidateRevokeReason(s string) error {
	if utf8.RuneCountInString(s) > MaxRevokeReasonChars || !utf8.ValidString(s) {
		return errors.New("must be at most 200 characters")
	}
	for _, r := range s {
		if r == unicode.ReplacementChar || !unicode.IsPrint(r) {
			return errors.New("must contain only printable characters, without control characters")
		}
	}
	return nil
}

// statusOf builds the status of a stored session at now. An active session that is past its
// expiry or idle past the idle timeout is reported as ended: it can no longer be used, whether or
// not the sweep has recorded that yet. EndedAt stays unset until it has been recorded.
func statusOf(s db.PlaybackSession, idle time.Duration, now time.Time) SessionStatus {
	state := s.State
	if state == db.PlaybackActive && (!now.Before(s.ExpiresAt) || !now.Before(s.LastHeartbeatAt.Add(idle))) {
		state = db.PlaybackEnded
	}
	return SessionStatus{
		AssetID: s.AssetID, ViewerID: s.ViewerID, State: state, CreatedAt: s.CreatedAt,
		LastHeartbeatAt: s.LastHeartbeatAt, SessionExpiresAt: s.ExpiresAt,
		EndedAt: s.EndedAt, RevokedAt: s.RevokedAt, RevokeReason: s.RevokeReason,
	}
}

// GetSession returns the status of the tenant's session. Another tenant's session and an unknown
// one are both not_found.
func (s *Service) GetSession(ctx context.Context, tenantID id.TenantID, sid id.SessionID) (SessionStatus, error) {
	row, err := s.repos.GetPlaybackSession(ctx, tenantID, db.SessionHash(sid))
	if err != nil {
		return SessionStatus{}, err
	}
	set, err := s.repos.GetPlaybackSettings(ctx, tenantID)
	if err != nil {
		return SessionStatus{}, err
	}
	return statusOf(row, time.Duration(set.IdleTimeoutSeconds)*time.Second, s.now().UTC()), nil
}

// RevokeSession revokes the tenant's session and returns its status. It is idempotent: a revoked
// session is returned as it is (keeping its first reason) and an ended one stays ended. Revoking
// is audited when it changes the session.
func (s *Service) RevokeSession(ctx context.Context, tenantID id.TenantID, actor auth.Actor, sid id.SessionID, reason string) (SessionStatus, error) {
	if err := ValidateRevokeReason(reason); err != nil {
		return SessionStatus{}, errs.Invalid("The request is invalid.", []errs.FieldError{{Field: "reason", Message: err.Error()}})
	}
	set, err := s.repos.GetPlaybackSettings(ctx, tenantID)
	if err != nil {
		return SessionStatus{}, err
	}
	hash := db.SessionHash(sid)
	now := s.now().UTC().Truncate(time.Microsecond)
	var row db.PlaybackSession
	err = db.Tx(ctx, s.pool, func(tx *db.Repos) error {
		var changed bool
		var err error
		if row, changed, err = tx.RevokePlaybackSession(ctx, tenantID, hash, reason, now); err != nil || !changed {
			return err
		}
		_, err = tx.InsertAuditEvent(ctx, db.NewAuditEvent{
			TenantID: tenantID, ClientID: actor.ClientID, APIKeyID: actor.KeyID,
			Action: AuditSessionRevoke, Target: auditSessionTargetLabel + hex.EncodeToString(hash[:auditSessionLabelBytes]),
			RequestID: actor.RequestID,
		})
		return err
	})
	if err != nil {
		return SessionStatus{}, err
	}
	return statusOf(row, time.Duration(set.IdleTimeoutSeconds)*time.Second, now), nil
}

// RevokeSessions revokes every active session of the tenant that matches the viewer and/or the
// asset, and returns how many it revoked. At least one filter is required (invalid_request): a
// tenant-wide revoke is not offered. A bulk revoke that revokes at least one session is audited,
// with the filters and the count in the event's target.
func (s *Service) RevokeSessions(ctx context.Context, tenantID id.TenantID, actor auth.Actor, viewerID string, assetID id.AssetID, reason string) (int64, error) {
	if viewerID == "" && assetID.IsZero() {
		return 0, errs.Invalid("The request is invalid.", []errs.FieldError{{Field: "viewer_id", Message: "viewer_id or asset_id is required"}})
	}
	if viewerID != "" {
		if err := ValidateViewerID(viewerID); err != nil {
			return 0, errs.Invalid("The request is invalid.", []errs.FieldError{{Field: "viewer_id", Message: err.Error()}})
		}
	}
	if err := ValidateRevokeReason(reason); err != nil {
		return 0, errs.Invalid("The request is invalid.", []errs.FieldError{{Field: "reason", Message: err.Error()}})
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	var n int64
	err := db.Tx(ctx, s.pool, func(tx *db.Repos) error {
		var err error
		if n, err = tx.RevokePlaybackSessionsByFilter(ctx, tenantID, viewerID, assetID, reason, now); err != nil || n == 0 {
			return err
		}
		_, err = tx.InsertAuditEvent(ctx, db.NewAuditEvent{
			TenantID: tenantID, ClientID: actor.ClientID, APIKeyID: actor.KeyID,
			Action: AuditSessionRevokeBulk, Target: bulkTarget(viewerID, assetID, n), RequestID: actor.RequestID,
		})
		return err
	})
	return n, err
}

// bulkTarget describes a bulk revoke for the audit log: the filters and how many sessions it hit.
// A viewer ID is the embedding application's pseudonym, which is what the log should show.
func bulkTarget(viewerID string, assetID id.AssetID, n int64) string {
	t := ""
	if viewerID != "" {
		t += "viewer=" + viewerID + " "
	}
	if !assetID.IsZero() {
		t += "asset=" + assetID.String() + " "
	}
	return t + "revoked=" + strconv.FormatInt(n, 10)
}
