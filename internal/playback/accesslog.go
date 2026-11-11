package playback

import (
	"context"
	"errors"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// AuditPrivacyUpdate is the audit action written when a tenant's privacy settings change.
const AuditPrivacyUpdate = "privacy_settings.update"

// GetPrivacy returns the tenant's effective privacy settings: its stored ones, or the defaults
// (everything off).
func (s *Service) GetPrivacy(ctx context.Context, tenantID id.TenantID) (db.PrivacySettings, error) {
	return s.repos.GetPrivacySettings(ctx, tenantID)
}

// PutPrivacy replaces the tenant's privacy settings and records an audit event. The settings apply
// to access-trail rows written afterwards (each edge replica caches them for up to 30 seconds).
func (s *Service) PutPrivacy(ctx context.Context, tenantID id.TenantID, actor auth.Actor, in db.PrivacySettings) (db.PrivacySettings, error) {
	var out db.PrivacySettings
	err := db.Tx(ctx, s.pool, func(tx *db.Repos) error {
		var err error
		if out, err = tx.PutPrivacySettings(ctx, tenantID, in, s.now().UTC()); err != nil {
			return err
		}
		_, err = tx.InsertAuditEvent(ctx, db.NewAuditEvent{
			TenantID: tenantID, ClientID: actor.ClientID, APIKeyID: actor.KeyID,
			Action: AuditPrivacyUpdate, Target: tenantID.String(), RequestID: actor.RequestID,
		})
		return err
	})
	return out, err
}

// AccessLogPage is one page of the access trail, newest first. Next is nil on the last page.
type AccessLogPage struct {
	Entries []db.AccessLogEntry
	Next    *db.AccessLogCursor
}

func checkAccessQuery(q db.AccessLogQuery) error {
	if !q.From.IsZero() && !q.To.IsZero() && !q.From.Before(q.To) {
		return errs.Invalid("The request is invalid.", []errs.FieldError{{Field: "from", Message: "must be before to"}})
	}
	return nil
}

// AssetAccessLog returns the access trail of one asset of the tenant. An asset of another tenant, a
// deleted one and an unknown one are all not_found.
func (s *Service) AssetAccessLog(ctx context.Context, tenantID id.TenantID, assetID id.AssetID, q db.AccessLogQuery) (AccessLogPage, error) {
	if err := checkAccessQuery(q); err != nil {
		return AccessLogPage{}, err
	}
	a, err := s.repos.GetAsset(ctx, tenantID, assetID)
	if err != nil {
		var e *errs.Error
		if errors.As(err, &e) && e.Code == errs.NotFound {
			return AccessLogPage{}, errs.New(errs.NotFound, "No such asset.")
		}
		return AccessLogPage{}, err
	}
	if a.State == db.AssetDeleted {
		return AccessLogPage{}, errs.New(errs.NotFound, "No such asset.")
	}
	entries, next, err := s.repos.ListAssetAccessLog(ctx, tenantID, assetID, q)
	return AccessLogPage{Entries: entries, Next: next}, err
}

// SessionAccessLog returns the access trail of one session of the tenant. A session of another
// tenant and an unknown one are both not_found.
func (s *Service) SessionAccessLog(ctx context.Context, tenantID id.TenantID, sid id.SessionID, q db.AccessLogQuery) (AccessLogPage, error) {
	if err := checkAccessQuery(q); err != nil {
		return AccessLogPage{}, err
	}
	hash := db.SessionHash(sid)
	if _, err := s.repos.GetPlaybackSession(ctx, tenantID, hash); err != nil {
		return AccessLogPage{}, err
	}
	entries, next, err := s.repos.ListSessionAccessLog(ctx, tenantID, hash, q)
	return AccessLogPage{Entries: entries, Next: next}, err
}
