// Package quota enforces the per-tenant limits, with optional lower per-client overrides, of
// ADR 0047: storage bytes, monthly transcode minutes, concurrent playback sessions and control-plane
// request rates. A limit nobody set is unlimited.
//
// The checks that must not race (storage at creation and commit, sessions, the transcode ledger)
// take the tenant's quota lock inside the caller's transaction and read usage from the registries
// through that same transaction; nothing here takes a second connection from the pool while a
// transaction is open.
package quota

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// The limit names, as they appear in the API and in a quota_exceeded problem's `limit` member.
const (
	LimitStorageBytes       = "storage_bytes"
	LimitTranscodeMinutes   = "transcode_minutes_per_month"
	LimitConcurrentSessions = "concurrent_sessions"
	LimitRequestsPerMinute  = "requests_per_minute"
)

// Audit actions written when limits change.
const (
	AuditTenantUpdate = "quotas.update"
	AuditClientUpdate = "client_quotas.update"
)

// Exceeds reports whether used+add is over limit, without overflowing. Reaching the limit exactly
// is allowed.
func Exceeds(used, add, limit int64) bool {
	if add > 0 {
		return used > limit-add // add and limit are non-negative, so this cannot overflow
	}
	return used > limit
}

// MinPtr returns the lower of two optional limits; nil is unlimited.
func MinPtr[T int | int64](a, b *T) *T {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	}
	return new(min(*a, *b))
}

// Effective is the limits in force for a client: the lower of the tenant's and the client's.
func Effective(tenant, client db.Quotas) db.Quotas {
	return db.Quotas{
		StorageBytes:             MinPtr(tenant.StorageBytes, client.StorageBytes),
		TranscodeMinutesPerMonth: MinPtr(tenant.TranscodeMinutesPerMonth, client.TranscodeMinutesPerMonth),
		ConcurrentSessions:       MinPtr(tenant.ConcurrentSessions, client.ConcurrentSessions),
		RequestsPerMinute:        MinPtr(tenant.RequestsPerMinute, client.RequestsPerMinute),
	}
}

// MonthBounds returns the start of the calendar month (UTC) containing t and the start of the next.
func MonthBounds(t time.Time) (time.Time, time.Time) {
	t = t.UTC()
	from := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	return from, from.AddDate(0, 1, 0)
}

// limits reads the tenant's limits and the client's overrides (the zero client has none).
func limits(ctx context.Context, r *db.Repos, tenant id.TenantID, client id.ClientID) (t, c db.Quotas, err error) {
	if t, err = r.GetTenantQuotas(ctx, tenant); err != nil {
		return
	}
	if !client.IsZero() {
		c, err = r.GetClientQuotas(ctx, tenant, client)
	}
	return
}

// CheckStorage refuses with quota_exceeded (limit storage_bytes) when the tenant's or the client's
// bytes plus add would pass its limit. client is the client whose limit applies (the asset's
// creator); exclude leaves one asset out of the usage (the asset being committed, which is counted
// through add). r must be a transaction: the check holds the tenant's quota lock until it ends, so
// two requests cannot both pass on the same remaining room.
func CheckStorage(ctx context.Context, r *db.Repos, tenant id.TenantID, client id.ClientID, add int64, exclude id.AssetID) error {
	t, c, err := limits(ctx, r, tenant, client)
	if err != nil || (t.StorageBytes == nil && c.StorageBytes == nil) {
		return err
	}
	if err := r.LockQuota(ctx, tenant); err != nil {
		return err
	}
	if t.StorageBytes != nil {
		used, err := r.StorageBytes(ctx, tenant, id.ClientID{}, exclude)
		if err != nil {
			return err
		}
		if Exceeds(used, add, *t.StorageBytes) {
			return errs.Quota(LimitStorageBytes, "The tenant's storage quota would be exceeded.")
		}
	}
	if c.StorageBytes != nil {
		used, err := r.StorageBytes(ctx, tenant, client, exclude)
		if err != nil {
			return err
		}
		if Exceeds(used, add, *c.StorageBytes) {
			return errs.Quota(LimitStorageBytes, "The client's storage quota would be exceeded.")
		}
	}
	return nil
}

// CheckSessions refuses with quota_exceeded (limit concurrent_sessions) when one more active
// session would pass the tenant's limit or, for an API-key session (client not zero), the client's.
// r must be a transaction; the check holds the tenant's quota lock until it ends.
func CheckSessions(ctx context.Context, r *db.Repos, tenant id.TenantID, client id.ClientID, now time.Time, idle time.Duration) error {
	t, c, err := limits(ctx, r, tenant, client)
	if err != nil || (t.ConcurrentSessions == nil && c.ConcurrentSessions == nil) {
		return err
	}
	if err := r.LockQuota(ctx, tenant); err != nil {
		return err
	}
	if t.ConcurrentSessions != nil {
		n, err := r.CountActiveSessions(ctx, tenant, id.ClientID{}, now, idle)
		if err != nil {
			return err
		}
		if Exceeds(int64(n), 1, int64(*t.ConcurrentSessions)) {
			return errs.Quota(LimitConcurrentSessions, "The tenant has the maximum number of concurrent playback sessions.")
		}
	}
	if c.ConcurrentSessions != nil {
		n, err := r.CountActiveSessions(ctx, tenant, client, now, idle)
		if err != nil {
			return err
		}
		if Exceeds(int64(n), 1, int64(*c.ConcurrentSessions)) {
			return errs.Quota(LimitConcurrentSessions, "The client has the maximum number of concurrent playback sessions.")
		}
	}
	return nil
}

// Service charges transcode minutes, reports usage and stores limits. Safe for concurrent use.
type Service struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// NewService builds a Service. now defaults to time.Now.
func NewService(pool *pgxpool.Pool, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{pool: pool, now: now}
}

// ChargeTranscode records an asset's source duration against the month's transcode minutes of its
// tenant and client, once per asset: a retry charges nothing more and is never refused. When the
// charge would pass a limit it is not recorded and the error is quota_exceeded (limit
// transcode_minutes_per_month). The pipeline calls it once the duration is known.
func (s *Service) ChargeTranscode(ctx context.Context, tenant id.TenantID, asset id.AssetID, d time.Duration) error {
	at := s.now().UTC().Truncate(time.Microsecond)
	from, until := MonthBounds(at)
	return db.Tx(ctx, s.pool, func(r *db.Repos) error {
		a, err := r.GetAsset(ctx, tenant, asset)
		if err != nil {
			return err
		}
		t, c, err := limits(ctx, r, tenant, a.CreatedByClientID)
		if err != nil {
			return err
		}
		limited := t.TranscodeMinutesPerMonth != nil || c.TranscodeMinutesPerMonth != nil
		if limited {
			if err := r.LockQuota(ctx, tenant); err != nil {
				return err
			}
		}
		if charged, err := r.ChargeTranscode(ctx, tenant, asset, d, at); err != nil || !charged || !limited {
			return err
		}
		// The new row is already in the sums below, so the check is "usage including this asset".
		if t.TranscodeMinutesPerMonth != nil {
			ms, err := r.TranscodeMillis(ctx, tenant, id.ClientID{}, from, until)
			if err != nil {
				return err
			}
			if ms > int64(*t.TranscodeMinutesPerMonth)*60_000 {
				return errs.Quota(LimitTranscodeMinutes, "The tenant's transcode minutes for this month are used up.")
			}
		}
		if c.TranscodeMinutesPerMonth != nil {
			ms, err := r.TranscodeMillis(ctx, tenant, a.CreatedByClientID, from, until)
			if err != nil {
				return err
			}
			if ms > int64(*c.TranscodeMinutesPerMonth)*60_000 {
				return errs.Quota(LimitTranscodeMinutes, "The client's transcode minutes for this month are used up.")
			}
		}
		return nil
	})
}

// Meter is one usage figure and the limit it is measured against; Limit is nil when unlimited.
type Meter struct {
	Used  int64
	Limit *int64
}

// Usage is the current usage of a tenant, or of one of its clients, against the limits in force.
type Usage struct {
	// MonthStart is the start (UTC) of the month TranscodeMillis counts.
	MonthStart time.Time
	// Storage is in bytes, TranscodeMillis in milliseconds of source (its limit is the minutes
	// limit converted), Sessions in active sessions.
	Storage         Meter
	TranscodeMillis Meter
	Sessions        Meter
	// RequestsPerMinute is the per-key rate limit in force; there is no usage figure for it.
	RequestsPerMinute *int
}

// GetUsage measures the tenant's usage or, with a client, that client's, against the effective
// limits (for a client the lower of its override and the tenant's). The client must belong to the
// tenant (not_found otherwise, like any other client of another tenant).
func (s *Service) GetUsage(ctx context.Context, tenant id.TenantID, client id.ClientID) (Usage, error) {
	now := s.now().UTC()
	r := db.New(s.pool)
	if !client.IsZero() {
		if _, err := r.GetClient(ctx, tenant, client); err != nil {
			return Usage{}, err
		}
	}
	t, c, err := limits(ctx, r, tenant, client)
	if err != nil {
		return Usage{}, err
	}
	eff := Effective(t, c)
	set, err := r.GetPlaybackSettings(ctx, tenant)
	if err != nil {
		return Usage{}, err
	}
	from, until := MonthBounds(now)
	u := Usage{MonthStart: from, RequestsPerMinute: eff.RequestsPerMinute}
	if u.Storage.Used, err = r.StorageBytes(ctx, tenant, client, id.AssetID{}); err != nil {
		return Usage{}, err
	}
	if u.TranscodeMillis.Used, err = r.TranscodeMillis(ctx, tenant, client, from, until); err != nil {
		return Usage{}, err
	}
	n, err := r.CountActiveSessions(ctx, tenant, client, now, time.Duration(set.IdleTimeoutSeconds)*time.Second)
	if err != nil {
		return Usage{}, err
	}
	u.Sessions.Used = int64(n)
	u.Storage.Limit = eff.StorageBytes
	if eff.TranscodeMinutesPerMonth != nil {
		u.TranscodeMillis.Limit = new(int64(*eff.TranscodeMinutesPerMonth) * 60_000)
	}
	if eff.ConcurrentSessions != nil {
		u.Sessions.Limit = new(int64(*eff.ConcurrentSessions))
	}
	return u, nil
}

// Get returns the tenant's limits, or with a client that client's overrides (the client must
// belong to the tenant).
func (s *Service) Get(ctx context.Context, tenant id.TenantID, client id.ClientID) (db.Quotas, error) {
	r := db.New(s.pool)
	if client.IsZero() {
		return r.GetTenantQuotas(ctx, tenant)
	}
	if _, err := r.GetClient(ctx, tenant, client); err != nil {
		return db.Quotas{}, err
	}
	return r.GetClientQuotas(ctx, tenant, client)
}

// Put replaces the tenant's limits, or with a client that client's overrides, and records an audit
// event. A client's override above the tenant's limit is invalid_request: an override can only be
// lower.
func (s *Service) Put(ctx context.Context, tenant id.TenantID, client id.ClientID, actor auth.Actor, in db.Quotas) (db.Quotas, error) {
	var out db.Quotas
	err := db.Tx(ctx, s.pool, func(r *db.Repos) error {
		var err error
		action, target := AuditTenantUpdate, tenant.String()
		if client.IsZero() {
			out, err = r.PutTenantQuotas(ctx, tenant, in, s.now().UTC())
		} else {
			action, target = AuditClientUpdate, client.String()
			var t db.Quotas
			if t, err = r.GetTenantQuotas(ctx, tenant); err != nil {
				return err
			}
			if fields := aboveTenant(in, t); len(fields) > 0 {
				return errs.Invalid("A client's limit cannot be higher than the tenant's.", fields)
			}
			out, err = r.PutClientQuotas(ctx, tenant, client, in, s.now().UTC())
		}
		if err != nil {
			return err
		}
		_, err = r.InsertAuditEvent(ctx, db.NewAuditEvent{
			TenantID: tenant, ClientID: actor.ClientID, APIKeyID: actor.KeyID,
			Action: action, Target: target, RequestID: actor.RequestID,
		})
		return err
	})
	return out, err
}

func aboveTenant(c, t db.Quotas) []errs.FieldError {
	var out []errs.FieldError
	add := func(field string) {
		out = append(out, errs.FieldError{Field: field, Message: "must not be higher than the tenant's limit"})
	}
	if c.StorageBytes != nil && t.StorageBytes != nil && *c.StorageBytes > *t.StorageBytes {
		add(LimitStorageBytes)
	}
	if c.TranscodeMinutesPerMonth != nil && t.TranscodeMinutesPerMonth != nil && *c.TranscodeMinutesPerMonth > *t.TranscodeMinutesPerMonth {
		add(LimitTranscodeMinutes)
	}
	if c.ConcurrentSessions != nil && t.ConcurrentSessions != nil && *c.ConcurrentSessions > *t.ConcurrentSessions {
		add(LimitConcurrentSessions)
	}
	if c.RequestsPerMinute != nil && t.RequestsPerMinute != nil && *c.RequestsPerMinute > *t.RequestsPerMinute {
		add(LimitRequestsPerMinute)
	}
	return out
}
