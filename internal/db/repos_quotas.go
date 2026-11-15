package db

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// Quotas are the limits of a tenant, or the lower overrides of one client (ADR 0047). A nil field
// is unlimited (for a client: no override of its own). The zero Quotas limits nothing. UpdatedAt is
// the zero time while nothing was ever stored.
type Quotas struct {
	// StorageBytes limits source plus delivery bytes.
	StorageBytes *int64
	// TranscodeMinutesPerMonth limits the minutes of source processed per calendar month (UTC).
	TranscodeMinutesPerMonth *int
	// ConcurrentSessions limits active playback sessions.
	ConcurrentSessions *int
	// RequestsPerMinute limits control-plane requests per API key (per process instance).
	RequestsPerMinute *int
	UpdatedAt         time.Time
}

func int32Ptr(p *int) *int32 {
	if p == nil {
		return nil
	}
	n := int32(min(*p, math.MaxInt32)) //nolint:gosec // clamped
	return &n
}

func intPtr(p *int32) *int {
	if p == nil {
		return nil
	}
	n := int(*p)
	return &n
}

func quotasFromRow(storage *int64, minutes, sessions, rpm *int32, at time.Time) Quotas {
	return Quotas{
		StorageBytes: storage, TranscodeMinutesPerMonth: intPtr(minutes), ConcurrentSessions: intPtr(sessions),
		RequestsPerMinute: intPtr(rpm), UpdatedAt: at.UTC(),
	}
}

// GetTenantQuotas returns the tenant's limits, or the zero Quotas (unlimited) when none are stored.
func (r *Repos) GetTenantQuotas(ctx context.Context, tenantID id.TenantID) (Quotas, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return Quotas{}, err
	}
	row, err := r.q.GetTenantQuotas(ctx, tid)
	if errors.Is(err, pgx.ErrNoRows) {
		return Quotas{}, nil
	}
	if err != nil {
		return Quotas{}, mapError(err)
	}
	return quotasFromRow(row.StorageBytes, row.TranscodeMinutesPerMonth, row.ConcurrentSessions, row.RequestsPerMinute, row.UpdatedAt), nil
}

// PutTenantQuotas replaces the tenant's limits.
func (r *Repos) PutTenantQuotas(ctx context.Context, tenantID id.TenantID, q Quotas, at time.Time) (Quotas, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return Quotas{}, err
	}
	row, err := r.q.UpsertTenantQuotas(ctx, dbgen.UpsertTenantQuotasParams{
		TenantID: tid, StorageBytes: q.StorageBytes, TranscodeMinutesPerMonth: int32Ptr(q.TranscodeMinutesPerMonth),
		ConcurrentSessions: int32Ptr(q.ConcurrentSessions), RequestsPerMinute: int32Ptr(q.RequestsPerMinute), At: at,
	})
	if err != nil {
		return Quotas{}, mapError(err)
	}
	return quotasFromRow(row.StorageBytes, row.TranscodeMinutesPerMonth, row.ConcurrentSessions, row.RequestsPerMinute, row.UpdatedAt), nil
}

// GetClientQuotas returns the client's overrides, or the zero Quotas when it has none. The client
// must belong to the tenant for a row to be found.
func (r *Repos) GetClientQuotas(ctx context.Context, tenantID id.TenantID, clientID id.ClientID) (Quotas, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return Quotas{}, err
	}
	cid, err := requirePG(clientID)
	if err != nil {
		return Quotas{}, err
	}
	row, err := r.q.GetClientQuotas(ctx, dbgen.GetClientQuotasParams{TenantID: tid, ClientID: cid})
	if errors.Is(err, pgx.ErrNoRows) {
		return Quotas{}, nil
	}
	if err != nil {
		return Quotas{}, mapError(err)
	}
	return quotasFromRow(row.StorageBytes, row.TranscodeMinutesPerMonth, row.ConcurrentSessions, row.RequestsPerMinute, row.UpdatedAt), nil
}

// PutClientQuotas replaces the client's overrides. A client of another tenant is not_found.
func (r *Repos) PutClientQuotas(ctx context.Context, tenantID id.TenantID, clientID id.ClientID, q Quotas, at time.Time) (Quotas, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return Quotas{}, err
	}
	cid, err := requirePG(clientID)
	if err != nil {
		return Quotas{}, err
	}
	row, err := r.q.UpsertClientQuotas(ctx, dbgen.UpsertClientQuotasParams{
		TenantID: tid, ClientID: cid, StorageBytes: q.StorageBytes, TranscodeMinutesPerMonth: int32Ptr(q.TranscodeMinutesPerMonth),
		ConcurrentSessions: int32Ptr(q.ConcurrentSessions), RequestsPerMinute: int32Ptr(q.RequestsPerMinute), At: at,
	})
	if err != nil {
		return Quotas{}, mapError(err)
	}
	return quotasFromRow(row.StorageBytes, row.TranscodeMinutesPerMonth, row.ConcurrentSessions, row.RequestsPerMinute, row.UpdatedAt), nil
}

// LockQuota holds the tenant's quota lock until the transaction ends. Take it before a usage check
// whose result must still hold when the row is written.
func (r *Repos) LockQuota(ctx context.Context, tenantID id.TenantID) error {
	if tenantID.IsZero() {
		return errs.New(errs.InvalidRequest, "a required identifier is missing")
	}
	return mapError(r.q.LockQuota(ctx, "cipherframe.quota:"+tenantID.String()))
}

// StorageBytes returns the source plus delivery bytes the tenant's assets hold, from the registries.
// A zero client counts the whole tenant; otherwise only the assets that client created. exclude, when
// not zero, leaves one asset out.
func (r *Repos) StorageBytes(ctx context.Context, tenantID id.TenantID, clientID id.ClientID, exclude id.AssetID) (int64, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return 0, err
	}
	row, err := r.q.StorageUsage(ctx, dbgen.StorageUsageParams{TenantID: tid, ClientID: toPG(clientID), ExcludeAsset: toPG(exclude)})
	if err != nil {
		return 0, mapError(err)
	}
	return row.SourceBytes + row.DeliveryBytes, nil
}

// TranscodeMillis returns the milliseconds of source charged in [from, until), for the tenant or,
// with a client, for that client.
func (r *Repos) TranscodeMillis(ctx context.Context, tenantID id.TenantID, clientID id.ClientID, from, until time.Time) (int64, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return 0, err
	}
	n, err := r.q.TranscodeUsage(ctx, dbgen.TranscodeUsageParams{TenantID: tid, ClientID: toPG(clientID), FromAt: from, UntilAt: until})
	return n, mapError(err)
}

// ChargeTranscode records the duration of an asset's source against its tenant and client. It
// reports false when the asset was charged before (a retry), in which case nothing changes.
func (r *Repos) ChargeTranscode(ctx context.Context, tenantID id.TenantID, assetID id.AssetID, d time.Duration, at time.Time) (bool, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return false, err
	}
	aid, err := requirePG(assetID)
	if err != nil {
		return false, err
	}
	n, err := r.q.InsertTranscodeCharge(ctx, dbgen.InsertTranscodeChargeParams{
		TenantID: tid, AssetID: aid, DurationMs: d.Milliseconds(), At: at,
	})
	return n > 0, mapError(err)
}

// CountActiveSessions counts the tenant's active playback sessions (idle ones past idle do not
// count), or with a client only that client's.
func (r *Repos) CountActiveSessions(ctx context.Context, tenantID id.TenantID, clientID id.ClientID, now time.Time, idle time.Duration) (int, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return 0, err
	}
	n, err := r.q.CountTenantActiveSessions(ctx, dbgen.CountTenantActiveSessionsParams{
		TenantID: tid, ClientID: toPG(clientID), Now: now, IdleSeconds: int32(idle / time.Second), //nolint:gosec // an idle timeout is hours at most
	})
	return int(n), mapError(err)
}
