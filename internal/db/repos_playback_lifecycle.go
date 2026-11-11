package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// HeartbeatOutcome is what HeartbeatPlaybackSession decided.
type HeartbeatOutcome int

// The outcomes of a heartbeat.
const (
	// HeartbeatRecorded: last_heartbeat_at was set to now.
	HeartbeatRecorded HeartbeatOutcome = iota
	// HeartbeatTooSoon: the session is usable but its previous heartbeat is younger than the
	// minimum gap. Nothing was written.
	HeartbeatTooSoon
	// HeartbeatUnusable: the session is unknown, for another asset, not active, expired or idle.
	HeartbeatUnusable
)

// HeartbeatPlaybackSession records a heartbeat for a session, in one UPDATE: only when the session
// is for the asset, active, before its expiry, not idle (judged on the previous heartbeat) and
// when that previous heartbeat is at least minGap old. On HeartbeatRecorded it returns the updated
// row. On HeartbeatTooSoon retry is how long until a heartbeat is accepted.
func (r *Repos) HeartbeatPlaybackSession(ctx context.Context, tenantID id.TenantID, hash []byte, assetID id.AssetID, now time.Time, idle, minGap time.Duration) (row PlaybackSession, outcome HeartbeatOutcome, retry time.Duration, err error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return PlaybackSession{}, HeartbeatUnusable, 0, err
	}
	aid, err := requirePG(assetID)
	if err != nil {
		return PlaybackSession{}, HeartbeatUnusable, 0, err
	}
	got, err := r.q.HeartbeatPlaybackSession(ctx, dbgen.HeartbeatPlaybackSessionParams{
		Now: now, TenantID: tid, IDHash: hash, AssetID: aid,
		IdleSeconds:   int32(idle / time.Second),   //nolint:gosec // bounded by the settings range
		MinGapSeconds: int32(minGap / time.Second), //nolint:gosec // small
	})
	if err == nil {
		return sessionFromRow(got), HeartbeatRecorded, 0, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return PlaybackSession{}, HeartbeatUnusable, 0, mapError(err)
	}
	// Not updated: usable but too soon, or unusable. Reading afterwards is safe: a session that
	// became unusable in between is reported as such, and one that was usable stays rejected.
	cur, err := r.GetPlaybackSession(ctx, tenantID, hash)
	if err != nil {
		var e *errs.Error
		if errors.As(err, &e) && e.Code == errs.NotFound {
			return PlaybackSession{}, HeartbeatUnusable, 0, nil
		}
		return PlaybackSession{}, HeartbeatUnusable, 0, err
	}
	if cur.AssetID == assetID && cur.State == PlaybackActive && now.Before(cur.ExpiresAt) && now.Before(cur.LastHeartbeatAt.Add(idle)) {
		return PlaybackSession{}, HeartbeatTooSoon, max(cur.LastHeartbeatAt.Add(minGap).Sub(now), 0), nil
	}
	return PlaybackSession{}, HeartbeatUnusable, 0, nil
}

// EndPlaybackSession marks an active session ended and reports whether it changed anything. An
// ended or revoked session is left as it is (ended is idempotent, revoked stays revoked), and an
// unknown session is not an error.
func (r *Repos) EndPlaybackSession(ctx context.Context, tenantID id.TenantID, hash []byte, now time.Time) (bool, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return false, err
	}
	n, err := r.q.EndPlaybackSession(ctx, dbgen.EndPlaybackSessionParams{Now: now, TenantID: tid, IDHash: hash})
	return n > 0, mapError(err)
}

// RevokePlaybackSession revokes the tenant's session. An active session becomes revoked (changed
// is true). A session that is already revoked is returned as it is, keeping its first reason, and
// so is an ended one: revoking never rewrites history (changed is false). An unknown session, or
// another tenant's, is a not_found error.
func (r *Repos) RevokePlaybackSession(ctx context.Context, tenantID id.TenantID, hash []byte, reason string, now time.Time) (row PlaybackSession, changed bool, err error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return PlaybackSession{}, false, err
	}
	got, err := r.q.RevokePlaybackSession(ctx, dbgen.RevokePlaybackSessionParams{
		Now: now, Reason: strPtr(reason), TenantID: tid, IDHash: hash,
	})
	if err == nil {
		return sessionFromRow(got), true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return PlaybackSession{}, false, mapError(err)
	}
	cur, err := r.GetPlaybackSession(ctx, tenantID, hash)
	return cur, false, err
}

// RevokePlaybackSessionsByFilter revokes the tenant's active sessions of one viewer (viewerID not
// empty) and/or one asset (assetID not zero) and returns how many it revoked. At least one filter
// is required: it never revokes every session of a tenant.
func (r *Repos) RevokePlaybackSessionsByFilter(ctx context.Context, tenantID id.TenantID, viewerID string, assetID id.AssetID, reason string, now time.Time) (int64, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return 0, err
	}
	if viewerID == "" && assetID.IsZero() {
		return 0, errs.New(errs.InvalidRequest, "a viewer or an asset filter is required")
	}
	n, err := r.q.RevokePlaybackSessionsByFilter(ctx, dbgen.RevokePlaybackSessionsByFilterParams{
		Now: now, Reason: strPtr(reason), TenantID: tid, ViewerID: strPtr(viewerID), AssetID: toPG(assetID),
	})
	return n, mapError(err)
}

// MinIdleTimeoutSeconds is the smallest idle timeout a tenant can configure (see
// playback.ValidateSettings). The sweep uses it to narrow its index scan.
const MinIdleTimeoutSeconds = 30

// EndExpiredPlaybackSessions ends up to batch active sessions, across tenants, that are past
// their expiry or idle past their tenant's idle timeout, and returns how many it ended.
func (r *Repos) EndExpiredPlaybackSessions(ctx context.Context, now time.Time, batch int) (int64, error) {
	if batch < 1 {
		return 0, errs.New(errs.InvalidRequest, "invalid batch size")
	}
	n, err := r.q.EndExpiredPlaybackSessions(ctx, dbgen.EndExpiredPlaybackSessionsParams{
		Now: now, MinIdleSeconds: MinIdleTimeoutSeconds,
		DefaultIdleSeconds: int32(DefaultPlaybackSettings().IdleTimeoutSeconds), //nolint:gosec // constant
		Batch:              int32(batch),                                        //nolint:gosec // small
	})
	return n, mapError(err)
}
