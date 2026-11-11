package playback

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
)

const (
	// SweepInterval is how often the sweeper runs.
	SweepInterval = 10 * time.Minute
	// sweepGrace is how long after a token's expiry its counter row is kept. The token cannot
	// verify any more, so the row is dead weight; the grace only covers clock skew between
	// replicas.
	sweepGrace = 5 * time.Minute
	// SweepBatch is how many sessions one statement of the expiry sweep ends, and maxSweepPasses
	// bounds how many statements one run issues, so a backlog is worked off over several ticks
	// instead of holding locks for long.
	SweepBatch     = 1000
	maxSweepPasses = 20
)

// Sweeper is what the playback sweeper writes to. *db.Repos implements it.
type Sweeper interface {
	SweepPlaybackKeyFetches(ctx context.Context, before time.Time) (int64, error)
	EndExpiredPlaybackSessions(ctx context.Context, now time.Time, batch int) ([]db.SessionRef, error)
	SweepPlaybackJWTIDs(ctx context.Context, before time.Time) (int64, error)
	InsertAccessLog(ctx context.Context, rows []db.AccessLogRow) error
	EnsureAccessLogPartitions(ctx context.Context, now time.Time, ahead int) (int, error)
}

// AccessLogPartitionsAhead is how many months after the current one the sweeper keeps the access
// log's partitions created for (the current month plus two).
const AccessLogPartitionsAhead = 2

// EnsureAccessLogPartitions creates the access log's monthly partitions for the current month and
// the next AccessLogPartitionsAhead, when missing, and returns how many it created. Without a
// partition for the current time every access-log insert fails, so this runs first in every sweep.
// It is idempotent, so any number of replicas may run it. Nothing ever drops a partition here:
// access-log retention is M6-4.
func EnsureAccessLogPartitions(ctx context.Context, s Sweeper, now time.Time) (int, error) {
	return s.EnsureAccessLogPartitions(ctx, now, AccessLogPartitionsAhead)
}

// SweepKeyFetches deletes the counters of tokens that expired more than a few minutes before now
// and returns how many it deleted. Without it playback_key_fetches would grow by one row per token
// that ever asked for a key. It is idempotent, so any number of replicas may run it.
func SweepKeyFetches(ctx context.Context, s Sweeper, now time.Time) (int64, error) {
	return s.SweepPlaybackKeyFetches(ctx, now.Add(-sweepGrace))
}

// SweepJWTIDs deletes the single-use JWT ids (ADR 0029) whose expiry has passed and returns how
// many it deleted. A row's expiry is the token's exp plus the clock skew allowance, so a token
// whose id was deleted can no longer verify: its exp is in the past even with the allowance. It is
// idempotent, so any number of replicas may run it.
func SweepJWTIDs(ctx context.Context, s Sweeper, now time.Time) (int64, error) {
	return s.SweepPlaybackJWTIDs(ctx, now)
}

// SweepSessions marks active sessions ended when they are past their expiry or idle past their
// tenant's idle timeout, in batches of batch (SweepBatch in production), and returns how many it ended. Nothing depends
// on it for correctness (every check recomputes the same rule from the row's times); it keeps the
// stored state, the status endpoint's ended_at and the active-session indexes honest. A run stops
// after maxSweepPasses batches; the next tick continues. It is idempotent, so any number of
// replicas may run it.
//
// Every session it ends gets an "expired" row in the access log, written directly (not through the
// best-effort queue) right after the batch is ended. A failure to write them is returned after the
// sweep finishes; the sessions stay ended, and their rows are lost (the trail is best effort).
func SweepSessions(ctx context.Context, s Sweeper, now time.Time, batch int) (int64, error) {
	var total int64
	var logErr error
	for range maxSweepPasses {
		ended, err := s.EndExpiredPlaybackSessions(ctx, now, batch)
		n := int64(len(ended))
		total += n
		if n > 0 {
			if err := s.InsertAccessLog(ctx, expiredRows(ended, now)); err != nil {
				logErr = fmt.Errorf("access log: %w", err)
			}
		}
		if err != nil {
			return total, err
		}
		if n < int64(batch) {
			break
		}
	}
	return total, logErr
}

// expiredRows are the access-log rows of sessions the sweep ended. They carry no address or user
// agent: nobody made a request.
func expiredRows(ended []db.SessionRef, at time.Time) []db.AccessLogRow {
	at = at.UTC().Truncate(time.Microsecond)
	rows := make([]db.AccessLogRow, len(ended))
	for i, e := range ended {
		rows[i] = db.AccessLogRow{
			TenantID: e.TenantID, AssetID: e.AssetID, SessionHash: e.IDHash, ViewerID: e.ViewerID,
			AuthMethod: e.AuthMethod, Event: db.AccessExpired, At: at,
		}
	}
	return rows
}

// RunSweeper sweeps every interval until ctx is cancelled (a failure is logged and retried at the
// next tick): access-log partitions (created ahead), key-fetch counters, used JWT ids and expired
// sessions. It sweeps once immediately, so a restarted
// process cleans up at once.
func RunSweeper(ctx context.Context, s Sweeper, interval time.Duration, log *slog.Logger) {
	if interval <= 0 {
		interval = SweepInterval
	}
	run := func() {
		now := time.Now()
		created, err := EnsureAccessLogPartitions(ctx, s, now)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			log.ErrorContext(ctx, "access log partition creation failed", slog.Any("error", err))
		case created > 0:
			log.InfoContext(ctx, "access log partitions created", slog.Int("created", created))
		}
		n, err := SweepKeyFetches(ctx, s, now)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			log.WarnContext(ctx, "key fetch sweep failed", slog.Any("error", err))
		case n > 0:
			log.DebugContext(ctx, "key fetch counters swept", slog.Int64("deleted", n))
		}
		jtis, err := SweepJWTIDs(ctx, s, now)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			log.WarnContext(ctx, "jwt id sweep failed", slog.Any("error", err))
		case jtis > 0:
			log.DebugContext(ctx, "jwt ids swept", slog.Int64("deleted", jtis))
		}
		ended, err := SweepSessions(ctx, s, now, SweepBatch)
		switch {
		case ctx.Err() != nil:
		case err != nil:
			log.WarnContext(ctx, "playback session sweep failed", slog.Any("error", err))
		case ended > 0:
			log.DebugContext(ctx, "playback sessions ended", slog.Int64("ended", ended))
		}
	}
	run()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
