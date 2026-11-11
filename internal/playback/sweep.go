package playback

import (
	"context"
	"log/slog"
	"time"
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
	EndExpiredPlaybackSessions(ctx context.Context, now time.Time, batch int) (int64, error)
}

// SweepKeyFetches deletes the counters of tokens that expired more than a few minutes before now
// and returns how many it deleted. Without it playback_key_fetches would grow by one row per token
// that ever asked for a key. It is idempotent, so any number of replicas may run it.
func SweepKeyFetches(ctx context.Context, s Sweeper, now time.Time) (int64, error) {
	return s.SweepPlaybackKeyFetches(ctx, now.Add(-sweepGrace))
}

// SweepSessions marks active sessions ended when they are past their expiry or idle past their
// tenant's idle timeout, in batches of batch (SweepBatch in production), and returns how many it ended. Nothing depends
// on it for correctness (every check recomputes the same rule from the row's times); it keeps the
// stored state, the status endpoint's ended_at and the active-session indexes honest. A run stops
// after maxSweepPasses batches; the next tick continues. It is idempotent, so any number of
// replicas may run it.
func SweepSessions(ctx context.Context, s Sweeper, now time.Time, batch int) (int64, error) {
	var total int64
	for range maxSweepPasses {
		n, err := s.EndExpiredPlaybackSessions(ctx, now, batch)
		total += n
		if err != nil {
			return total, err
		}
		if n < int64(batch) {
			break
		}
	}
	return total, nil
}

// RunSweeper sweeps every interval until ctx is cancelled (a failure is logged and retried at the
// next tick): key-fetch counters and expired sessions. It sweeps once immediately, so a restarted
// process cleans up at once.
func RunSweeper(ctx context.Context, s Sweeper, interval time.Duration, log *slog.Logger) {
	if interval <= 0 {
		interval = SweepInterval
	}
	run := func() {
		now := time.Now()
		n, err := SweepKeyFetches(ctx, s, now)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			log.WarnContext(ctx, "key fetch sweep failed", slog.Any("error", err))
		case n > 0:
			log.DebugContext(ctx, "key fetch counters swept", slog.Int64("deleted", n))
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
