package playback

import (
	"context"
	"log/slog"
	"time"
)

const (
	// SweepInterval is how often the key-fetch sweeper runs.
	SweepInterval = 10 * time.Minute
	// sweepGrace is how long after a token's expiry its counter row is kept. The token cannot
	// verify any more, so the row is dead weight; the grace only covers clock skew between
	// replicas.
	sweepGrace = 5 * time.Minute
)

// KeyFetchSweeper deletes key-fetch counters. *db.Repos implements it.
type KeyFetchSweeper interface {
	SweepPlaybackKeyFetches(ctx context.Context, before time.Time) (int64, error)
}

// SweepKeyFetches deletes the counters of tokens that expired more than a few minutes before now
// and returns how many it deleted. Without it playback_key_fetches would grow by one row per token
// that ever asked for a key. It is idempotent, so any number of replicas may run it.
func SweepKeyFetches(ctx context.Context, s KeyFetchSweeper, now time.Time) (int64, error) {
	return s.SweepPlaybackKeyFetches(ctx, now.Add(-sweepGrace))
}

// RunKeyFetchSweeper sweeps every interval until ctx is cancelled (a failure is logged and
// retried at the next tick). It sweeps once immediately, so a restarted process cleans up at once.
func RunKeyFetchSweeper(ctx context.Context, s KeyFetchSweeper, interval time.Duration, log *slog.Logger) {
	if interval <= 0 {
		interval = SweepInterval
	}
	run := func() {
		n, err := SweepKeyFetches(ctx, s, time.Now())
		switch {
		case ctx.Err() != nil:
		case err != nil:
			log.WarnContext(ctx, "key fetch sweep failed", slog.Any("error", err))
		case n > 0:
			log.DebugContext(ctx, "key fetch counters swept", slog.Int64("deleted", n))
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
