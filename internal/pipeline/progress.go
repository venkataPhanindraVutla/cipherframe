package pipeline

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Progress is a 0-100 hint for clients, spread over the job: the transcode covers 0 to
// transcodeShare, the upload the rest up to uploadShare, and 100 is written by the transition to
// ready.
const (
	transcodeShare = 90
	uploadShare    = 99
)

// reporter writes the progress column at most once per interval, from its own goroutine, so a slow
// database can never stall FFmpeg's output pipe. Only the latest value matters.
type reporter struct {
	set      func(ctx context.Context, percent int) error
	interval time.Duration

	latest atomic.Int32
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// startReporter begins reporting. Stop it with stop.
func startReporter(ctx context.Context, interval time.Duration, set func(ctx context.Context, percent int) error) *reporter {
	ctx, cancel := context.WithCancel(ctx)
	r := &reporter{set: set, interval: interval, cancel: cancel}
	r.latest.Store(-1)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		t := time.NewTicker(interval)
		defer t.Stop()
		last := int32(-1)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if cur := r.latest.Load(); cur > last {
					// Progress is best effort: a failed write is simply tried again with the next value.
					wctx, wcancel := context.WithTimeout(ctx, 5*time.Second)
					if err := r.set(wctx, int(cur)); err == nil {
						last = cur
					}
					wcancel()
				}
			}
		}
	}()
	return r
}

// transcoded reports how far the transcode is: done of total.
func (r *reporter) transcoded(done, total time.Duration) {
	if total <= 0 {
		return
	}
	p := int(float64(done) / float64(total) * transcodeShare)
	r.latest.Store(int32(min(max(p, 0), transcodeShare))) //nolint:gosec // 0..90
}

func (r *reporter) stop() {
	r.cancel()
	r.wg.Wait()
}
