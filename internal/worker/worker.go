// Package worker is the background-job role (ADR 0008). It runs the job queue when job kinds are
// registered; until a milestone registers one (for example transcoding in M3) it idles until
// shutdown. FFmpeg and FFprobe run as separate processes (invariant 1) and arrive with M3.
//
// This package must not import internal/api or internal/edge (enforced by depguard).
package worker

import (
	"context"
	"log/slog"
	"time"
)

// StopGrace is how long running jobs get to finish after shutdown begins. Jobs still running are
// cancelled and retried later (they are idempotent).
const StopGrace = 20 * time.Second

// Runner is the part of the job queue the worker drives. *jobs.Queue satisfies it.
type Runner interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// Worker is the background-job loop.
type Worker struct {
	log   *slog.Logger
	queue Runner
	kinds []string
}

// New returns a Worker. queue may be nil when no job kinds are registered; kinds lists them.
func New(log *slog.Logger, queue Runner, kinds []string) *Worker {
	if log == nil {
		log = slog.Default()
	}
	return &Worker{log: log, queue: queue, kinds: kinds}
}

// Kinds returns the registered job kinds.
func (w *Worker) Kinds() []string { return w.kinds }

// Run works jobs until ctx is cancelled, then stops the queue within StopGrace.
func (w *Worker) Run(ctx context.Context) error {
	if w.queue == nil || len(w.kinds) == 0 {
		w.log.InfoContext(ctx, "worker started with no job kinds registered; idle until shutdown")
		<-ctx.Done()
		w.log.InfoContext(ctx, "worker stopped")
		return nil
	}
	if err := w.queue.Start(ctx); err != nil {
		return err
	}
	w.log.InfoContext(ctx, "worker started", slog.Any("kinds", w.kinds))
	<-ctx.Done()
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), StopGrace)
	defer cancel()
	err := w.queue.Stop(stopCtx)
	w.log.InfoContext(ctx, "worker stopped")
	return err
}
