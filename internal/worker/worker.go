// Package worker is the background-job role (ADR 0008). Only the skeleton exists: no job kinds are
// registered, so the loop idles until shutdown.
//
// Queue seam (ADR 0007, ADR 0010): the job-queue task replaces the body of Run with a claim loop
// over the queue, and registers each job kind (for example "transcode") in Kinds. FFmpeg and
// FFprobe run as separate processes (invariant 1) and arrive with the transcode task.
//
// This package must not import internal/api or internal/edge (enforced by depguard).
package worker

import (
	"context"
	"log/slog"
)

// Worker is the background-job loop.
type Worker struct {
	log *slog.Logger
}

// New returns a Worker that logs to log.
func New(log *slog.Logger) *Worker {
	if log == nil {
		log = slog.Default()
	}
	return &Worker{log: log}
}

// Kinds returns the registered job kinds. It is empty until the queue task lands.
func (w *Worker) Kinds() []string { return nil }

// Run blocks until ctx is cancelled. With no job kinds registered it only logs that fact once.
func (w *Worker) Run(ctx context.Context) error {
	if len(w.Kinds()) == 0 {
		w.log.InfoContext(ctx, "worker started with no job kinds registered; idle until shutdown")
	}
	<-ctx.Done()
	w.log.InfoContext(ctx, "worker stopped")
	return nil
}
