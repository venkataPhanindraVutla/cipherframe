//go:build integration

package jobs_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/telemetry"
)

type traceArgs struct{}

func (traceArgs) Kind() string { return "test.trace" }

// The trace of the request that inserts a job continues in the worker's job span, and the
// queue-depth gauge reads the job table.
func TestJobSpanContinuesTheInsertersTraceAndQueueDepthIsExposed(t *testing.T) {
	pool := newMigrated(t)
	exp := tracetest.NewInMemoryExporter()
	tel, err := telemetry.Setup(context.Background(), telemetry.Options{SpanExporter: exp, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tel.Shutdown(context.Background()) })
	if err := tel.RegisterJobs(pool); err != nil {
		t.Fatal(err)
	}

	reg := jobs.NewRegistry()
	done := make(chan struct{}, 1)
	if err := jobs.Register(reg, func(context.Context, jobs.Job[traceArgs]) error { done <- struct{}{}; return nil }, jobs.KindConfig{}); err != nil {
		t.Fatal(err)
	}

	// Insert while no worker runs, so the queue depth is observable.
	insert := insertOnly(t, pool, reg)
	reqCtx, endReq := telemetry.StartFFmpeg(context.Background(), "probe") // stands in for the inserting request's span
	tx, err := pool.Begin(reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := insert.Enqueue(reqCtx, tx, traceArgs{}, nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(reqCtx); err != nil {
		t.Fatal(err)
	}
	endReq(nil)

	var meta string
	if err := pool.QueryRow(context.Background(), "SELECT metadata::text FROM river_job WHERE kind = 'test.trace'").Scan(&meta); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(meta, "traceparent") {
		t.Fatalf("job metadata has no trace context: %s", meta)
	}

	scrape := func() string {
		t.Helper()
		var sb strings.Builder
		fams, err := tel.Registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fams {
			if f.GetName() != "cipherframe_jobs" {
				continue
			}
			for _, m := range f.GetMetric() {
				l := m.GetLabel()
				fmt.Fprintf(&sb, "%s/%s=%d;", l[0].GetValue(), l[1].GetValue(), int(m.GetGauge().GetValue()))
			}
		}
		return sb.String()
	}
	if got := scrape(); !strings.Contains(got, "test.trace/available=1;") {
		t.Fatalf("queue depth = %q", got)
	}

	startQueue(t, pool, reg)
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("job did not run")
	}
	waitFor(t, 10*time.Second, "job span", func() bool {
		_ = tel.Flush(context.Background())
		return len(exp.GetSpans()) >= 2
	})
	var parent, job tracetest.SpanStub
	for _, s := range exp.GetSpans() {
		switch s.Name {
		case "ffmpeg probe":
			parent = s
		case "job test.trace":
			job = s
		}
	}
	if job.Name == "" || job.SpanContext.TraceID() != parent.SpanContext.TraceID() || job.Parent.SpanID() != parent.SpanContext.SpanID() {
		t.Fatalf("job span is not a child of the inserting span: %+v", job)
	}
}
