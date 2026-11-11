//go:build integration

package jobs_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
)

type mediaArgs struct {
	N int `json:"n"`
}

func (mediaArgs) Kind() string { return "test.media" }

func queueOf(t *testing.T, pool *pgxpool.Pool, jobID int64) string {
	t.Helper()
	var q string
	if err := pool.QueryRow(context.Background(), "SELECT queue FROM river_job WHERE id = $1", jobID).Scan(&q); err != nil {
		t.Fatalf("read queue of job %d: %v", jobID, err)
	}
	return q
}

func TestEnqueueUsesTheKindsQueue(t *testing.T) {
	pool := newMigrated(t)
	reg := jobs.NewRegistry()
	if err := jobs.Register(reg, func(context.Context, jobs.Job[mediaArgs]) error { return nil },
		jobs.KindConfig{Queue: jobs.QueueMedia}); err != nil {
		t.Fatal(err)
	}
	if err := jobs.Register(reg, func(context.Context, jobs.Job[pingArgs]) error { return nil }, jobs.KindConfig{}); err != nil {
		t.Fatal(err)
	}
	q := insertOnly(t, pool, reg)
	if got := queueOf(t, pool, enqueueCommitted(t, pool, q, mediaArgs{}, nil)); got != jobs.QueueMedia {
		t.Fatalf("media kind queue = %q, want %q", got, jobs.QueueMedia)
	}
	if got := queueOf(t, pool, enqueueCommitted(t, pool, q, pingArgs{}, nil)); got != "default" {
		t.Fatalf("plain kind queue = %q, want default", got)
	}
}

// The api role has no handlers; a declared kind still lands on its queue.
func TestDeclaredKindEnqueuesToItsQueue(t *testing.T) {
	pool := newMigrated(t)
	reg := jobs.NewRegistry()
	if err := jobs.Declare[mediaArgs](reg, jobs.KindConfig{Queue: jobs.QueueMedia}); err != nil {
		t.Fatal(err)
	}
	q := insertOnly(t, pool, reg)
	if got := queueOf(t, pool, enqueueCommitted(t, pool, q, mediaArgs{}, nil)); got != jobs.QueueMedia {
		t.Fatalf("declared kind queue = %q, want %q", got, jobs.QueueMedia)
	}
}

func TestWorkerWithQueuesRunsMediaJobs(t *testing.T) {
	pool := newMigrated(t)
	reg := jobs.NewRegistry()
	got := make(chan int, 1)
	if err := jobs.Register(reg, func(_ context.Context, j jobs.Job[mediaArgs]) error {
		got <- j.Args.N
		return nil
	}, jobs.KindConfig{Queue: jobs.QueueMedia}); err != nil {
		t.Fatal(err)
	}
	q, err := jobs.NewQueue(pool, reg, jobs.Config{Workers: 2, Queues: map[string]int{jobs.QueueMedia: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = q.Stop(ctx)
	})
	jobID := enqueueCommitted(t, pool, q, mediaArgs{N: 9}, nil)
	select {
	case n := <-got:
		if n != 9 {
			t.Fatalf("job argument = %d, want 9", n)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("media job did not run")
	}
	waitFor(t, 10*time.Second, "completion", func() bool { return jobRow(t, pool, jobID).State == "completed" })
}

// A worker that does not serve the media queue leaves media jobs untouched.
func TestMediaJobWaitsWithoutMediaWorkers(t *testing.T) {
	pool := newMigrated(t)
	reg := jobs.NewRegistry()
	ran := make(chan struct{}, 1)
	if err := jobs.Register(reg, func(context.Context, jobs.Job[mediaArgs]) error {
		ran <- struct{}{}
		return nil
	}, jobs.KindConfig{Queue: jobs.QueueMedia}); err != nil {
		t.Fatal(err)
	}
	q := startQueue(t, pool, reg) // default queue only
	jobID := enqueueCommitted(t, pool, q, mediaArgs{}, nil)
	select {
	case <-ran:
		t.Fatal("a worker without the media queue ran a media job")
	case <-time.After(3 * time.Second):
	}
	if st := jobRow(t, pool, jobID).State; st != "available" {
		t.Fatalf("job state = %q, want available", st)
	}
}
