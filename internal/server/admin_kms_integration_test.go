//go:build integration

package server

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/local"
)

func TestMain(m *testing.M) { os.Exit(dbtest.Run(m)) }

func localAt(t *testing.T, current int) *local.Provider {
	t.Helper()
	p, err := local.NewFromKeys(config.Development, map[int][]byte{
		1: bytes.Repeat([]byte{0x41}, config.KEKBytes),
		2: bytes.Repeat([]byte{0x42}, config.KEKBytes),
	}, current, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func managerFor(t *testing.T, pool *pgxpool.Pool, current *local.Provider) *contentkey.Manager {
	t.Helper()
	reg, err := kms.NewRegistry(current)
	if err != nil {
		t.Fatal(err)
	}
	return contentkey.NewManager(pool, reg, slog.New(slog.DiscardHandler))
}

func seedKeys(t *testing.T, pool *pgxpool.Pool, mgr *contentkey.Manager, n int) {
	t.Helper()
	ctx := context.Background()
	repos := db.New(pool)
	tn, err := repos.CreateTenant(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	cl, err := repos.CreateClient(ctx, tn.ID, "app")
	if err != nil {
		t.Fatal(err)
	}
	for range n {
		a, err := repos.CreateAsset(ctx, tn.ID, cl.ID, db.AssetCreated)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Tx(ctx, pool, func(tx *db.Repos) error {
			_, err := mgr.Create(ctx, tx, tn.ID, a.ID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNewWorkerRegistersRewrap(t *testing.T) {
	pool := dbtest.NewMigrated(t)
	w, err := newWorker(pool, managerFor(t, pool, localAt(t, 1)), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if got := w.Kinds(); len(got) != 1 || got[0] != contentkey.RewrapKind {
		t.Fatalf("worker kinds = %v, want [%s]", got, contentkey.RewrapKind)
	}
}

// TestRewrapWaitReportsProgress runs the worker's job through the real worker role and waits the way
// `admin kms-rewrap --wait` does.
func TestRewrapWaitReportsProgress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool := dbtest.NewMigrated(t)
	seedKeys(t, pool, managerFor(t, pool, localAt(t, 1)), 5)

	v2 := localAt(t, 2)
	w, err := newWorker(pool, managerFor(t, pool, v2), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	wctx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- w.Run(wctx) }()
	t.Cleanup(func() { stop(); <-done })

	q, err := jobs.NewQueue(pool, jobs.NewRegistry(), jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	jobID, err := q.Enqueue(ctx, tx, contentkey.RewrapArgs{BatchSize: 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var progress bytes.Buffer
	if err := waitRewrap(ctx, db.New(pool), q, v2, jobID, &progress, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	out := progress.String()
	if !strings.Contains(out, "kms-rewrap: 0 content keys remain on another KEK") {
		t.Fatalf("progress = %q", out)
	}
	usage, err := db.New(pool).CountContentKeysByKEK(ctx)
	if err != nil || len(usage) != 1 || usage[0].KEK.Version != "2" || usage[0].Keys != 5 {
		t.Fatalf("usage = %+v, %v", usage, err)
	}
	if lines := KMSUsageLines(usage); len(lines) != 1 || lines[0] != "provider=local kek_id=local version=2: 5 content keys" {
		t.Fatalf("usage lines = %v", lines)
	}
}

func TestRewrapWaitFailsOnDeadLetter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool := dbtest.NewMigrated(t)
	seedKeys(t, pool, managerFor(t, pool, localAt(t, 1)), 3)
	if _, err := pool.Exec(ctx, "UPDATE content_keys SET wrapped = set_byte(wrapped, 20, get_byte(wrapped, 20) # 1)"); err != nil {
		t.Fatal(err)
	}

	v2 := localAt(t, 2)
	w, err := newWorker(pool, managerFor(t, pool, v2), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	wctx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- w.Run(wctx) }()
	t.Cleanup(func() { stop(); <-done })

	q, err := jobs.NewQueue(pool, jobs.NewRegistry(), jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	jobID, err := q.Enqueue(ctx, tx, contentkey.RewrapArgs{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var progress bytes.Buffer
	err = waitRewrap(ctx, db.New(pool), q, v2, jobID, &progress, 50*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "cancelled") || !strings.Contains(err.Error(), "internal_error") {
		t.Fatalf("got %v, want a failure naming the cancelled job and its code", err)
	}
}
