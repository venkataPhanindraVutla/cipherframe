//go:build integration

package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/health"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/telemetry"
)

type listenerArgs struct{}

func (listenerArgs) Kind() string { return "test.listener" }

// A worker-only process answers health and, with the scrape token, /metrics with the queue depth.
func TestWorkerListenerServesHealthAndMetrics(t *testing.T) {
	const token = "test-fixture-worker-scrape-token"
	pool := dbtest.NewMigrated(t)
	tel, err := telemetry.Setup(context.Background(), telemetry.Options{MetricsToken: token, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tel.Shutdown(context.Background()) })
	if err := tel.RegisterJobs(pool); err != nil {
		t.Fatal(err)
	}

	reg := jobs.NewRegistry()
	if err := jobs.Declare[listenerArgs](reg, jobs.KindConfig{}); err != nil {
		t.Fatal(err)
	}
	q, err := jobs.NewQueue(pool, reg, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(context.Background(), tx, listenerArgs{}, nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}

	ready := health.NewRunner(slog.New(slog.DiscardHandler), time.Second, health.Database(pool))
	srv := httptest.NewServer(tel.Mount(workerHandler(ready)))
	t.Cleanup(srv.Close)

	get := func(path, authz string) (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, _ := get("/healthz", ""); code != http.StatusOK {
		t.Fatalf("/healthz = %d", code)
	}
	if code, body := get("/readyz", ""); code != http.StatusOK || !strings.Contains(body, `"database"`) {
		t.Fatalf("/readyz = %d %s", code, body)
	}
	if code, _ := get("/metrics", ""); code != http.StatusUnauthorized {
		t.Fatalf("/metrics without token = %d", code)
	}
	code, body := get("/metrics", "Bearer "+token)
	if code != http.StatusOK || !strings.Contains(body, `cipherframe_jobs{kind="test.listener",state="available"} 1`) {
		t.Fatalf("/metrics = %d\n%s", code, body)
	}
}
