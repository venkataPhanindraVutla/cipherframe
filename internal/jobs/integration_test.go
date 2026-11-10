//go:build integration

package jobs_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
)

const defaultPGImage = "postgres:18.6"

var (
	adminURL string
	dbCount  atomic.Int64
)

func TestMain(m *testing.M) { os.Exit(run(m)) }

func run(m *testing.M) int {
	image := os.Getenv("CIPHERFRAME_TEST_PG_IMAGE")
	if image == "" {
		image = defaultPGImage
	}
	ctx := context.Background()
	ctr, err := postgres.Run(ctx, image,
		postgres.WithDatabase("postgres"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot start the test Postgres container:", err)
		return 1
	}
	defer func() { _ = testcontainers.TerminateContainer(ctr) }()
	adminURL, err = ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot read the container connection string:", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "integration tests run against", image)
	return m.Run()
}

// newMigrated creates an empty database in the container, migrates it (goose and River) and
// returns a pool on it.
func newMigrated(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatalf("admin pool: %v", err)
	}
	defer admin.Close()
	name := fmt.Sprintf("j%d", dbCount.Add(1))
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for %s", timeout, what)
}

// startQueue builds a queue with workers, starts it and stops it when the test ends.
func startQueue(t *testing.T, pool *pgxpool.Pool, reg *jobs.Registry) *jobs.Queue {
	t.Helper()
	q, err := jobs.NewQueue(pool, reg, jobs.Config{Workers: 4})
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
	return q
}

func insertOnly(t *testing.T, pool *pgxpool.Pool, reg *jobs.Registry) *jobs.Queue {
	t.Helper()
	q, err := jobs.NewQueue(pool, reg, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func enqueueCommitted(t *testing.T, pool *pgxpool.Pool, q *jobs.Queue, args jobs.Args, opts *jobs.EnqueueOpts) int64 {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	jobID, err := q.Enqueue(ctx, tx, args, opts)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return jobID
}

type riverRow struct {
	State       string
	Attempt     int
	MaxAttempts int
	Errors      string
}

func jobRow(t *testing.T, pool *pgxpool.Pool, jobID int64) riverRow {
	t.Helper()
	var r riverRow
	err := pool.QueryRow(context.Background(),
		"SELECT state::text, attempt, max_attempts, COALESCE(errors::text, '') FROM river_job WHERE id = $1", jobID).
		Scan(&r.State, &r.Attempt, &r.MaxAttempts, &r.Errors)
	if err != nil {
		t.Fatalf("read job %d: %v", jobID, err)
	}
	return r
}

func countRows(t *testing.T, pool *pgxpool.Pool, table string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func wantCode(t *testing.T, err error, code errs.Code) {
	t.Helper()
	var e *errs.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("error = %v, want code %s", err, code)
	}
}

// --- test job kinds ---

type pingArgs struct {
	N int `json:"n"`
}

func (pingArgs) Kind() string { return "test.ping" }

type flakyArgs struct {
	Name string `json:"name"`
}

func (flakyArgs) Kind() string { return "test.flaky" }

type brokenArgs struct {
	Name string `json:"name"`
}

func (brokenArgs) Kind() string { return "test.broken" }

const secretDetail = "https://storage.invalid/source/obj-123?X-Signature=SECRET-TOKEN" //nolint:gosec // fake value; tests check it never leaks

func fastBackoff(int) time.Duration { return 10 * time.Millisecond }

// --- transactional enqueue ---

func TestEnqueueRolledBackLeavesNoJob(t *testing.T) {
	pool := newMigrated(t)
	reg := jobs.NewRegistry()
	q := insertOnly(t, pool, reg)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(ctx, tx, pingArgs{N: 1}, nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, pool, "river_job"); n != 0 {
		t.Fatalf("river_job rows after rollback = %d, want 0", n)
	}
}

func TestCommittedEnqueueRuns(t *testing.T) {
	pool := newMigrated(t)
	reg := jobs.NewRegistry()
	got := make(chan jobs.Job[pingArgs], 1)
	if err := jobs.Register(reg, func(_ context.Context, j jobs.Job[pingArgs]) error {
		got <- j
		return nil
	}, jobs.KindConfig{}); err != nil {
		t.Fatal(err)
	}
	q := startQueue(t, pool, reg)
	jobID := enqueueCommitted(t, pool, q, pingArgs{N: 7}, nil)

	select {
	case j := <-got:
		if j.Args.N != 7 || j.Attempt != 1 || j.MaxAttempts != jobs.DefaultMaxAttempts || j.ID != jobID {
			t.Fatalf("job = %+v", j)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("committed job did not run")
	}
	waitFor(t, 10*time.Second, "completion", func() bool { return jobRow(t, pool, jobID).State == "completed" })
}

func TestEnqueueRespectsPerKindAndPerCallMaxAttempts(t *testing.T) {
	pool := newMigrated(t)
	reg := jobs.NewRegistry()
	if err := jobs.Register(reg, func(context.Context, jobs.Job[pingArgs]) error { return nil },
		jobs.KindConfig{MaxAttempts: 3}); err != nil {
		t.Fatal(err)
	}
	q := insertOnly(t, pool, reg)
	a := enqueueCommitted(t, pool, q, pingArgs{}, nil)
	b := enqueueCommitted(t, pool, q, pingArgs{}, &jobs.EnqueueOpts{MaxAttempts: 9})
	c := enqueueCommitted(t, pool, q, flakyArgs{}, nil) // unregistered kind: default
	if got := jobRow(t, pool, a).MaxAttempts; got != 3 {
		t.Errorf("per-kind max attempts = %d, want 3", got)
	}
	if got := jobRow(t, pool, b).MaxAttempts; got != 9 {
		t.Errorf("per-call max attempts = %d, want 9", got)
	}
	if got := jobRow(t, pool, c).MaxAttempts; got != jobs.DefaultMaxAttempts {
		t.Errorf("default max attempts = %d, want %d", got, jobs.DefaultMaxAttempts)
	}
}

// --- retry policy and dead letters ---

func TestRetryableFailureThenSuccess(t *testing.T) {
	pool := newMigrated(t)
	reg := jobs.NewRegistry()
	var calls atomic.Int32
	if err := jobs.Register(reg, func(_ context.Context, j jobs.Job[flakyArgs]) error {
		if calls.Add(1) == 1 {
			return errs.New(errs.DependencyUnavailable, secretDetail)
		}
		return nil
	}, jobs.KindConfig{Backoff: fastBackoff}); err != nil {
		t.Fatal(err)
	}
	q := startQueue(t, pool, reg)
	jobID := enqueueCommitted(t, pool, q, flakyArgs{Name: "a"}, nil)

	waitFor(t, 30*time.Second, "the retry to succeed", func() bool { return jobRow(t, pool, jobID).State == "completed" })
	r := jobRow(t, pool, jobID)
	if r.Attempt != 2 || calls.Load() != 2 {
		t.Fatalf("attempt = %d, calls = %d, want 2 and 2", r.Attempt, calls.Load())
	}
	if strings.Contains(r.Errors, "SECRET") || strings.Contains(r.Errors, "storage.invalid") {
		t.Fatalf("stored errors leak the handler's error text: %s", r.Errors)
	}
	dead, _, err := q.ListDead(context.Background(), "", 10)
	if err != nil || len(dead) != 0 {
		t.Fatalf("dead = %v, err = %v; a recovered job is not dead", dead, err)
	}
}

func TestNonRetryableErrorIsDeadImmediately(t *testing.T) {
	pool := newMigrated(t)
	reg := jobs.NewRegistry()
	var calls atomic.Int32
	var fixed atomic.Bool
	if err := jobs.Register(reg, func(_ context.Context, j jobs.Job[brokenArgs]) error {
		calls.Add(1)
		if fixed.Load() {
			return nil
		}
		return errs.New(errs.InvalidRequest, secretDetail)
	}, jobs.KindConfig{MaxAttempts: 5, Backoff: fastBackoff}); err != nil {
		t.Fatal(err)
	}
	q := startQueue(t, pool, reg)
	jobID := enqueueCommitted(t, pool, q, brokenArgs{Name: "payload-should-not-be-listed"}, nil)

	var dead []jobs.DeadJob
	waitFor(t, 20*time.Second, "the job to be dead-lettered", func() bool {
		var err error
		dead, _, err = q.ListDead(context.Background(), "", 10)
		return err == nil && len(dead) == 1
	})
	d := dead[0]
	if d.ID != jobID || d.Kind != "test.broken" || d.State != "cancelled" {
		t.Fatalf("dead job = %+v", d)
	}
	if d.Attempts != 1 || d.MaxAttempts != 5 {
		t.Fatalf("attempts = %d of %d, want 1 of 5: a non-retryable error must not be retried", d.Attempts, d.MaxAttempts)
	}
	if d.LastErrorCode != "invalid_request" || d.FinalizedAt == nil || d.CreatedAt.IsZero() {
		t.Fatalf("dead job = %+v", d)
	}
	if calls.Load() != 1 {
		t.Fatalf("handler ran %d times, want 1", calls.Load())
	}
	if raw, _ := json.Marshal(d); strings.Contains(string(raw), "payload-should-not") || strings.Contains(string(raw), "SECRET") {
		t.Fatalf("dead-letter entry leaks arguments or error text: %s", raw)
	}
	if r := jobRow(t, pool, jobID); strings.Contains(r.Errors, "SECRET") {
		t.Fatalf("stored errors leak the handler's error text: %s", r.Errors)
	}

	// Retrying runs it again; this time the handler succeeds.
	fixed.Store(true)
	if err := q.RetryDead(context.Background(), jobID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 20*time.Second, "the retried job to complete", func() bool { return jobRow(t, pool, jobID).State == "completed" })
	if calls.Load() != 2 {
		t.Fatalf("handler ran %d times, want 2", calls.Load())
	}
	dead, _, err := q.ListDead(context.Background(), "", 10)
	if err != nil || len(dead) != 0 {
		t.Fatalf("dead after retry = %v, err = %v", dead, err)
	}
}

func TestAttemptsExhaustedIsDiscarded(t *testing.T) {
	pool := newMigrated(t)
	reg := jobs.NewRegistry()
	var calls atomic.Int32
	if err := jobs.Register(reg, func(context.Context, jobs.Job[flakyArgs]) error {
		calls.Add(1)
		return errors.New("transient " + secretDetail) // unknown error: retried
	}, jobs.KindConfig{MaxAttempts: 2, Backoff: fastBackoff}); err != nil {
		t.Fatal(err)
	}
	q := startQueue(t, pool, reg)
	jobID := enqueueCommitted(t, pool, q, flakyArgs{}, nil)

	waitFor(t, 40*time.Second, "the job to be discarded", func() bool { return jobRow(t, pool, jobID).State == "discarded" })
	dead, _, err := q.ListDead(context.Background(), "", 10)
	if err != nil || len(dead) != 1 {
		t.Fatalf("dead = %v, err = %v", dead, err)
	}
	if dead[0].State != "discarded" || dead[0].Attempts != 2 || dead[0].LastErrorCode != "internal_error" {
		t.Fatalf("dead job = %+v", dead[0])
	}
	if calls.Load() != 2 {
		t.Fatalf("handler ran %d times, want 2", calls.Load())
	}
	if r := jobRow(t, pool, jobID); strings.Contains(r.Errors, "SECRET") {
		t.Fatalf("stored errors leak the handler's error text: %s", r.Errors)
	}
}

func TestPanicIsRetriedWithoutLeaking(t *testing.T) {
	pool := newMigrated(t)
	reg := jobs.NewRegistry()
	var calls atomic.Int32
	if err := jobs.Register(reg, func(context.Context, jobs.Job[flakyArgs]) error {
		if calls.Add(1) == 1 {
			panic(secretDetail)
		}
		return nil
	}, jobs.KindConfig{Backoff: fastBackoff}); err != nil {
		t.Fatal(err)
	}
	q := startQueue(t, pool, reg)
	jobID := enqueueCommitted(t, pool, q, flakyArgs{}, nil)
	waitFor(t, 30*time.Second, "the job to complete after a panic", func() bool { return jobRow(t, pool, jobID).State == "completed" })
	if r := jobRow(t, pool, jobID); strings.Contains(r.Errors, "SECRET") {
		t.Fatalf("stored errors leak the panic value: %s", r.Errors)
	}
}

func TestRetryDeadRejections(t *testing.T) {
	pool := newMigrated(t)
	reg := jobs.NewRegistry()
	if err := jobs.Register(reg, func(context.Context, jobs.Job[pingArgs]) error { return nil }, jobs.KindConfig{}); err != nil {
		t.Fatal(err)
	}
	q := startQueue(t, pool, reg)
	wantCode(t, q.RetryDead(context.Background(), 987654), errs.NotFound)

	jobID := enqueueCommitted(t, pool, q, pingArgs{}, nil)
	waitFor(t, 15*time.Second, "completion", func() bool { return jobRow(t, pool, jobID).State == "completed" })
	wantCode(t, q.RetryDead(context.Background(), jobID), errs.Conflict)
}

func TestListDeadPagination(t *testing.T) {
	pool := newMigrated(t)
	reg := jobs.NewRegistry()
	if err := jobs.Register(reg, func(context.Context, jobs.Job[brokenArgs]) error {
		return errs.New(errs.Forbidden, "no")
	}, jobs.KindConfig{}); err != nil {
		t.Fatal(err)
	}
	q := startQueue(t, pool, reg)
	var ids []int64
	for i := 0; i < 5; i++ {
		ids = append(ids, enqueueCommitted(t, pool, q, brokenArgs{}, nil))
	}
	waitFor(t, 30*time.Second, "all jobs to be dead", func() bool {
		d, _, err := q.ListDead(context.Background(), "", 50)
		return err == nil && len(d) == 5
	})

	seen := map[int64]bool{}
	cursor := ""
	pages := 0
	for {
		page, next, err := q.ListDead(context.Background(), cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		if len(page) > 2 {
			t.Fatalf("page has %d rows, want at most 2", len(page))
		}
		for _, d := range page {
			if seen[d.ID] {
				t.Fatalf("job %d listed twice", d.ID)
			}
			seen[d.ID] = true
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if pages != 3 || len(seen) != 5 {
		t.Fatalf("pages = %d, jobs seen = %d; want 3 and 5", pages, len(seen))
	}
	for _, i := range ids {
		if !seen[i] {
			t.Fatalf("job %d missing from the dead-letter list", i)
		}
	}
	_, _, err := q.ListDead(context.Background(), "garbage", 2)
	wantCode(t, err, errs.InvalidRequest)
}

// --- external hand-off ---

const extKind = "ml.embed"

func newEnvelope(t *testing.T) jobs.Envelope {
	t.Helper()
	asset := id.New[id.AssetKind]()
	return jobs.Envelope{
		Kind:     extKind,
		TenantID: id.New[id.TenantKind](),
		AssetID:  &asset,
		Payload:  json.RawMessage(`{"rendition":"720p"}`),
	}
}

func createTask(t *testing.T, pool *pgxpool.Pool, q *jobs.Queue, env jobs.Envelope, opts *jobs.TaskOpts) jobs.Task {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	task, err := q.CreateTask(ctx, tx, env, opts)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return task
}

type resultSink struct {
	mu    sync.Mutex
	calls []jobs.Result
}

func (s *resultSink) handle(_ context.Context, _ jobs.Task, res jobs.Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, res)
	return nil
}

func (s *resultSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func externalQueue(t *testing.T, pool *pgxpool.Pool, sink *resultSink) *jobs.Queue {
	t.Helper()
	reg := jobs.NewRegistry()
	if err := jobs.RegisterExternal(reg, pool, jobs.ExternalConfig{
		OnResult:     sink.handle,
		PollInterval: 50 * time.Millisecond,
	}); err != nil {
		t.Fatal(err)
	}
	return startQueue(t, pool, reg)
}

func okResult(taskID uuid.UUID) jobs.Result {
	return jobs.Result{
		EnvelopeVersion: jobs.EnvelopeVersion,
		TaskID:          taskID,
		Status:          jobs.StatusSucceeded,
		Artifacts: []jobs.Artifact{{
			Kind:      "ml.embedding",
			Key:       "derived/x/embedding.bin",
			SHA256:    strings.Repeat("ab", 32),
			SizeBytes: 128,
			ModelID:   "example-model", ModelVersion: "1",
		}},
	}
}

func failResult(taskID uuid.UUID, code string, retryable bool) jobs.Result {
	return jobs.Result{
		EnvelopeVersion: jobs.EnvelopeVersion,
		TaskID:          taskID,
		Status:          jobs.StatusFailed,
		Error:           &jobs.TaskError{Code: code, Retryable: retryable, Message: "operator note"},
	}
}

func TestCreateTaskRollsBackWithItsJob(t *testing.T) {
	pool := newMigrated(t)
	q := insertOnly(t, pool, jobs.NewRegistry())
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateTask(ctx, tx, newEnvelope(t), nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if countRows(t, pool, "external_tasks") != 0 || countRows(t, pool, "river_job") != 0 {
		t.Fatal("a rolled-back CreateTask left a task or a job behind")
	}
}

func TestCreateTaskValidatesAndFillsDefaults(t *testing.T) {
	pool := newMigrated(t)
	q := insertOnly(t, pool, jobs.NewRegistry())
	ctx := context.Background()

	bad := newEnvelope(t)
	bad.Kind = "Not A Kind"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = q.CreateTask(ctx, tx, bad, nil)
	_ = tx.Rollback(ctx)
	wantCode(t, err, errs.InvalidRequest)

	task := createTask(t, pool, q, newEnvelope(t), &jobs.TaskOpts{MaxAttempts: 4})
	if task.State != jobs.StatePending || task.Attempts != 0 || task.MaxAttempts != 4 || task.RiverJobID == nil {
		t.Fatalf("task = %+v", task)
	}
	env := task.Envelope
	if env.EnvelopeVersion != 1 || env.Attempt != 1 || env.TaskID != task.ID || env.CreatedAt.IsZero() {
		t.Fatalf("envelope = %+v", env)
	}
	if n := countRows(t, pool, "river_job"); n != 1 {
		t.Fatalf("river_job rows = %d, want 1", n)
	}
}

func TestExternalTaskFullCycle(t *testing.T) {
	pool := newMigrated(t)
	sink := &resultSink{}
	q := externalQueue(t, pool, sink)
	ctx := context.Background()
	task := createTask(t, pool, q, newEnvelope(t), nil)

	// Nothing claims a kind the worker does not handle.
	if got, err := jobs.Claim(ctx, pool, []string{"other.kind"}, "w1", time.Minute); err != nil || got != nil {
		t.Fatalf("claim of another kind = %v, %v", got, err)
	}
	claimed, err := jobs.Claim(ctx, pool, []string{extKind}, "w1", time.Minute)
	if err != nil || claimed == nil {
		t.Fatalf("claim = %v, %v", claimed, err)
	}
	if claimed.ID != task.ID || claimed.State != jobs.StateLeased || claimed.LeaseOwner != "w1" || claimed.Attempts != 0 {
		t.Fatalf("claimed = %+v", claimed)
	}
	if claimed.Envelope.Attempt != 1 || string(claimed.Envelope.Payload) != `{"rendition": "720p"}` && string(claimed.Envelope.Payload) != `{"rendition":"720p"}` {
		t.Fatalf("claimed envelope = %+v (%s)", claimed.Envelope, claimed.Envelope.Payload)
	}
	// A second claim finds nothing: the task is leased.
	if again, err := jobs.Claim(ctx, pool, []string{extKind}, "w2", time.Minute); err != nil || again != nil {
		t.Fatalf("second claim = %v, %v", again, err)
	}
	if err := jobs.Heartbeat(ctx, pool, task.ID, "w1", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := jobs.Complete(ctx, pool, task.ID, "w1", okResult(task.ID)); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 30*time.Second, "the result callback", func() bool { return sink.count() >= 1 })
	sink.mu.Lock()
	res := sink.calls[0]
	sink.mu.Unlock()
	if res.Status != jobs.StatusSucceeded || len(res.Artifacts) != 1 || res.Artifacts[0].Key != "derived/x/embedding.bin" ||
		res.Artifacts[0].ModelID != "example-model" {
		t.Fatalf("callback result = %+v", res)
	}
	var jobState string
	waitFor(t, 10*time.Second, "the await job to complete", func() bool {
		if err := pool.QueryRow(ctx, "SELECT state::text FROM river_job WHERE id = $1", *task.RiverJobID).Scan(&jobState); err != nil {
			return false
		}
		return jobState == "completed"
	})
	final, err := jobs.GetTask(ctx, pool, task.ID)
	if err != nil || final.State != jobs.StateSucceeded || final.CompletedAt == nil || final.LeaseOwner != "" {
		t.Fatalf("final = %+v, %v", final, err)
	}
}

func TestExternalRetryableFailureRequeues(t *testing.T) {
	pool := newMigrated(t)
	sink := &resultSink{}
	q := externalQueue(t, pool, sink)
	ctx := context.Background()
	task := createTask(t, pool, q, newEnvelope(t), &jobs.TaskOpts{MaxAttempts: 3})

	c1, err := jobs.Claim(ctx, pool, []string{extKind}, "w1", time.Minute)
	if err != nil || c1 == nil {
		t.Fatalf("claim: %v %v", c1, err)
	}
	if err := jobs.Fail(ctx, pool, task.ID, "w1", failResult(task.ID, "model_unavailable", true)); err != nil {
		t.Fatal(err)
	}

	// The await job puts the task back to pending with the next attempt number.
	var c2 *jobs.Task
	waitFor(t, 30*time.Second, "the task to be claimable again", func() bool {
		c2, err = jobs.Claim(ctx, pool, []string{extKind}, "w2", time.Minute)
		return err == nil && c2 != nil
	})
	if c2.Attempts != 1 || c2.Envelope.Attempt != 2 || c2.Result != nil {
		t.Fatalf("second claim = attempts %d, envelope attempt %d, result %s", c2.Attempts, c2.Envelope.Attempt, c2.Result)
	}
	if err := jobs.Complete(ctx, pool, task.ID, "w2", okResult(task.ID)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 30*time.Second, "the result callback", func() bool { return sink.count() == 1 })
	dead, _, err := q.ListDead(ctx, "", 10)
	if err != nil || len(dead) != 0 {
		t.Fatalf("dead = %v, %v; a recovered task is not dead", dead, err)
	}
}

func TestExternalNonRetryableFailureIsDead(t *testing.T) {
	pool := newMigrated(t)
	sink := &resultSink{}
	q := externalQueue(t, pool, sink)
	ctx := context.Background()
	task := createTask(t, pool, q, newEnvelope(t), nil)

	if c, err := jobs.Claim(ctx, pool, []string{extKind}, "w1", time.Minute); err != nil || c == nil {
		t.Fatalf("claim: %v %v", c, err)
	}
	if err := jobs.Fail(ctx, pool, task.ID, "w1", failResult(task.ID, "unsupported_media", false)); err != nil {
		t.Fatal(err)
	}
	var dead []jobs.DeadJob
	waitFor(t, 30*time.Second, "the await job to be dead-lettered", func() bool {
		var err error
		dead, _, err = q.ListDead(ctx, "", 10)
		return err == nil && len(dead) == 1
	})
	if dead[0].Kind != jobs.AwaitKind || dead[0].State != "cancelled" || dead[0].LastErrorCode != "unsupported_media" || dead[0].Attempts != 1 {
		t.Fatalf("dead = %+v", dead[0])
	}
	if sink.count() != 0 {
		t.Fatal("the result callback ran for a failed task")
	}
	// The task stays failed and is never offered again.
	if c, err := jobs.Claim(ctx, pool, []string{extKind}, "w2", time.Minute); err != nil || c != nil {
		t.Fatalf("claim of a failed task = %v, %v", c, err)
	}
}

func TestExternalRetriesRunOutAtMaxAttempts(t *testing.T) {
	pool := newMigrated(t)
	q := externalQueue(t, pool, &resultSink{})
	ctx := context.Background()
	task := createTask(t, pool, q, newEnvelope(t), &jobs.TaskOpts{MaxAttempts: 1})

	if c, err := jobs.Claim(ctx, pool, []string{extKind}, "w1", time.Minute); err != nil || c == nil {
		t.Fatalf("claim: %v %v", c, err)
	}
	if err := jobs.Fail(ctx, pool, task.ID, "w1", failResult(task.ID, "model_unavailable", true)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 30*time.Second, "the exhausted task to be dead-lettered", func() bool {
		dead, _, err := q.ListDead(ctx, "", 10)
		return err == nil && len(dead) == 1 && dead[0].LastErrorCode == "model_unavailable"
	})
	if got, _ := jobs.GetTask(ctx, pool, task.ID); got.State != jobs.StateFailed || got.Attempts != 0 {
		t.Fatalf("task = %+v, want failed at attempt 0", got)
	}
}

func TestExternalMalformedResultFailsClosed(t *testing.T) {
	pool := newMigrated(t)
	sink := &resultSink{}
	q := externalQueue(t, pool, sink)
	ctx := context.Background()
	task := createTask(t, pool, q, newEnvelope(t), nil)

	if c, err := jobs.Claim(ctx, pool, []string{extKind}, "w1", time.Minute); err != nil || c == nil {
		t.Fatalf("claim: %v %v", c, err)
	}
	// A worker that bypasses the Go helpers and writes a result that breaks the contract.
	if _, err := pool.Exec(ctx, `UPDATE external_tasks SET state = 'succeeded', result = '{"status":"succeeded"}',
		lease_owner = NULL, lease_until = NULL WHERE id = $1`, task.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 30*time.Second, "the await job to be dead-lettered", func() bool {
		dead, _, err := q.ListDead(ctx, "", 10)
		return err == nil && len(dead) == 1 && dead[0].LastErrorCode == jobs.CodeInvalidResult
	})
	if sink.count() != 0 {
		t.Fatal("a malformed result reached the callback")
	}
}

func TestLeaseExpiryLetsAnotherWorkerReclaim(t *testing.T) {
	pool := newMigrated(t)
	q := insertOnly(t, pool, jobs.NewRegistry())
	ctx := context.Background()
	task := createTask(t, pool, q, newEnvelope(t), &jobs.TaskOpts{MaxAttempts: 3})

	c1, err := jobs.Claim(ctx, pool, []string{extKind}, "w1", 700*time.Millisecond)
	if err != nil || c1 == nil || c1.Attempts != 0 {
		t.Fatalf("claim: %v %v", c1, err)
	}
	// While the lease is valid nobody else can take the task.
	if c, err := jobs.Claim(ctx, pool, []string{extKind}, "w2", time.Minute); err != nil || c != nil {
		t.Fatalf("claim during a live lease = %v, %v", c, err)
	}
	time.Sleep(900 * time.Millisecond)

	c2, err := jobs.Claim(ctx, pool, []string{extKind}, "w2", time.Minute)
	if err != nil || c2 == nil {
		t.Fatalf("reclaim after expiry: %v %v", c2, err)
	}
	if c2.ID != task.ID || c2.LeaseOwner != "w2" || c2.Attempts != 1 || c2.Envelope.Attempt != 2 {
		t.Fatalf("reclaimed = %+v", c2)
	}
	// The first worker lost its lease and can neither extend it nor write a result.
	wantCode(t, jobs.Heartbeat(ctx, pool, task.ID, "w1", time.Minute), errs.Conflict)
	wantCode(t, jobs.Complete(ctx, pool, task.ID, "w1", okResult(task.ID)), errs.Conflict)
	wantCode(t, jobs.Fail(ctx, pool, task.ID, "w1", failResult(task.ID, "late", true)), errs.Conflict)
	if got, _ := jobs.GetTask(ctx, pool, task.ID); got.State != jobs.StateLeased || got.LeaseOwner != "w2" || got.Result != nil {
		t.Fatalf("task after the stale writes = %+v", got)
	}
	if err := jobs.Complete(ctx, pool, task.ID, "w2", okResult(task.ID)); err != nil {
		t.Fatal(err)
	}
}

func TestHeartbeatKeepsTheLease(t *testing.T) {
	pool := newMigrated(t)
	q := insertOnly(t, pool, jobs.NewRegistry())
	ctx := context.Background()
	task := createTask(t, pool, q, newEnvelope(t), nil)
	if c, err := jobs.Claim(ctx, pool, []string{extKind}, "w1", 800*time.Millisecond); err != nil || c == nil {
		t.Fatalf("claim: %v %v", c, err)
	}
	for i := 0; i < 3; i++ {
		time.Sleep(400 * time.Millisecond)
		if err := jobs.Heartbeat(ctx, pool, task.ID, "w1", 800*time.Millisecond); err != nil {
			t.Fatalf("heartbeat %d: %v", i, err)
		}
		if c, err := jobs.Claim(ctx, pool, []string{extKind}, "w2", time.Minute); err != nil || c != nil {
			t.Fatalf("a heartbeating task was reclaimed: %v %v", c, err)
		}
	}
}

func TestWrongLeaseOwnerCannotWrite(t *testing.T) {
	pool := newMigrated(t)
	q := insertOnly(t, pool, jobs.NewRegistry())
	ctx := context.Background()
	task := createTask(t, pool, q, newEnvelope(t), nil)
	if c, err := jobs.Claim(ctx, pool, []string{extKind}, "owner", time.Minute); err != nil || c == nil {
		t.Fatalf("claim: %v %v", c, err)
	}
	wantCode(t, jobs.Complete(ctx, pool, task.ID, "intruder", okResult(task.ID)), errs.Conflict)
	wantCode(t, jobs.Fail(ctx, pool, task.ID, "intruder", failResult(task.ID, "x_error", false)), errs.Conflict)
	wantCode(t, jobs.Heartbeat(ctx, pool, task.ID, "intruder", time.Minute), errs.Conflict)
	got, err := jobs.GetTask(ctx, pool, task.ID)
	if err != nil || got.State != jobs.StateLeased || got.LeaseOwner != "owner" || got.Result != nil {
		t.Fatalf("task changed by a worker without the lease: %+v, %v", got, err)
	}
	// A result for a different task or of the wrong status is rejected before touching the row.
	other := okResult(uuid.NewV7())
	wantCode(t, jobs.Complete(ctx, pool, task.ID, "owner", other), errs.InvalidRequest)
	wantCode(t, jobs.Complete(ctx, pool, task.ID, "owner", failResult(task.ID, "x_error", false)), errs.InvalidRequest)
	if err := jobs.Complete(ctx, pool, task.ID, "owner", okResult(task.ID)); err != nil {
		t.Fatal(err)
	}
	// Once completed the lease is gone: a second write is refused.
	wantCode(t, jobs.Complete(ctx, pool, task.ID, "owner", okResult(task.ID)), errs.Conflict)
}

func TestExpiredLeaseWithNoAttemptLeftFailsTheTask(t *testing.T) {
	pool := newMigrated(t)
	q := externalQueue(t, pool, &resultSink{})
	ctx := context.Background()
	task := createTask(t, pool, q, newEnvelope(t), &jobs.TaskOpts{MaxAttempts: 1})

	if c, err := jobs.Claim(ctx, pool, []string{extKind}, "crashy", 300*time.Millisecond); err != nil || c == nil {
		t.Fatalf("claim: %v %v", c, err)
	}
	time.Sleep(400 * time.Millisecond)
	// With one attempt, the expired lease may not be claimed again.
	if c, err := jobs.Claim(ctx, pool, []string{extKind}, "w2", time.Minute); err != nil || c != nil {
		t.Fatalf("an exhausted task was reclaimed: %v %v", c, err)
	}
	waitFor(t, 30*time.Second, "the await job to fail the task", func() bool {
		dead, _, err := q.ListDead(ctx, "", 10)
		return err == nil && len(dead) == 1 && dead[0].LastErrorCode == jobs.CodeLeaseExpired
	})
	got, err := jobs.GetTask(ctx, pool, task.ID)
	if err != nil || got.State != jobs.StateFailed {
		t.Fatalf("task = %+v, %v", got, err)
	}
	if res, err := jobs.ParseResult(got.Result); err != nil || res.Error == nil || res.Error.Code != jobs.CodeLeaseExpired {
		t.Fatalf("result = %+v, %v", res, err)
	}
}

func TestConcurrentClaimsNeverDoubleClaim(t *testing.T) {
	pool := newMigrated(t)
	q := insertOnly(t, pool, jobs.NewRegistry())
	ctx := context.Background()
	const tasks, workers = 12, 6
	want := map[uuid.UUID]bool{}
	for i := 0; i < tasks; i++ {
		want[createTask(t, pool, q, newEnvelope(t), nil).ID] = true
	}

	var mu sync.Mutex
	claimed := map[uuid.UUID]string{}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		owner := fmt.Sprintf("w%d", w)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				c, err := jobs.Claim(ctx, pool, []string{extKind}, owner, time.Minute)
				if err != nil {
					t.Errorf("claim: %v", err)
					return
				}
				if c == nil {
					return
				}
				mu.Lock()
				if prev, dup := claimed[c.ID]; dup {
					t.Errorf("task %s claimed by %s and %s", c.ID, prev, owner)
				}
				claimed[c.ID] = owner
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(claimed) != tasks {
		t.Fatalf("claimed %d tasks, want %d", len(claimed), tasks)
	}
	for id := range want {
		if _, ok := claimed[id]; !ok {
			t.Fatalf("task %s was never claimed", id)
		}
	}
}

func TestHandOffTableConstraints(t *testing.T) {
	pool := newMigrated(t)
	ctx := context.Background()
	other := uuid.NewV7()
	// The envelope must describe the row it is stored in.
	_, err := pool.Exec(ctx, `INSERT INTO external_tasks (id, kind, envelope, max_attempts)
		VALUES ($1, 'ml.embed', jsonb_build_object('task_id', $2::text, 'kind', 'ml.embed'), 3)`, uuid.NewV7(), other.String())
	if err == nil {
		t.Fatal("an envelope for another task id was accepted")
	}
	_, err = pool.Exec(ctx, `INSERT INTO external_tasks (id, kind, envelope, max_attempts, state)
		VALUES ($1, 'ml.embed', jsonb_build_object('task_id', $1::text, 'kind', 'ml.embed'), 3, 'running')`, other)
	if err == nil {
		t.Fatal("an unknown state was accepted")
	}
	_, err = pool.Exec(ctx, `INSERT INTO external_tasks (id, kind, envelope, max_attempts)
		VALUES ($1, 'ml.embed', jsonb_build_object('task_id', $1::text, 'kind', 'ml.embed'), 0)`, other)
	if err == nil {
		t.Fatal("max_attempts = 0 was accepted")
	}
}

func TestStopWithoutWorkers(t *testing.T) {
	pool := newMigrated(t)
	q := insertOnly(t, pool, jobs.NewRegistry())
	if err := q.Start(context.Background()); err == nil {
		t.Fatal("an insert-only queue must not start")
	}
	if err := q.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCheckReady(t *testing.T) {
	ctx := context.Background()
	// An unmigrated database is not ready.
	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	name := fmt.Sprintf("j%d", dbCount.Add(1))
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	empty, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close()
	if err := jobs.CheckReady(ctx, empty); err == nil {
		t.Fatal("an unmigrated database must not be ready")
	}
	// A migrated one is.
	if err := jobs.CheckReady(ctx, newMigrated(t)); err != nil {
		t.Fatalf("migrated database: %v", err)
	}
}
