// Package jobs is Cipherframe's job queue (ADR 0007) and the Go side of the language-neutral
// hand-off to external workers (ADR 0010).
//
// Handlers register typed job kinds through this package and never import River. Jobs are
// inserted in the caller's database transaction, so a job exists if and only if the state change
// that needs it committed. Delivery is at-least-once: a handler may run more than once for the
// same job and must be idempotent.
//
// Error policy: a handler that returns an *errs.Error whose registered code is not retryable has
// its job cancelled at once; a retryable code, an unregistered code and any other error retry with
// backoff until the kind's attempt limit, after which the job is discarded. Cancelled and discarded
// jobs form the dead-letter list (ListDead, RetryDead).
//
// Nothing in this package logs a job's arguments or an error's text. The text River stores for a
// failed attempt is a fixed string that holds the error code only.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

// DefaultMaxAttempts is the attempt limit of a kind that does not configure one. It counts the
// first run, so a job is tried at most five times.
const DefaultMaxAttempts = 5

// Args is a job's typed argument struct. It is stored as JSON, so it must never hold secrets,
// tokens, signed URLs or source object keys. Kind is the stable identifier of the job type; do not
// rename it once jobs of that kind exist.
type Args interface {
	Kind() string
}

// Job is what a handler receives.
type Job[A Args] struct {
	ID          int64
	Args        A
	Attempt     int // 1 on the first run
	MaxAttempts int
}

// Handler works one job. Returning nil completes it. Handlers must be idempotent, and should
// return when ctx is cancelled.
type Handler[A Args] func(ctx context.Context, job Job[A]) error

// BackoffFunc returns how long to wait before the next try, given the number of attempts made so
// far (1 after the first failure).
type BackoffFunc func(attempt int) time.Duration

// KindConfig tunes one job kind. Zero values mean the defaults.
type KindConfig struct {
	MaxAttempts int           // default DefaultMaxAttempts
	Backoff     BackoffFunc   // default DefaultBackoff
	Timeout     time.Duration // per-run limit; default 1 minute
}

// DefaultBackoff doubles from 15 seconds and stops growing at 30 minutes.
func DefaultBackoff(attempt int) time.Duration {
	const (
		base = 15 * time.Second
		max  = 30 * time.Minute
	)
	d := base
	for i := 1; i < attempt && d < max; i++ {
		d *= 2
	}
	return min(d, max)
}

func (c KindConfig) withDefaults() KindConfig {
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = DefaultMaxAttempts
	}
	if c.Backoff == nil {
		c.Backoff = DefaultBackoff
	}
	return c
}

// Registry holds the handlers and per-kind settings. Build it before creating a Queue, and do not
// change it afterwards.
type Registry struct {
	mu      sync.Mutex
	workers *river.Workers
	kinds   map[string]KindConfig
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{workers: river.NewWorkers(), kinds: map[string]KindConfig{}}
}

func (r *Registry) config(kind string) KindConfig {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.kinds[kind]; ok {
		return c
	}
	return KindConfig{}.withDefaults()
}

// Register adds the handler for kind A. It fails if the kind is empty or already registered.
func Register[A Args](r *Registry, handler Handler[A], cfg KindConfig) error {
	var zero A
	kind := zero.Kind()
	if kind == "" {
		return errors.New("jobs: kind must not be empty")
	}
	if handler == nil {
		return fmt.Errorf("jobs: handler for %q is nil", kind)
	}
	cfg = cfg.withDefaults()
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.kinds[kind]; dup {
		return fmt.Errorf("jobs: kind %q is already registered", kind)
	}
	if err := river.AddWorkerSafely[A](r.workers, &worker[A]{handler: handler, cfg: cfg}); err != nil {
		return fmt.Errorf("jobs: register %q: %w", kind, err)
	}
	r.kinds[kind] = cfg
	return nil
}

// Config configures a Queue.
type Config struct {
	// Workers is the number of jobs worked at once. Zero builds an insert-only queue that can
	// Enqueue, ListDead and RetryDead but cannot Start.
	Workers int
	// Logger receives River's own messages (never job arguments or error text from handlers).
	// Nil discards them.
	Logger *slog.Logger
}

// Queue enqueues jobs and, when configured with workers, runs them.
type Queue struct {
	client   *river.Client[pgx.Tx]
	registry *Registry
	working  bool
}

// NewQueue builds a Queue over pool. The database must already be migrated (db.Migrate).
func NewQueue(pool *pgxpool.Pool, reg *Registry, cfg Config) (*Queue, error) {
	if pool == nil || reg == nil {
		return nil, errors.New("jobs: pool and registry are required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	rc := &river.Config{Logger: logger}
	if cfg.Workers > 0 {
		rc.Queues = map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: cfg.Workers}}
		rc.Workers = reg.workers
	}
	client, err := river.NewClient(riverpgxv5.New(pool), rc)
	if err != nil {
		return nil, fmt.Errorf("jobs: create queue: %w", db.MapError(err))
	}
	return &Queue{client: client, registry: reg, working: cfg.Workers > 0}, nil
}

// Start begins working jobs. It returns once the workers are running; ctx bounds the startup only
// in the sense that cancelling it stops the workers too, so pass a long-lived context.
func (q *Queue) Start(ctx context.Context) error {
	if !q.working {
		return errors.New("jobs: queue was created without workers")
	}
	if err := q.client.Start(ctx); err != nil {
		return fmt.Errorf("jobs: start: %w", db.MapError(err))
	}
	return nil
}

// Stop stops fetching jobs and waits for running jobs to finish, until ctx is done. Jobs still
// running at that point are cancelled and retried later.
func (q *Queue) Stop(ctx context.Context) error {
	if !q.working {
		return nil
	}
	if err := q.client.Stop(ctx); err != nil {
		// Stop returns ctx's error when jobs did not finish in time; cancel what is left.
		if ctx.Err() != nil {
			return q.client.StopAndCancel(context.WithoutCancel(ctx))
		}
		return fmt.Errorf("jobs: stop: %w", db.MapError(err))
	}
	return nil
}

// EnqueueOpts are per-insert overrides.
type EnqueueOpts struct {
	MaxAttempts int       // overrides the kind's limit when positive
	ScheduledAt time.Time // run no earlier than this
}

// Enqueue inserts a job in the caller's transaction and returns its ID. The job becomes visible to
// workers only if tx commits; if tx rolls back, no job exists. A kind that was never registered
// in this process (an API process that only enqueues) gets the default attempt limit.
func (q *Queue) Enqueue(ctx context.Context, tx pgx.Tx, args Args, opts *EnqueueOpts) (int64, error) {
	if tx == nil || args == nil {
		return 0, errs.New(errs.InvalidRequest, "a transaction and job arguments are required")
	}
	io := &river.InsertOpts{MaxAttempts: q.registry.config(args.Kind()).MaxAttempts}
	if opts != nil {
		if opts.MaxAttempts > 0 {
			io.MaxAttempts = opts.MaxAttempts
		}
		io.ScheduledAt = opts.ScheduledAt
	}
	res, err := q.client.InsertTx(ctx, tx, args, io)
	if err != nil {
		return 0, db.MapError(err)
	}
	return res.Job.ID, nil
}

// worker adapts a Handler to River and applies the error policy.
type worker[A Args] struct {
	river.WorkerDefaults[A]
	handler Handler[A]
	cfg     KindConfig
}

func (w *worker[A]) Timeout(*river.Job[A]) time.Duration { return w.cfg.Timeout }

func (w *worker[A]) NextRetry(job *river.Job[A]) time.Time {
	return time.Now().Add(w.cfg.Backoff(job.Attempt))
}

func (w *worker[A]) Work(ctx context.Context, job *river.Job[A]) (err error) {
	defer func() {
		// A panic value can hold anything, so it is replaced by a fixed failure and retried.
		if recover() != nil {
			err = failure{code: string(errs.InternalError)}
		}
	}()
	return classify(w.handler(ctx, Job[A]{
		ID:          job.ID,
		Args:        job.Args,
		Attempt:     job.Attempt,
		MaxAttempts: job.MaxAttempts,
	}))
}
