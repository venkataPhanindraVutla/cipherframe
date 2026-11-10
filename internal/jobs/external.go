package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

// AwaitKind is the River kind of the job that waits for an external task.
const AwaitKind = "external_task.await"

// DefaultAwaitPoll is how often the await job looks at its task.
const DefaultAwaitPoll = 5 * time.Second

// Failure codes the Go side itself records for an external task.
const (
	CodeLeaseExpired  = "lease_expired"  // the lease ran out and no attempt was left
	CodeInvalidResult = "invalid_result" // the stored result did not follow the contract
)

// AwaitArgs are the arguments of the await job: the task's ID only.
type AwaitArgs struct {
	TaskID uuid.UUID `json:"task_id"`
}

// Kind implements Args.
func (AwaitArgs) Kind() string { return AwaitKind }

// Task is a row of the hand-off table.
type Task struct {
	ID          uuid.UUID
	Kind        string
	Envelope    Envelope
	State       string
	Attempts    int // zero-based index of the current attempt
	MaxAttempts int
	LeaseOwner  string
	LeaseUntil  *time.Time
	Result      json.RawMessage // nil until a worker records one
	RiverJobID  *int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
	CompletedAt *time.Time
}

func toTask(r dbgen.ExternalTask) (Task, error) {
	t := Task{
		ID:          uuid.UUID(r.ID.Bytes),
		Kind:        r.Kind,
		State:       r.State,
		Attempts:    int(r.Attempts),
		MaxAttempts: int(r.MaxAttempts),
		LeaseUntil:  r.LeaseUntil,
		Result:      r.Result,
		RiverJobID:  r.RiverJobID,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
		CompletedAt: r.CompletedAt,
	}
	if r.LeaseOwner != nil {
		t.LeaseOwner = *r.LeaseOwner
	}
	if err := json.Unmarshal(r.Envelope, &t.Envelope); err != nil {
		// The decoder's text can quote the document, so it is dropped.
		return Task{}, errs.Wrap(errs.InternalError, "stored task envelope is unreadable",
			errors.New("jobs: stored envelope does not decode"))
	}
	return t, nil
}

func pgUUID(u uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: [16]byte(u), Valid: true} }

// TaskOpts are per-task overrides for CreateTask.
type TaskOpts struct {
	MaxAttempts int // default DefaultMaxAttempts
}

// CreateTask writes a hand-off row and the River job that waits for it, both in tx, so either both
// exist or neither does. Unset envelope fields are filled in: version, task ID (a new UUIDv7),
// attempt 1, creation time and an empty payload. The envelope is validated before anything is
// written.
func (q *Queue) CreateTask(ctx context.Context, tx pgx.Tx, env Envelope, opts *TaskOpts) (Task, error) {
	if tx == nil {
		return Task{}, errs.New(errs.InvalidRequest, "a transaction is required")
	}
	if env.EnvelopeVersion == 0 {
		env.EnvelopeVersion = EnvelopeVersion
	}
	if env.TaskID == uuid.Nil() {
		env.TaskID = uuid.NewV7()
	}
	if env.Attempt == 0 {
		env.Attempt = 1
	}
	if env.CreatedAt.IsZero() {
		env.CreatedAt = time.Now().UTC()
	}
	if len(env.Payload) == 0 {
		env.Payload = json.RawMessage(`{}`)
	}
	if err := env.Validate(); err != nil {
		return Task{}, err
	}
	max := DefaultMaxAttempts
	if opts != nil && opts.MaxAttempts > 0 {
		max = opts.MaxAttempts
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return Task{}, errs.Wrap(errs.InvalidRequest, "task envelope cannot be encoded",
			errors.New("jobs: envelope does not marshal"))
	}

	jobID, err := q.Enqueue(ctx, tx, AwaitArgs{TaskID: env.TaskID}, nil)
	if err != nil {
		return Task{}, err
	}
	row, err := dbgen.New(tx).InsertExternalTask(ctx, dbgen.InsertExternalTaskParams{
		ID:          pgUUID(env.TaskID),
		Kind:        env.Kind,
		Envelope:    raw,
		MaxAttempts: int32(max), //nolint:gosec // bounded by the caller's small attempt limit
		RiverJobID:  &jobID,
	})
	if err != nil {
		return Task{}, db.MapError(err)
	}
	return toTask(row)
}

// GetTask reads a hand-off row.
func GetTask(ctx context.Context, d dbgen.DBTX, taskID uuid.UUID) (Task, error) {
	row, err := dbgen.New(d).GetExternalTask(ctx, pgUUID(taskID))
	if err != nil {
		return Task{}, db.MapError(err)
	}
	return toTask(row)
}

// ResultHandler receives the parsed result of a succeeded task so that the Go side can register its
// derived artifacts (invariant I6). It may run more than once for the same task and must be
// idempotent. Returning an error retries the await job.
type ResultHandler func(ctx context.Context, task Task, res Result) error

// ExternalConfig configures the await job.
type ExternalConfig struct {
	OnResult     ResultHandler // required
	PollInterval time.Duration // how long the await job sleeps between looks; default DefaultAwaitPoll
}

// RegisterExternal registers the await job on reg. The job snoozes while the task is pending or
// leased and then acts on the outcome:
//
//   - succeeded: parses the result and calls OnResult, then completes;
//   - failed and retryable, attempts left: puts the task back to pending with the attempt number
//     plus one;
//   - failed and not retryable, or no attempt left: cancels (the dead-letter list shows the
//     failure's code);
//   - a leased task whose lease expired with no attempt left: marks it failed (lease_expired) and
//     cancels;
//   - a stored result that does not follow the contract: cancels (invalid_result), failing closed.
func RegisterExternal(reg *Registry, pool *pgxpool.Pool, cfg ExternalConfig) error {
	if pool == nil || cfg.OnResult == nil {
		return errors.New("jobs: pool and OnResult are required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultAwaitPoll
	}
	a := &awaiter{pool: pool, onResult: cfg.OnResult, poll: cfg.PollInterval}
	return Register(reg, Handler[AwaitArgs](a.await), KindConfig{})
}

type awaiter struct {
	pool     *pgxpool.Pool
	onResult ResultHandler
	poll     time.Duration
}

func (a *awaiter) await(ctx context.Context, job Job[AwaitArgs]) error {
	q := dbgen.New(a.pool)
	row, err := q.GetExternalTask(ctx, pgUUID(job.Args.TaskID))
	if err != nil {
		err = db.MapError(err)
		if !Retryable(err) {
			return Cancel(err) // not_found: the task is gone, nothing to wait for
		}
		return err
	}
	task, err := toTask(row)
	if err != nil {
		return err
	}

	switch task.State {
	case StatePending:
		return Snooze(a.poll)

	case StateLeased:
		if task.Attempts+1 >= task.MaxAttempts {
			n, err := q.ExpireExternalTask(ctx, dbgen.ExpireExternalTaskParams{
				ID:     row.ID,
				Result: expiredResult(task.ID),
			})
			if err != nil {
				return db.MapError(err)
			}
			if n == 1 {
				return cancelWith(CodeLeaseExpired)
			}
		}
		return Snooze(a.poll)

	case StateSucceeded:
		res, err := ParseResult(task.Result)
		if err != nil || res.Status != StatusSucceeded || res.TaskID != task.ID {
			return cancelWith(CodeInvalidResult)
		}
		return a.onResult(ctx, task, res)

	case StateFailed:
		res, err := ParseResult(task.Result)
		if err != nil || res.Status != StatusFailed || res.TaskID != task.ID {
			return cancelWith(CodeInvalidResult)
		}
		if res.Error.Retryable {
			n, err := q.RequeueExternalTask(ctx, row.ID)
			if err != nil {
				return db.MapError(err)
			}
			if n == 1 {
				return Snooze(a.poll)
			}
			// No attempt left: the failure is final.
		}
		return cancelWith(res.Error.Code)
	}
	return cancelWith(CodeInvalidResult)
}

func expiredResult(taskID uuid.UUID) []byte {
	b, _ := json.Marshal(Result{
		EnvelopeVersion: EnvelopeVersion,
		TaskID:          taskID,
		Status:          StatusFailed,
		Error: &TaskError{
			Code:      CodeLeaseExpired,
			Retryable: true,
			Message:   "the lease expired and no attempt is left",
		},
	})
	return b
}
