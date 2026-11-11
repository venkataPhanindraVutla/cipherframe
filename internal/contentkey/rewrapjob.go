package contentkey

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
)

// RewrapKind is the job kind of the re-wrap job. Do not rename it once jobs of that kind exist.
const RewrapKind = "kms.rewrap"

// rewrapTimeout bounds one run (one batch): every key takes an unwrap, a wrap and a verifying
// unwrap at the key service.
const rewrapTimeout = 5 * time.Minute

// RewrapArgs are the arguments of the re-wrap job. They hold no key material.
type RewrapArgs struct {
	// BatchSize is how many content keys one run re-wraps; zero means DefaultRewrapBatch.
	BatchSize int `json:"batch_size,omitempty"`
}

// Kind implements jobs.Args.
func (RewrapArgs) Kind() string { return RewrapKind }

// Enqueuer inserts a job in the caller's transaction. *jobs.Queue implements it.
type Enqueuer interface {
	Enqueue(ctx context.Context, tx pgx.Tx, args jobs.Args, opts *jobs.EnqueueOpts) (int64, error)
}

// RegisterRewrapJob registers the kms.rewrap job kind. Each run re-wraps one batch and, when keys
// remain, enqueues the next run in the same transaction as its last update, so the chain survives a
// crash and a rolled-back batch enqueues nothing. enq must be able to insert jobs of this kind.
//
// Error policy (jobs package): an unavailable key service is dependency_unavailable and retries
// with backoff; a key that fails authentication cancels the job at once and shows in the
// dead-letter list with its error code only. Every other failure retries up to the attempt limit.
func RegisterRewrapJob(reg *jobs.Registry, m *Manager, enq Enqueuer, cfg jobs.KindConfig) error {
	if m == nil || enq == nil {
		return errors.New("contentkey: a manager and an enqueuer are required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = rewrapTimeout
	}
	return jobs.Register(reg, func(ctx context.Context, job jobs.Job[RewrapArgs]) error {
		batch := job.Args.BatchSize
		if batch < 0 || batch > MaxRewrapBatch {
			return jobs.Cancel(errs.New(errs.InvalidRequest, "the batch size is out of range"))
		}
		_, err := m.Rewrap(ctx, batch, func(ctx context.Context, tx pgx.Tx, _ int64) error {
			_, err := enq.Enqueue(ctx, tx, RewrapArgs{BatchSize: batch}, nil)
			return err
		})
		if err != nil && kms.IsIntegrityFailure(err) {
			return jobs.Cancel(err)
		}
		return err
	}, cfg)
}
