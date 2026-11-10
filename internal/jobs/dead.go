package jobs

import (
	"context"
	"errors"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

// DeadJob describes a job that will not run again unless someone retries it. It deliberately has no
// arguments, no error text and no attempt history beyond the last error code: arguments and error
// text can hold sensitive data.
type DeadJob struct {
	ID            int64
	Kind          string
	State         string // "discarded" (attempts used up) or "cancelled" (non-retryable error)
	Attempts      int
	MaxAttempts   int
	LastErrorCode string // "" if the job never recorded an error
	CreatedAt     time.Time
	FinalizedAt   *time.Time
}

// Dead-letter paging limits.
const (
	defaultDeadLimit = 50
	maxDeadLimit     = 200
)

// ListDead returns discarded and cancelled jobs, newest first. cursor is "" for the first page or
// the next-page cursor of the previous call; the returned cursor is "" when there are no more
// pages. limit is clamped to 1..200 (default 50 when not positive).
func (q *Queue) ListDead(ctx context.Context, cursor string, limit int) ([]DeadJob, string, error) {
	if limit <= 0 {
		limit = defaultDeadLimit
	}
	limit = min(limit, maxDeadLimit)

	params := river.NewJobListParams().
		States(rivertype.JobStateDiscarded, rivertype.JobStateCancelled).
		OrderBy(river.JobListOrderByID, river.SortOrderDesc).
		// One extra row tells whether another page exists.
		First(limit + 1)
	if cursor != "" {
		var c river.JobListCursor
		if err := c.UnmarshalText([]byte(cursor)); err != nil {
			return nil, "", errs.New(errs.InvalidRequest, "the cursor is not valid")
		}
		params = params.After(&c)
	}
	res, err := q.client.JobList(ctx, params)
	if err != nil {
		return nil, "", db.MapError(err)
	}
	rows := res.Jobs
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		text, err := river.JobListCursorFromJob(rows[len(rows)-1]).MarshalText()
		if err != nil {
			return nil, "", errs.Wrap(errs.InternalError, "could not build the next cursor", err)
		}
		next = string(text)
	}
	out := make([]DeadJob, 0, len(rows))
	for _, r := range rows {
		out = append(out, toDead(r))
	}
	return out, next, nil
}

func toDead(r *rivertype.JobRow) DeadJob {
	d := DeadJob{
		ID:          r.ID,
		Kind:        r.Kind,
		State:       string(r.State),
		Attempts:    r.Attempt,
		MaxAttempts: r.MaxAttempts,
		CreatedAt:   r.CreatedAt,
		FinalizedAt: r.FinalizedAt,
	}
	if n := len(r.Errors); n > 0 {
		d.LastErrorCode = codeFromStored(r.Errors[n-1].Error)
	}
	return d
}

// RetryDead puts a discarded or cancelled job back in the queue for another run. It reports
// not_found if there is no such job and conflict if the job is not in the dead-letter list.
func (q *Queue) RetryDead(ctx context.Context, jobID int64) error {
	job, err := q.client.JobGet(ctx, jobID)
	if err != nil {
		if errors.Is(err, river.ErrNotFound) {
			return errs.New(errs.NotFound, "job not found")
		}
		return db.MapError(err)
	}
	if job.State != rivertype.JobStateDiscarded && job.State != rivertype.JobStateCancelled {
		return errs.New(errs.Conflict, "the job is not in the dead-letter list")
	}
	if _, err := q.client.JobRetry(ctx, jobID); err != nil {
		if errors.Is(err, river.ErrNotFound) {
			return errs.New(errs.NotFound, "job not found")
		}
		return db.MapError(err)
	}
	return nil
}
