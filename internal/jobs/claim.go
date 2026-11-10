package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

// The functions below implement the claim protocol of spec/jobs/README.md in Go, with the same SQL
// (internal/db/queries/external_tasks.sql). Production external workers are written in other
// languages and run the documented statements themselves; these functions exist so that tests can
// play the part of an external worker.

// Claim leases the oldest claimable task of one of kinds to owner for lease. It returns nil, nil
// when nothing is claimable. A leased task whose lease expired is claimable again and the claim
// counts as a new attempt.
func Claim(ctx context.Context, d dbgen.DBTX, kinds []string, owner string, lease time.Duration) (*Task, error) {
	if len(kinds) == 0 || owner == "" || lease <= 0 {
		return nil, errs.New(errs.InvalidRequest, "kinds, an owner and a positive lease are required")
	}
	row, err := dbgen.New(d).ClaimExternalTask(ctx, dbgen.ClaimExternalTaskParams{
		Kinds:        kinds,
		Owner:        owner,
		LeaseSeconds: lease.Seconds(),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, db.MapError(err)
	}
	t, err := toTask(row)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// Heartbeat extends owner's lease on the task by lease from now. It returns a conflict error when
// owner does not hold the lease (it expired and the task was claimed again, or it is not leased).
func Heartbeat(ctx context.Context, d dbgen.DBTX, taskID uuid.UUID, owner string, lease time.Duration) error {
	if owner == "" || lease <= 0 {
		return errs.New(errs.InvalidRequest, "an owner and a positive lease are required")
	}
	n, err := dbgen.New(d).HeartbeatExternalTask(ctx, dbgen.HeartbeatExternalTaskParams{
		ID:           pgUUID(taskID),
		Owner:        owner,
		LeaseSeconds: lease.Seconds(),
	})
	if err != nil {
		return db.MapError(err)
	}
	if n != 1 {
		return leaseLost()
	}
	return nil
}

// Complete records a succeeded result. It returns a conflict error when owner does not hold the
// lease; the result is then discarded.
func Complete(ctx context.Context, d dbgen.DBTX, taskID uuid.UUID, owner string, res Result) error {
	if res.Status != StatusSucceeded {
		return errs.New(errs.InvalidRequest, "Complete needs a succeeded result")
	}
	raw, err := checkedResult(taskID, owner, res)
	if err != nil {
		return err
	}
	n, err := dbgen.New(d).CompleteExternalTask(ctx, dbgen.CompleteExternalTaskParams{
		ID: pgUUID(taskID), Owner: owner, Result: raw,
	})
	return lost(n, err)
}

// Fail records a failed result (with its retryable flag). It returns a conflict error when owner
// does not hold the lease.
func Fail(ctx context.Context, d dbgen.DBTX, taskID uuid.UUID, owner string, res Result) error {
	if res.Status != StatusFailed {
		return errs.New(errs.InvalidRequest, "Fail needs a failed result")
	}
	raw, err := checkedResult(taskID, owner, res)
	if err != nil {
		return err
	}
	n, err := dbgen.New(d).FailExternalTask(ctx, dbgen.FailExternalTaskParams{
		ID: pgUUID(taskID), Owner: owner, Result: raw,
	})
	return lost(n, err)
}

func checkedResult(taskID uuid.UUID, owner string, res Result) ([]byte, error) {
	if owner == "" {
		return nil, errs.New(errs.InvalidRequest, "an owner is required")
	}
	if res.TaskID != taskID {
		return nil, invalidResult("task id does not match")
	}
	if err := res.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(res)
	if err != nil {
		return nil, invalidResult("result cannot be encoded")
	}
	return raw, nil
}

func lost(n int64, err error) error {
	if err != nil {
		return db.MapError(err)
	}
	if n != 1 {
		return leaseLost()
	}
	return nil
}
