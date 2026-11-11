package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	kmsregistry "github.com/venkataPhanindraVutla/cipherframe/internal/kms/registry"
)

// rewrapPollInterval is how often `admin kms-rewrap --wait` looks at progress.
const rewrapPollInterval = 2 * time.Second

// KMSUsage prints, to out, how many content keys each KEK (provider, KEK id, KEK version) wraps:
// what an operator needs to know before a KEK version or provider can be retired. It prints counts
// only, never key material.
func KMSUsage(ctx context.Context, cfg *config.Config, log *slog.Logger, out io.Writer) error {
	pool, err := openDatabase(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer pool.Close()

	usage, err := db.New(pool).CountContentKeysByKEK(ctx)
	if err != nil {
		return fmt.Errorf("count content keys by KEK: %w", err)
	}
	for _, line := range KMSUsageLines(usage) {
		if _, err := fmt.Fprintln(out, line); err != nil {
			return err
		}
	}
	return nil
}

// KMSUsageLines formats usage as one "provider=P kek_id=K version=V: N content keys" line each.
func KMSUsageLines(usage []db.KEKUsage) []string {
	if len(usage) == 0 {
		return []string{"no content keys"}
	}
	lines := make([]string, 0, len(usage))
	for _, u := range usage {
		lines = append(lines, fmt.Sprintf("provider=%s kek_id=%s version=%s: %d content keys",
			u.KEK.Provider, u.KEK.KeyID, u.KEK.Version, u.Keys))
	}
	return lines
}

// KMSRewrap enqueues the kms.rewrap job and prints its id to out. The job runs on a worker. With
// wait it then polls until no content key is left on a KEK other than the current one, writing
// progress to progress, and fails if the job (or a job it chained) ends in the dead-letter list.
// The HTTP trigger for this is a later decision (operator API); until then this command is the
// trigger.
func KMSRewrap(ctx context.Context, cfg *config.Config, log *slog.Logger, out, progress io.Writer, batchSize int, wait bool) error {
	pool, err := openDatabase(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer pool.Close()

	// The job is enqueued in a transaction, as every job is. The handler registered on the worker
	// supplies the attempt limit; this insert-only queue uses the default, which is the same.
	q, err := jobs.NewQueue(pool, jobs.NewRegistry(), jobs.Config{Logger: log})
	if err != nil {
		return fmt.Errorf("kms-rewrap: %w", err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("kms-rewrap: %w", db.MapError(err))
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	jobID, err := q.Enqueue(ctx, tx, contentkey.RewrapArgs{BatchSize: batchSize}, nil)
	if err != nil {
		return fmt.Errorf("kms-rewrap: enqueue: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("kms-rewrap: enqueue: %w", db.MapError(err))
	}
	log.InfoContext(ctx, "re-wrap job enqueued", slog.Int64("job_id", jobID))
	if _, err := fmt.Fprintln(out, jobID); err != nil {
		return fmt.Errorf("write job id: %w", err)
	}
	if !wait {
		return nil
	}

	reg, err := kmsregistry.FromConfig(cfg, log)
	if err != nil {
		return err
	}
	return waitRewrap(ctx, db.New(pool), q, reg.Current(), jobID, progress, rewrapPollInterval)
}

// waitRewrap polls until no content key is on a KEK other than p's current one. It reports progress
// counts on each poll and fails when a kms.rewrap job at or after jobID (the chain re-enqueues
// itself, so later runs have higher ids) has been cancelled or discarded.
func waitRewrap(ctx context.Context, repos *db.Repos, q *jobs.Queue, p kms.Provider, jobID int64, progress io.Writer, every time.Duration) error {
	total := int64(-1)
	for {
		ref, err := p.Current(ctx)
		switch {
		case err == nil:
			left, err := repos.CountContentKeysNotOnKEK(ctx, db.KEKRef{Provider: p.Name(), KeyID: ref.KeyID, Version: ref.Version})
			if err != nil {
				return fmt.Errorf("kms-rewrap: count remaining keys: %w", err)
			}
			if total < 0 || left > total {
				total = left
			}
			_, _ = fmt.Fprintf(progress, "kms-rewrap: %d content keys remain on another KEK (%d at start)\n", left, total)
			if left == 0 {
				return nil
			}
		case kms.KindOf(err) == kms.Unavailable:
			_, _ = fmt.Fprintln(progress, "kms-rewrap: the key service is unavailable; still waiting")
		default:
			return fmt.Errorf("kms-rewrap: current KEK: %w", err)
		}

		dead, _, err := q.ListDead(ctx, "", 50)
		if err != nil {
			return fmt.Errorf("kms-rewrap: check the dead-letter list: %w", err)
		}
		for _, d := range dead {
			if d.Kind == contentkey.RewrapKind && d.ID >= jobID {
				return fmt.Errorf("kms-rewrap: job %d is %s with error code %q; see the dead-letter list and fix the cause before retrying",
					d.ID, d.State, d.LastErrorCode)
			}
		}

		select {
		case <-ctx.Done():
			return errors.Join(errors.New("kms-rewrap: stopped waiting; the job keeps running on the worker"), ctx.Err())
		case <-time.After(every):
		}
	}
}
