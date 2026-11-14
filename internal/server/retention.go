package server

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/purge"
	"github.com/venkataPhanindraVutla/cipherframe/internal/retention"
)

// newRetention builds the retention sweeper of the worker role (M6-4): it queues asset.delete for
// expired assets through an insert-only queue and removes old access-trail rows and anomaly events.
// Any number of workers may run it at once: queueing a deletion is idempotent and the deletes are
// bounded batches.
func newRetention(pool *pgxpool.Pool, cfg *config.Config, log *slog.Logger) (*retentionService, error) {
	reg := jobs.NewRegistry()
	if err := purge.Declare(reg); err != nil {
		return nil, fmt.Errorf("retention: %w", err)
	}
	queue, err := jobs.NewQueue(pool, reg, jobs.Config{Logger: log})
	if err != nil {
		return nil, fmt.Errorf("retention: %w", err)
	}
	requester, err := purge.NewRequester(pool, queue)
	if err != nil {
		return nil, fmt.Errorf("retention: %w", err)
	}
	return &retentionService{sweeper: &retention.Sweeper{
		Store: db.New(pool), Requester: requester, AccessLogDays: cfg.Retention.AccessLogDays, Log: log,
	}}, nil
}

// retentionService runs the retention sweep until shutdown.
type retentionService struct{ sweeper *retention.Sweeper }

func (s *retentionService) run(ctx context.Context) error {
	s.sweeper.Run(ctx, retention.Interval)
	return nil
}
func (*retentionService) close() {}
