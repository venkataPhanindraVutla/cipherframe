// Package retention is how long Cipherframe keeps things (M6-4, ADR 0040, ADR 0042).
//
//   - Assets are kept until deleted unless a time-to-live applies: ResolveExpiry turns a request's
//     expires_at or ttl_seconds into the asset's expiry, and the Sweeper hands every expired asset
//     to the verified purge (reason "retention").
//   - The access trail (playback_access_log) and the anomaly events (playback_events) are kept for
//     CIPHERFRAME_ACCESS_LOG_RETENTION_DAYS (default 90): the Sweeper drops whole monthly partitions
//     past the window and deletes the older rows of the partition the window ends in, and the older
//     rows of playback_events, which is not partitioned.
package retention

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// MinLead is the least time between now and an expiry that is set (a request that would expire an
// asset sooner is invalid: DELETE does that on purpose).
const MinLead = time.Duration(db.MinAssetTTLSeconds) * time.Second

// MaxLead is the furthest an expiry may lie in the future: ten years.
const MaxLead = time.Duration(db.MaxAssetTTLSeconds) * time.Second

// ResolveExpiry turns the retention fields of a request into an expiry. At most one of expiresAt
// and ttlSeconds may be set; with neither it returns nil (no expiry from this request). An
// expires_at must lie between MinLead and MaxLead from now, a ttl_seconds between
// db.MinAssetTTLSeconds and db.MaxAssetTTLSeconds; it counts from now, not from the asset's creation.
func ResolveExpiry(now time.Time, expiresAt *time.Time, ttlSeconds *int) (*time.Time, error) {
	var fields []errs.FieldError
	switch {
	case expiresAt != nil && ttlSeconds != nil:
		fields = append(fields, errs.FieldError{Field: "ttl_seconds", Message: "give expires_at or ttl_seconds, not both"})
	case expiresAt != nil:
		if lead := expiresAt.Sub(now); lead < MinLead || lead > MaxLead {
			fields = append(fields, errs.FieldError{Field: "expires_at", Message: "must be at least a minute and at most ten years from now"})
		}
	case ttlSeconds != nil:
		if *ttlSeconds < db.MinAssetTTLSeconds || *ttlSeconds > db.MaxAssetTTLSeconds {
			fields = append(fields, errs.FieldError{
				Field:   "ttl_seconds",
				Message: fmt.Sprintf("must be a whole number of seconds from %d to %d", db.MinAssetTTLSeconds, db.MaxAssetTTLSeconds),
			})
		}
	default:
		return nil, nil
	}
	if len(fields) > 0 {
		return nil, errs.Invalid("The request is invalid.", fields)
	}
	if expiresAt != nil {
		t := expiresAt.UTC().Truncate(time.Microsecond)
		return &t, nil
	}
	t := now.UTC().Add(time.Duration(*ttlSeconds) * time.Second).Truncate(time.Microsecond)
	return &t, nil
}

// Sweep sizes. A backlog is worked off over several runs so one run never holds locks for long.
const (
	// Interval is how often the worker role runs the sweep.
	Interval = 5 * time.Minute
	// expiredBatch assets are handed to the purge per page, at most maxExpiredPages pages per run.
	expiredBatch    = 100
	maxExpiredPages = 20
	// deleteBatch rows are deleted per statement, at most maxDeletePasses statements per table
	// and run.
	deleteBatch     = 5000
	maxDeletePasses = 200
)

// Store is the database access the sweep needs. *db.Repos implements it.
type Store interface {
	ListExpiredAssets(ctx context.Context, now time.Time, limit int) ([]db.Asset, error)
	DropAccessLogPartitionsBefore(ctx context.Context, before time.Time) ([]string, error)
	DeleteAccessLogBefore(ctx context.Context, cutoff time.Time, batch int) (int64, error)
	DeletePlaybackEventsBefore(ctx context.Context, cutoff time.Time, batch int) (int64, error)
}

// Requester starts a deletion. *purge.Requester implements it.
type Requester interface {
	Request(ctx context.Context, tenant id.TenantID, asset id.AssetID, reason string, actor *auth.Actor) (db.Asset, error)
}

// Sweeper runs the retention sweep.
type Sweeper struct {
	Store     Store
	Requester Requester
	// AccessLogDays is the retention window of the access trail and the anomaly events.
	AccessLogDays int
	Log           *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
}

// Result says what one sweep did.
type Result struct {
	// ExpiredAssets is how many expired assets were handed to the purge.
	ExpiredAssets int
	// DroppedPartitions are the access-log partitions dropped whole.
	DroppedPartitions []string
	// AccessLogRows and EventRows are the rows deleted one by one.
	AccessLogRows int64
	EventRows     int64
}

// Sweep hands the assets that expired by now to the purge, then removes the access trail and the
// anomaly events older than the window. A failure in one part does not stop the others; the
// errors are returned together after the whole sweep, and the next run continues.
func (s *Sweeper) Sweep(ctx context.Context) (Result, error) {
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Log == nil {
		s.Log = slog.Default()
	}
	now := s.Now().UTC()
	var res Result
	var errList []error
	n, err := s.expireAssets(ctx, now)
	res.ExpiredAssets = n
	if err != nil {
		errList = append(errList, err)
	}
	cutoff := now.AddDate(0, 0, -s.AccessLogDays)
	if dropped, err := s.Store.DropAccessLogPartitionsBefore(ctx, cutoff); err != nil {
		errList = append(errList, fmt.Errorf("retention: drop access log partitions: %w", err))
	} else {
		res.DroppedPartitions = dropped
	}
	if res.AccessLogRows, err = deleteOld(ctx, cutoff, s.Store.DeleteAccessLogBefore); err != nil {
		errList = append(errList, fmt.Errorf("retention: delete old access log rows: %w", err))
	}
	if res.EventRows, err = deleteOld(ctx, cutoff, s.Store.DeletePlaybackEventsBefore); err != nil {
		errList = append(errList, fmt.Errorf("retention: delete old anomaly events: %w", err))
	}
	return res, joinErrors(errList)
}

// expireAssets requests the deletion of every asset that has expired. An asset that fails (say, its
// job could not be queued) is logged and skipped, so one bad row does not hold the others up; it is
// found again on the next run.
func (s *Sweeper) expireAssets(ctx context.Context, now time.Time) (int, error) {
	done := 0
	var firstErr error
	for range maxExpiredPages {
		page, err := s.Store.ListExpiredAssets(ctx, now, expiredBatch)
		if err != nil {
			return done, fmt.Errorf("retention: list expired assets: %w", err)
		}
		queued := 0
		for _, a := range page {
			if _, err := s.Requester.Request(ctx, a.TenantID, a.ID, db.DeletionRetention, nil); err != nil {
				s.Log.WarnContext(ctx, "could not start the deletion of an expired asset",
					slog.String("tenant_id", a.TenantID.String()), slog.String("asset_id", a.ID.String()), slog.Any("error", err))
				if firstErr == nil {
					firstErr = fmt.Errorf("retention: expire asset: %w", err)
				}
				continue
			}
			queued++
		}
		done += queued
		// Everything that was queued left the list; stop when a page held nothing new.
		if len(page) < expiredBatch || queued == 0 {
			break
		}
	}
	return done, firstErr
}

// deleteOld calls del with the cutoff until a batch is not full, and returns the rows deleted.
func deleteOld(ctx context.Context, cutoff time.Time, del func(context.Context, time.Time, int) (int64, error)) (int64, error) {
	var total int64
	for range maxDeletePasses {
		n, err := del(ctx, cutoff, deleteBatch)
		total += n
		if err != nil {
			return total, err
		}
		if n < deleteBatch {
			break
		}
	}
	return total, nil
}

func joinErrors(list []error) error {
	switch len(list) {
	case 0:
		return nil
	case 1:
		return list[0]
	}
	return fmt.Errorf("%w (and %d more)", list[0], len(list)-1)
}

// Run sweeps once at once and then every interval until ctx is cancelled. A failed sweep is logged
// and retried at the next tick.
func (s *Sweeper) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = Interval
	}
	run := func() {
		res, err := s.Sweep(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			s.Log.ErrorContext(ctx, "retention sweep failed", slog.Any("error", err))
		}
		if res.ExpiredAssets > 0 || len(res.DroppedPartitions) > 0 || res.AccessLogRows > 0 || res.EventRows > 0 {
			s.Log.InfoContext(ctx, "retention sweep",
				slog.Int("expired_assets", res.ExpiredAssets), slog.Int("dropped_partitions", len(res.DroppedPartitions)),
				slog.Int64("access_log_rows", res.AccessLogRows), slog.Int64("event_rows", res.EventRows))
		}
	}
	run()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
