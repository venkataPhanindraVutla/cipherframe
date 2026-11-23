package server

import (
	"context"
	"log/slog"
	"slices"
	"time"
	"uuid"

	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
)

// capabilityInterval is how often a worker says again which extra codecs it can encode. The settings
// endpoint counts a worker seen within playback.WorkerFresh, five of these, so a missed beat or two does
// not make a codec unavailable.
const capabilityInterval = time.Minute

// capabilityRetention is how long the row of a worker that stopped is kept before a running worker
// removes it. It only keeps the table small: a row older than playback.WorkerFresh counts for nothing.
const capabilityRetention = 24 * time.Hour

// capabilityStore is the part of the database a worker reports its codecs to.
type capabilityStore interface {
	UpsertWorkerCapabilities(ctx context.Context, workerID uuid.UUID, codecs []string, at time.Time) error
	PruneWorkerCapabilities(ctx context.Context, cutoff time.Time) (int64, error)
}

// capabilityService records the extra codecs this worker process can encode (ADR 0064, ADR 0067), at
// startup and then every capabilityInterval, one row per process. A failed write is logged and tried
// again at the next beat: the worker keeps working whatever the state of the table.
type capabilityService struct {
	store  capabilityStore
	id     uuid.UUID
	codecs []string
	log    *slog.Logger
	now    func() time.Time
}

func newCapabilityService(store capabilityStore, codecs []media.Codec, log *slog.Logger) *capabilityService {
	names := make([]string, len(codecs))
	for i, c := range codecs {
		names[i] = string(c)
	}
	return &capabilityService{store: store, id: uuid.New(), codecs: slices.Clone(names), log: log, now: time.Now}
}

// report writes one heartbeat and prunes the rows of workers that are long gone.
func (s *capabilityService) report(ctx context.Context) {
	at := s.now().UTC()
	if err := s.store.UpsertWorkerCapabilities(ctx, s.id, s.codecs, at); err != nil {
		s.log.WarnContext(ctx, "could not record the worker's codecs", slog.String("error", err.Error()))
		return
	}
	if _, err := s.store.PruneWorkerCapabilities(ctx, at.Add(-capabilityRetention)); err != nil {
		s.log.WarnContext(ctx, "could not remove stale worker records", slog.String("error", err.Error()))
	}
}

func (s *capabilityService) run(ctx context.Context) error {
	s.report(ctx)
	t := time.NewTicker(capabilityInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.report(ctx)
		}
	}
}

func (*capabilityService) close() {}
