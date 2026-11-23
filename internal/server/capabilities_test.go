package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"
	"uuid"

	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
)

type fakeCapabilityStore struct {
	rows    map[uuid.UUID][]string
	seen    map[uuid.UUID]time.Time
	pruned  []time.Time
	upsertE error
}

func (f *fakeCapabilityStore) UpsertWorkerCapabilities(_ context.Context, id uuid.UUID, codecs []string, at time.Time) error {
	if f.upsertE != nil {
		return f.upsertE
	}
	f.rows[id], f.seen[id] = codecs, at
	return nil
}

func (f *fakeCapabilityStore) PruneWorkerCapabilities(_ context.Context, cutoff time.Time) (int64, error) {
	f.pruned = append(f.pruned, cutoff)
	return 0, nil
}

func TestCapabilityServiceReportsTheCodecsOfThisWorker(t *testing.T) {
	store := &fakeCapabilityStore{rows: map[uuid.UUID][]string{}, seen: map[uuid.UUID]time.Time{}}
	at := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	s := newCapabilityService(store, []media.Codec{media.CodecHEVC, media.CodecAV1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.now = func() time.Time { return at }
	s.report(t.Context())
	if got := store.rows[s.id]; !slices.Equal(got, []string{"hevc", "av1"}) || !store.seen[s.id].Equal(at) {
		t.Fatalf("recorded %v at %v", got, store.seen[s.id])
	}
	if len(store.pruned) != 1 || !store.pruned[0].Equal(at.Add(-capabilityRetention)) {
		t.Fatalf("pruned %v", store.pruned)
	}
	// Another beat updates the same row (one row per process); a second process has its own.
	at = at.Add(capabilityInterval)
	s.report(t.Context())
	other := newCapabilityService(store, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	other.report(t.Context())
	if len(store.rows) != 2 || !store.seen[s.id].Equal(at) || len(store.rows[other.id]) != 0 {
		t.Fatalf("rows %v", store.rows)
	}
}

// A write that fails is logged and does not stop the worker.
func TestCapabilityServiceSurvivesAFailedWrite(t *testing.T) {
	store := &fakeCapabilityStore{upsertE: errors.New("database is down")}
	s := newCapabilityService(store, []media.Codec{media.CodecAV1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.report(t.Context()) // must not panic or block
	if len(store.pruned) != 0 {
		t.Error("pruned after a failed write")
	}
}

// The settings endpoint counts a worker seen within WorkerFresh, so several beats fit inside it.
func TestCapabilityHeartbeatFitsInsideTheFreshnessWindow(t *testing.T) {
	if capabilityInterval*3 > playback.WorkerFresh {
		t.Fatalf("a worker beating every %s is not seen as fresh for %s", capabilityInterval, playback.WorkerFresh)
	}
}
