package accesslog

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

type sinkRecorder struct {
	mu     sync.Mutex
	counts []SegmentCount
}

func (s *sinkRecorder) SegmentsServed(_ context.Context, c []SegmentCount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts = append(s.counts, c...)
}

func (s *sinkRecorder) total(hash []byte) (n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.counts {
		if string(c.SessionHash) == string(hash) {
			n += c.Count
		}
	}
	return n
}

// The segment sink gets every flush's counts, and the final flush at Close.
func TestSegmentSinkReceivesTheCounts(t *testing.T) {
	st := &fakeStore{}
	sink := &sinkRecorder{}
	r := New(Options{Store: st, FlushInterval: 5 * time.Millisecond, SegmentFlushInterval: 20 * time.Millisecond})
	r.SetSegmentSink(sink)
	tenant, asset := newTenant(), id.New[id.AssetKind]()
	for range 3 {
		r.CountSegment(tenant, asset, hashOf("a"))
	}
	waitFor(t, func() bool { return sink.total(hashOf("a")) == 3 })
	r.CountSegment(tenant, asset, hashOf("a"))
	r.CountSegment(tenant, asset, hashOf("b"))
	closeRec(t, r)
	if sink.total(hashOf("a")) != 4 || sink.total(hashOf("b")) != 1 {
		t.Fatalf("sink saw %+v", sink.counts)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, c := range sink.counts {
		if c.TenantID != tenant || c.AssetID != asset {
			t.Fatalf("count = %+v", c)
		}
	}
}

// Without a sink, after removing it, and on a nil recorder, nothing changes.
func TestSegmentSinkIsOptional(t *testing.T) {
	var nilRec *Recorder
	nilRec.SetSegmentSink(&sinkRecorder{})
	st := &fakeStore{}
	r := New(Options{Store: st, FlushInterval: time.Hour, SegmentFlushInterval: time.Hour})
	r.SetSegmentSink(&sinkRecorder{})
	r.SetSegmentSink(nil)
	r.CountSegment(newTenant(), id.AssetID{}, hashOf("a"))
	closeRec(t, r)
	if rows := st.snapshot(); len(rows) != 1 || rows[0].SegmentsServed != 1 {
		t.Fatalf("rows = %+v", rows)
	}
}
