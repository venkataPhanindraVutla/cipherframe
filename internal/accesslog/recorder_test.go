package accesslog

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// fakeStore is an in-memory Store. block, when set, is waited on inside InsertAccessLog.
type fakeStore struct {
	mu       sync.Mutex
	rows     []db.AccessLogRow
	privacy  db.PrivacySettings
	viewers  map[string]db.SessionViewer
	failNext atomic.Int32
	block    chan struct{}
	inserts  atomic.Int32
}

func (f *fakeStore) InsertAccessLog(ctx context.Context, rows []db.AccessLogRow) error {
	f.inserts.Add(1)
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if f.failNext.Load() > 0 {
		f.failNext.Add(-1)
		return errors.New("database is down")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows = append(f.rows, rows...)
	return nil
}

func (f *fakeStore) GetPrivacySettings(context.Context, id.TenantID) (db.PrivacySettings, error) {
	return f.privacy, nil
}

func (f *fakeStore) SessionViewers(_ context.Context, hashes [][]byte) (map[string]db.SessionViewer, error) {
	out := map[string]db.SessionViewer{}
	for _, h := range hashes {
		if v, ok := f.viewers[string(h)]; ok {
			out[string(h)] = v
		}
	}
	return out, nil
}

func (f *fakeStore) snapshot() []db.AccessLogRow {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]db.AccessLogRow(nil), f.rows...)
}

func newTenant() id.TenantID { return id.New[id.TenantKind]() }

func hashOf(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func closeRec(t *testing.T, r *Recorder) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r.Close(ctx)
}

func TestRecordWritesRowsAndFillsTheViewerFromTheSession(t *testing.T) {
	st := &fakeStore{viewers: map[string]db.SessionViewer{string(hashOf("s1")): {ViewerID: "viewer-1", AuthMethod: db.AuthMethodJWT}}}
	r := New(Options{Store: st, FlushInterval: 10 * time.Millisecond})
	tenant := newTenant()
	r.Record(Event{TenantID: tenant, SessionHash: hashOf("s1"), Kind: db.AccessKey, At: time.Now(), RequestID: "r1"})
	r.Record(Event{TenantID: tenant, SessionHash: hashOf("unknown"), Kind: db.AccessEnd, At: time.Now()})
	r.Record(Event{TenantID: tenant, ViewerID: "given", AuthMethod: db.AuthMethodCallback, SessionHash: hashOf("s1"), Kind: db.AccessSessionCreated, At: time.Now()})
	closeRec(t, r)
	rows := st.snapshot()
	if len(rows) != 3 {
		t.Fatalf("%d rows", len(rows))
	}
	if rows[0].ViewerID != "viewer-1" || rows[0].AuthMethod != db.AuthMethodJWT || rows[0].RequestID != "r1" {
		t.Fatalf("row 0 = %+v", rows[0])
	}
	if rows[1].ViewerID != "" {
		t.Fatalf("an unknown session got a viewer: %+v", rows[1])
	}
	if rows[2].ViewerID != "given" || rows[2].AuthMethod != db.AuthMethodCallback {
		t.Fatalf("row 2 = %+v", rows[2])
	}
	if s := r.Stats(); s.Written != 3 || s.Dropped != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestPrivacySettingsDecideWhatIsStored(t *testing.T) {
	cl := Client{RemoteAddr: "198.51.100.7:51234", UserAgent: "Mozilla/5.0\x00 (X11)\n" + strings.Repeat("é", 400)}
	for _, tc := range []struct {
		name     string
		set      db.PrivacySettings
		wantIP   string
		wantUA   bool
		uaLength int
	}{
		{"default is off", db.PrivacySettings{}, "", false, 0},
		{"ip only", db.PrivacySettings{StoreIP: true}, "198.51.100.7", false, 0},
		{"ua only", db.PrivacySettings{StoreUserAgent: true}, "", true, 256},
		{"both", db.PrivacySettings{StoreIP: true, StoreUserAgent: true}, "198.51.100.7", true, 256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &fakeStore{privacy: tc.set}
			r := New(Options{Store: st})
			r.Record(Event{TenantID: newTenant(), Kind: db.AccessSessionCreated, At: time.Now(), Client: cl})
			closeRec(t, r)
			rows := st.snapshot()
			if len(rows) != 1 {
				t.Fatalf("%d rows", len(rows))
			}
			if rows[0].IP != tc.wantIP {
				t.Errorf("ip = %q, want %q", rows[0].IP, tc.wantIP)
			}
			if (rows[0].UserAgent != "") != tc.wantUA {
				t.Fatalf("user agent = %q", rows[0].UserAgent)
			}
			if tc.wantUA {
				if n := len([]rune(rows[0].UserAgent)); n > tc.uaLength || strings.ContainsAny(rows[0].UserAgent, "\x00\n") {
					t.Errorf("user agent has %d chars or control characters: %q", n, rows[0].UserAgent)
				}
			}
		})
	}
}

func TestCleanIP(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.5:80":        "203.0.113.5",
		"[2001:db8::1]:443":     "2001:db8::1",
		"[::ffff:192.0.2.1]:80": "192.0.2.1",
		"[fe80::1%eth0]:80":     "fe80::1",
		"203.0.113.5":           "203.0.113.5",
		"":                      "",
		"not an address":        "",
	} {
		if got := cleanIP(in); got != want {
			t.Errorf("cleanIP(%q) = %q, want %q", in, got, want)
		}
	}
}

// A full queue and a blocked database must not block the caller, and what does not fit is counted.
func TestFullQueueDropsWithoutBlocking(t *testing.T) {
	st := &fakeStore{block: make(chan struct{})}
	r := New(Options{Store: st, QueueSize: 2, BatchSize: 1, FlushInterval: time.Hour})
	tenant := newTenant()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			r.Record(Event{TenantID: tenant, Kind: db.AccessPlaylist, At: time.Now()})
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Record blocked on a full queue")
	}
	s := r.Stats()
	// One event is in the writer (stuck in the blocked insert), two fit the queue.
	if s.Dropped < 90 || s.Queued+s.Dropped != 100 {
		t.Fatalf("stats = %+v", s)
	}
	close(st.block) // the database comes back
	closeRec(t, r)
	if got := uint64(len(st.snapshot())); got != s.Queued {
		t.Fatalf("wrote %d rows, queued %d", got, s.Queued)
	}
}

func TestRecordAfterCloseIsDroppedNotPanicking(t *testing.T) {
	st := &fakeStore{}
	r := New(Options{Store: st})
	closeRec(t, r)
	r.Record(Event{TenantID: newTenant(), Kind: db.AccessKey, At: time.Now()})
	r.CountSegment(newTenant(), id.AssetID{}, hashOf("s"))
	closeRec(t, r) // twice is fine
	if r.Stats().Dropped != 1 {
		t.Fatalf("stats = %+v", r.Stats())
	}
}

func TestNilRecorderIsANoOp(t *testing.T) {
	var r *Recorder
	r.Record(Event{})
	r.RecordHeartbeat(Event{})
	r.RecordKeyDenied(Event{})
	r.RecordSessionDenied(Event{})
	r.CountSegment(id.TenantID{}, id.AssetID{}, nil)
	r.Close(context.Background())
	if r.Stats() != (Stats{}) {
		t.Fatal("stats")
	}
}

// Shutdown writes what is queued and the segment counts that were never flushed.
func TestCloseFlushesQueueAndSegmentCounts(t *testing.T) {
	st := &fakeStore{}
	r := New(Options{Store: st, FlushInterval: time.Hour, SegmentFlushInterval: time.Hour})
	tenant := newTenant()
	asset := id.New[id.AssetKind]()
	r.Record(Event{TenantID: tenant, Kind: db.AccessEnd, At: time.Now()})
	for range 5 {
		r.CountSegment(tenant, asset, hashOf("a"))
	}
	r.CountSegment(tenant, asset, hashOf("b"))
	closeRec(t, r)
	rows := st.snapshot()
	counts := map[string]int{}
	var ends int
	for _, row := range rows {
		switch row.Event {
		case db.AccessSegments:
			counts[string(row.SessionHash)] = row.SegmentsServed
			if row.AssetID != asset || row.TenantID != tenant {
				t.Fatalf("segments row = %+v", row)
			}
		case db.AccessEnd:
			ends++
		}
	}
	if ends != 1 || counts[string(hashOf("a"))] != 5 || counts[string(hashOf("b"))] != 1 || len(counts) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestSegmentCountsFlushPeriodicallyAndStartOver(t *testing.T) {
	st := &fakeStore{}
	r := New(Options{Store: st, FlushInterval: 5 * time.Millisecond, SegmentFlushInterval: 20 * time.Millisecond})
	tenant := newTenant()
	asset := id.New[id.AssetKind]()
	r.CountSegment(tenant, asset, hashOf("a"))
	r.CountSegment(tenant, asset, hashOf("a"))
	waitFor(t, func() bool { return len(st.snapshot()) >= 1 })
	r.CountSegment(tenant, asset, hashOf("a"))
	closeRec(t, r)
	var total, rows int
	for _, row := range st.snapshot() {
		total += row.SegmentsServed
		rows++
		if row.SegmentsServed < 1 {
			t.Fatalf("a zero-count row: %+v", row)
		}
	}
	if total != 3 || rows < 2 {
		t.Fatalf("total %d in %d rows; want 3 in at least 2 (the count starts over after a flush)", total, rows)
	}
}

func TestSegmentCounterIsBounded(t *testing.T) {
	st := &fakeStore{}
	r := New(Options{Store: st, MaxSegmentSessions: 3, SegmentFlushInterval: time.Hour, FlushInterval: time.Hour})
	tenant := newTenant()
	for i := range 10 {
		r.CountSegment(tenant, id.AssetID{}, hashOf(string(rune('a'+i))))
	}
	r.CountSegment(tenant, id.AssetID{}, hashOf("a")) // an already counted session still counts
	if got := r.Stats().SegmentsDropped; got != 7 {
		t.Fatalf("dropped = %d, want 7", got)
	}
	closeRec(t, r)
	if n := len(st.snapshot()); n != 3 {
		t.Fatalf("%d rows, want 3", n)
	}
}

// A failing database is retried on the next tick; counts and events are not lost.
func TestWriteFailureIsRetried(t *testing.T) {
	st := &fakeStore{}
	st.failNext.Store(1)
	r := New(Options{Store: st, FlushInterval: 5 * time.Millisecond})
	r.Record(Event{TenantID: newTenant(), Kind: db.AccessEnd, At: time.Now()})
	waitFor(t, func() bool { return len(st.snapshot()) == 1 })
	closeRec(t, r)
	if s := r.Stats(); s.Dropped != 0 || s.Written != 1 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestPersistentFailureDropsAfterAttempts(t *testing.T) {
	st := &fakeStore{}
	st.failNext.Store(1000)
	r := New(Options{Store: st, FlushInterval: 5 * time.Millisecond})
	r.Record(Event{TenantID: newTenant(), Kind: db.AccessEnd, At: time.Now()})
	waitFor(t, func() bool { return r.Stats().Dropped == 1 })
	closeRec(t, r)
}

func TestHeartbeatIsThrottledPerSession(t *testing.T) {
	st := &fakeStore{}
	r := New(Options{Store: st})
	tenant := newTenant()
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	hb := func(sess string, at time.Time) {
		r.RecordHeartbeat(Event{TenantID: tenant, SessionHash: hashOf(sess), Kind: db.AccessHeartbeat, At: at})
	}
	hb("s1", t0)
	hb("s1", t0.Add(30*time.Second))
	hb("s1", t0.Add(4*time.Minute))
	hb("s2", t0.Add(time.Minute)) // another session is independent
	hb("s1", t0.Add(5*time.Minute))
	hb("s1", t0.Add(9*time.Minute))
	closeRec(t, r)
	if n := len(st.snapshot()); n != 3 {
		t.Fatalf("%d heartbeat rows, want 3 (s1 at 0 and 5 minutes, s2)", n)
	}
	if r.Stats().Throttled != 3 {
		t.Fatalf("stats = %+v", r.Stats())
	}
}

func TestThrottleIsBounded(t *testing.T) {
	th := newThrottle(3)
	now := time.Now()
	for i := range 10 {
		th.allow(hashOf(string(rune('a'+i))), db.AccessHeartbeat, now, time.Hour)
	}
	if len(th.m) != 3 || th.l.Len() != 3 {
		t.Fatalf("table holds %d entries", len(th.m))
	}
	// The most recent three are still remembered, the oldest forgotten.
	if th.allow(hashOf("j"), db.AccessHeartbeat, now, time.Hour) {
		t.Fatal("a remembered session was allowed again")
	}
	if !th.allow(hashOf("a"), db.AccessHeartbeat, now, time.Hour) {
		t.Fatal("a forgotten session was not allowed")
	}
}

func TestSessionDeniedIsLimited(t *testing.T) {
	st := &fakeStore{}
	r := New(Options{Store: st})
	tenant := newTenant()
	now := time.Now()
	for range 100 {
		r.RecordSessionDenied(Event{TenantID: tenant, Kind: db.AccessSessionDenied, At: now})
	}
	// Another tenant has its own budget.
	r.RecordSessionDenied(Event{TenantID: newTenant(), Kind: db.AccessSessionDenied, At: now})
	closeRec(t, r)
	if n := len(st.snapshot()); n != deniedPerTenantPerMin+1 {
		t.Fatalf("%d rows, want %d", n, deniedPerTenantPerMin+1)
	}
	// The next minute the budget is back.
	r = New(Options{Store: st})
	r.denied.allow(tenant, now)
	if !r.denied.allow(tenant, now.Add(2*time.Minute)) {
		t.Fatal("the window did not reset")
	}
	closeRec(t, r)
}

func TestMiddlewareStoresPeerAddressAndUserAgentOnly(t *testing.T) {
	var got Client
	h := Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = ClientFrom(r.Context()) }))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/play/x", nil)
	req.RemoteAddr = "192.0.2.10:4000"
	req.Header.Set("User-Agent", "ua/1")
	req.Header.Set("X-Forwarded-For", "6.6.6.6") // never read: no trusted-proxy setting exists
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got != (Client{RemoteAddr: "192.0.2.10:4000", UserAgent: "ua/1"}) {
		t.Fatalf("client = %+v", got)
	}
	if ClientFrom(context.Background()) != (Client{}) {
		t.Fatal("zero client expected")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(2 * time.Millisecond)
	}
}
