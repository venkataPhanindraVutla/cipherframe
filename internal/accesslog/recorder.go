// Package accesslog records the access trail (invariant I10): who played what and when, as one row
// per session event, and nothing about what was watched.
//
// What is never recorded: a session ID or token (only the SHA-256 of the session ID), which segment
// or position a viewer fetched, and anything a viewer does inside the player. Segment requests are
// counted per session and written as one "segments" row per flush interval.
//
// The trail is best effort and must never slow or fail playback. Requests hand events to a bounded
// queue without waiting; one background goroutine writes them in batches. When the queue is full
// (the database is slow or down) events are dropped and counted. A crash loses what is still
// queued (at most about a second of events and one segment-count interval).
//
// Privacy: the connecting address and the User-Agent are stored only for tenants that turned that on
// (db.PrivacySettings); the default is off.
package accesslog

import (
	"container/list"
	"context"
	"crypto/sha256"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// Defaults of Options.
const (
	DefaultQueueSize          = 8192
	DefaultBatchSize          = 500
	DefaultFlushInterval      = time.Second
	DefaultSegmentFlush       = 30 * time.Second
	DefaultMaxSegmentSessions = 10000
	// HeartbeatEvery is the most often a session's heartbeat is logged: a heartbeat arrives every
	// few tens of seconds, and one row per beat would be most of the table.
	HeartbeatEvery = 5 * time.Minute
	// KeyDeniedEvery is the most often a session's key denials are logged: a client that is
	// refused tends to retry at once.
	KeyDeniedEvery        = time.Minute
	defaultThrottleSize   = 10000
	defaultPrivacyTTL     = 30 * time.Second
	privacyCacheMax       = 1024
	maxPending            = 4 * DefaultBatchSize
	maxAttempts           = 3
	writeTimeout          = 10 * time.Second
	warnEvery             = time.Minute
	deniedPerTenantPerMin = 30
	deniedPerMinTotal     = 300
	deniedTenantsMax      = 1024
)

// Store is what the recorder reads and writes. *db.Repos implements it.
type Store interface {
	InsertAccessLog(ctx context.Context, rows []db.AccessLogRow) error
	GetPrivacySettings(ctx context.Context, tenantID id.TenantID) (db.PrivacySettings, error)
	SessionViewers(ctx context.Context, hashes [][]byte) (map[string]db.SessionViewer, error)
}

// SegmentCount is how many segments one session was served since the previous flush.
type SegmentCount struct {
	TenantID    id.TenantID
	AssetID     id.AssetID
	SessionHash []byte
	Count       int
}

// SegmentSink receives the segment counts at every flush, right after they are queued for the
// trail. The anomaly detector uses it for segments_without_key (M4-9). It runs on the writer
// goroutine with a bounded context, so it must be quick; an implementation logs its own failures
// (the counts of that interval are lost to it, never retried).
type SegmentSink interface {
	SegmentsServed(ctx context.Context, counts []SegmentCount)
}

type sinkHolder struct{ s SegmentSink }

// Event is one thing that happened. Leave ViewerID and AuthMethod empty when only the session is
// known: the writer fills them from the session row.
type Event struct {
	TenantID    id.TenantID
	AssetID     id.AssetID
	SessionHash []byte
	ViewerID    string
	AuthMethod  string
	Kind        string // one of the db.Access constants
	At          time.Time
	RequestID   string
	// Client is stored only when the tenant's privacy settings allow it. Leave it empty for events
	// that were not caused by the viewer's own request (an API call, the sweeper).
	Client Client

	segments int // the count of a "segments" event; set by the counter only
}

// Options configure a Recorder. Zero fields take the defaults above.
type Options struct {
	Store                Store
	Log                  *slog.Logger
	Now                  func() time.Time
	QueueSize            int
	BatchSize            int
	FlushInterval        time.Duration
	SegmentFlushInterval time.Duration
	MaxSegmentSessions   int
	PrivacyTTL           time.Duration
}

// Stats are counters for tests and diagnostics.
type Stats struct {
	// Queued is how many events were accepted, Written how many rows were stored.
	Queued, Written uint64
	// Dropped counts events lost because the queue was full or a write kept failing, and
	// SegmentsDropped segment counts lost because too many sessions were being counted.
	Dropped, SegmentsDropped uint64
	// Throttled counts events skipped on purpose (heartbeat, key_denied and denial limits).
	Throttled uint64
}

// Recorder collects access events. All methods are safe for concurrent use and are no-ops on a nil
// *Recorder, so callers need no check.
type Recorder struct {
	o  Options
	ch chan Event

	closeOnce sync.Once
	closing   chan struct{}
	done      chan struct{}
	mu        sync.RWMutex // guards sends against close of ch
	closed    bool

	queued, written, dropped, segDropped, throttled atomic.Uint64
	lastWarn                                        atomic.Int64 // unix nanoseconds

	sink atomic.Pointer[sinkHolder]

	seg      *segmentCounter
	throttle *throttle
	denied   *deniedLimiter

	privacy map[id.TenantID]privacyEntry // only the writer goroutine touches it
}

type privacyEntry struct {
	set     db.PrivacySettings
	expires time.Time
}

// New builds a Recorder and starts its writer. Call Close to flush it.
func New(o Options) *Recorder {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.QueueSize <= 0 {
		o.QueueSize = DefaultQueueSize
	}
	if o.BatchSize <= 0 {
		o.BatchSize = DefaultBatchSize
	}
	if o.FlushInterval <= 0 {
		o.FlushInterval = DefaultFlushInterval
	}
	if o.SegmentFlushInterval <= 0 {
		o.SegmentFlushInterval = DefaultSegmentFlush
	}
	if o.MaxSegmentSessions <= 0 {
		o.MaxSegmentSessions = DefaultMaxSegmentSessions
	}
	if o.PrivacyTTL <= 0 {
		o.PrivacyTTL = defaultPrivacyTTL
	}
	r := &Recorder{
		o: o, ch: make(chan Event, o.QueueSize), closing: make(chan struct{}), done: make(chan struct{}),
		seg:      &segmentCounter{max: o.MaxSegmentSessions, m: map[[sha256.Size]byte]*segCount{}},
		throttle: newThrottle(defaultThrottleSize),
		denied:   &deniedLimiter{tenants: map[id.TenantID]*window{}},
		privacy:  map[id.TenantID]privacyEntry{},
	}
	go r.run()
	return r
}

// SetSegmentSink sets the receiver of the segment counts (nil removes it). Set it before traffic
// starts; the recorder and its sink refer to each other, so it cannot be an option.
func (r *Recorder) SetSegmentSink(s SegmentSink) {
	if r == nil {
		return
	}
	if s == nil {
		r.sink.Store(nil)
		return
	}
	r.sink.Store(&sinkHolder{s: s})
}

// Stats returns the counters.
func (r *Recorder) Stats() Stats {
	if r == nil {
		return Stats{}
	}
	return Stats{
		Queued: r.queued.Load(), Written: r.written.Load(), Dropped: r.dropped.Load(),
		SegmentsDropped: r.segDropped.Load(), Throttled: r.throttled.Load(),
	}
}

// Record queues ev without waiting. When the queue is full, or the recorder is closed, the event is
// dropped and counted.
func (r *Recorder) Record(ev Event) {
	if r == nil || ev.TenantID.IsZero() || !db.ValidAccessEvent(ev.Kind) {
		return
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		r.drop(1)
		return
	}
	select {
	case r.ch <- ev:
		r.queued.Add(1)
	default:
		r.drop(1)
	}
}

// RecordHeartbeat is Record for a heartbeat, at most once per HeartbeatEvery per session per
// replica. The last time is kept in a bounded in-memory table (the least recently used session is
// forgotten first), so it costs no database round trip; another replica keeps its own.
func (r *Recorder) RecordHeartbeat(ev Event) {
	if r == nil {
		return
	}
	if !r.throttle.allow(ev.SessionHash, ev.Kind, ev.At, HeartbeatEvery) {
		r.throttled.Add(1)
		return
	}
	r.Record(ev)
}

// RecordKeyDenied is Record for a refused key request, at most once per KeyDeniedEvery per session.
func (r *Recorder) RecordKeyDenied(ev Event) {
	if r == nil {
		return
	}
	if !r.throttle.allow(ev.SessionHash, ev.Kind, ev.At, KeyDeniedEvery) {
		r.throttled.Add(1)
		return
	}
	r.Record(ev)
}

// RecordSessionDenied is Record for a refused session creation. Anyone on the internet can start
// that request for any tenant, so it is limited: at most deniedPerTenantPerMin rows per tenant and
// deniedPerMinTotal rows in all per minute per replica, the rest counted as throttled. Rows for a
// tenant that does not exist are discarded by the writer.
func (r *Recorder) RecordSessionDenied(ev Event) {
	if r == nil {
		return
	}
	if !r.denied.allow(ev.TenantID, ev.At) {
		r.throttled.Add(1)
		return
	}
	r.Record(ev)
}

// CountSegment counts one served segment request for a session. Only the count is kept: not which
// segment, rendition or position. It never blocks. When more than MaxSegmentSessions sessions are
// being counted at once, a new session's counts are dropped (and counted in Stats) until the next
// flush.
func (r *Recorder) CountSegment(tenant id.TenantID, asset id.AssetID, hash []byte) {
	if r == nil || len(hash) != sha256.Size || tenant.IsZero() {
		return
	}
	if !r.seg.add(tenant, asset, hash) {
		r.segDropped.Add(1)
	}
}

// Close stops accepting events, writes the segment counts and everything queued, and waits for the
// writer, until ctx ends. It is safe to call more than once.
func (r *Recorder) Close(ctx context.Context) {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		close(r.closing)
		r.mu.Unlock()
	})
	select {
	case <-r.done:
	case <-ctx.Done():
		r.o.Log.Warn("access log: shutdown flush did not finish")
	}
}

func (r *Recorder) drop(n uint64) {
	r.dropped.Add(n)
	now := r.o.Now().UnixNano()
	last := r.lastWarn.Load()
	if now-last >= int64(warnEvery) && r.lastWarn.CompareAndSwap(last, now) {
		r.o.Log.Warn("access log is overloaded or unavailable: events are being dropped",
			slog.Uint64("dropped_total", r.dropped.Load()))
	}
}

// run is the writer goroutine.
func (r *Recorder) run() {
	defer close(r.done)
	flushT := time.NewTicker(r.o.FlushInterval)
	segT := time.NewTicker(r.o.SegmentFlushInterval)
	defer flushT.Stop()
	defer segT.Stop()

	var batch []Event
	failures := 0
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
		err := r.write(ctx, batch)
		cancel()
		if err == nil {
			batch, failures = batch[:0], 0
			return
		}
		failures++
		if failures >= maxAttempts {
			r.drop(uint64(len(batch)))
			r.o.Log.Error("access log: dropping events after repeated write failures",
				slog.Int("events", len(batch)), slog.Any("error", err))
			batch, failures = batch[:0], 0
			return
		}
		r.o.Log.Warn("access log: write failed, will retry", slog.Any("error", err))
		if len(batch) > maxPending {
			r.drop(uint64(len(batch) - maxPending)) //nolint:gosec // len(batch) > maxPending here
			batch = batch[:maxPending]
		}
	}
	addSegments := func() {
		events := r.seg.drain(r.o.Now())
		batch = append(batch, events...)
		r.deliverSegments(events)
	}
	for {
		select {
		case ev := <-r.ch:
			batch = append(batch, ev)
			if len(batch) >= r.o.BatchSize {
				flush()
			}
		case <-flushT.C:
			flush()
		case <-segT.C:
			addSegments()
			flush()
		case <-r.closing:
			// No sender is active any more (Close holds the lock while it sets closed), so the
			// channel only has to be emptied.
			for {
				select {
				case ev := <-r.ch:
					batch = append(batch, ev)
					continue
				default:
				}
				break
			}
			addSegments()
			// A last attempt, and one more if it failed.
			for i := 0; i < maxAttempts && len(batch) > 0; i++ {
				flush()
			}
			return
		}
	}
}

// deliverSegments hands the drained counts to the sink, if there is one.
func (r *Recorder) deliverSegments(events []Event) {
	h := r.sink.Load()
	if h == nil || len(events) == 0 {
		return
	}
	counts := make([]SegmentCount, len(events))
	for i, ev := range events {
		counts[i] = SegmentCount{TenantID: ev.TenantID, AssetID: ev.AssetID, SessionHash: ev.SessionHash, Count: ev.segments}
	}
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	h.s.SegmentsServed(ctx, counts)
}

// write converts events to rows, applying the tenants' privacy settings and filling in viewers, and
// inserts them.
func (r *Recorder) write(ctx context.Context, events []Event) error {
	// Viewers of sessions that only the session is known for.
	var need [][]byte
	seen := map[string]bool{}
	for _, ev := range events {
		if ev.ViewerID == "" && len(ev.SessionHash) > 0 && !seen[string(ev.SessionHash)] {
			seen[string(ev.SessionHash)] = true
			need = append(need, ev.SessionHash)
		}
	}
	var viewers map[string]db.SessionViewer
	if len(need) > 0 {
		v, err := r.o.Store.SessionViewers(ctx, need)
		if err != nil {
			return err
		}
		viewers = v
	}
	rows := make([]db.AccessLogRow, 0, len(events))
	for _, ev := range events {
		row := db.AccessLogRow{
			TenantID: ev.TenantID, AssetID: ev.AssetID, SessionHash: ev.SessionHash, ViewerID: ev.ViewerID,
			AuthMethod: ev.AuthMethod, Event: ev.Kind, At: ev.At.UTC().Truncate(time.Microsecond), RequestID: ev.RequestID,
		}
		if row.ViewerID == "" && len(ev.SessionHash) > 0 {
			if v, ok := viewers[string(ev.SessionHash)]; ok {
				row.ViewerID, row.AuthMethod = v.ViewerID, v.AuthMethod
			}
		}
		if ev.Client != (Client{}) {
			set := r.privacyOf(ctx, ev.TenantID)
			if set.StoreIP {
				row.IP = cleanIP(ev.Client.RemoteAddr)
			}
			if set.StoreUserAgent {
				row.UserAgent = cleanUserAgent(ev.Client.UserAgent)
			}
		}
		if ev.Kind == db.AccessSegments {
			row.SegmentsServed = ev.segments
		}
		rows = append(rows, row)
	}
	if err := r.o.Store.InsertAccessLog(ctx, rows); err != nil {
		return err
	}
	r.written.Add(uint64(len(rows)))
	return nil
}

// privacyOf returns the tenant's privacy settings from a short-lived cache. When they cannot be
// read the answer is the most private one, and it is not cached.
func (r *Recorder) privacyOf(ctx context.Context, tenant id.TenantID) db.PrivacySettings {
	now := r.o.Now()
	if e, ok := r.privacy[tenant]; ok && now.Before(e.expires) {
		return e.set
	}
	set, err := r.o.Store.GetPrivacySettings(ctx, tenant)
	if err != nil {
		r.o.Log.Warn("access log: privacy settings unavailable, storing no address or user agent", slog.Any("error", err))
		return db.DefaultPrivacySettings()
	}
	if len(r.privacy) >= privacyCacheMax {
		clear(r.privacy)
	}
	r.privacy[tenant] = privacyEntry{set: set, expires: now.Add(r.o.PrivacyTTL)}
	return set
}

// segmentCounter counts served segments per session, bounded.
type segmentCounter struct {
	mu  sync.Mutex
	max int
	m   map[[sha256.Size]byte]*segCount
}

type segCount struct {
	tenant id.TenantID
	asset  id.AssetID
	hash   []byte
	n      int
}

func (c *segmentCounter) add(tenant id.TenantID, asset id.AssetID, hash []byte) bool {
	var k [sha256.Size]byte
	copy(k[:], hash)
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[k]; ok {
		e.n++
		return true
	}
	if len(c.m) >= c.max {
		return false
	}
	c.m[k] = &segCount{tenant: tenant, asset: asset, hash: append([]byte(nil), hash...), n: 1}
	return true
}

// drain returns one "segments" event per counted session and empties the counter.
func (c *segmentCounter) drain(now time.Time) []Event {
	c.mu.Lock()
	old := c.m
	c.m = make(map[[sha256.Size]byte]*segCount, len(old))
	c.mu.Unlock()
	out := make([]Event, 0, len(old))
	for _, e := range old {
		out = append(out, Event{
			TenantID: e.tenant, AssetID: e.asset, SessionHash: e.hash, Kind: db.AccessSegments, At: now, segments: e.n,
		})
	}
	return out
}

// throttle remembers when each (session, event) was last logged, in a bounded LRU.
type throttle struct {
	mu  sync.Mutex
	max int
	l   *list.List
	m   map[string]*list.Element
}

type throttleEntry struct {
	key  string
	last time.Time
}

func newThrottle(max int) *throttle {
	return &throttle{max: max, l: list.New(), m: map[string]*list.Element{}}
}

// allow reports whether an event of the kind for the session may be logged at now, and records it
// if so.
func (t *throttle) allow(hash []byte, kind string, now time.Time, every time.Duration) bool {
	key := string(hash) + "|" + kind
	t.mu.Lock()
	defer t.mu.Unlock()
	if el, ok := t.m[key]; ok {
		e := el.Value.(*throttleEntry)
		if now.Sub(e.last) < every && !now.Before(e.last) {
			t.l.MoveToFront(el)
			return false
		}
		e.last = now
		t.l.MoveToFront(el)
		return true
	}
	t.m[key] = t.l.PushFront(&throttleEntry{key: key, last: now})
	if t.l.Len() > t.max {
		oldest := t.l.Back()
		t.l.Remove(oldest)
		delete(t.m, oldest.Value.(*throttleEntry).key)
	}
	return true
}

// deniedLimiter is a fixed one-minute window per tenant plus one for all tenants.
type deniedLimiter struct {
	mu      sync.Mutex
	tenants map[id.TenantID]*window
	total   window
}

type window struct {
	start time.Time
	n     int
}

func (w *window) take(now time.Time, limit int) bool {
	if now.Sub(w.start) >= time.Minute || now.Before(w.start) {
		w.start, w.n = now, 0
	}
	if w.n >= limit {
		return false
	}
	w.n++
	return true
}

func (d *deniedLimiter) allow(tenant id.TenantID, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.tenants) >= deniedTenantsMax {
		clear(d.tenants)
	}
	w, ok := d.tenants[tenant]
	if !ok {
		w = &window{}
		d.tenants[tenant] = w
	}
	if !w.take(now, deniedPerTenantPerMin) {
		return false
	}
	return d.total.take(now, deniedPerMinTotal)
}
