//go:build integration

package edge_test

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/venkataPhanindraVutla/cipherframe/internal/anomaly"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
)

// useSignals prepares the env for the anomaly tests: a recorder that flushes segment counts every
// few milliseconds (the sink raises segments_without_key there), and the tenant's settings.
func (e *env) useSignals(edit func(*db.PlaybackSettings)) {
	e.t.Helper()
	e.segFlush = 20 * time.Millisecond
	e.useAccess()
	if edit != nil {
		e.settings(edit)
	}
}

// eventCounts returns how many events of each kind exist.
func (e *env) eventCounts() map[string]int {
	e.t.Helper()
	rows, err := e.pool.Query(context.Background(), "SELECT kind, count(*) FROM playback_events GROUP BY kind")
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			e.t.Fatal(err)
		}
		out[k] = n
	}
	return out
}

// waitEvents waits until n events of the kind exist (the segment sink runs on the recorder's
// writer goroutine).
func (e *env) waitEvents(kind string, n int) {
	e.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for e.events(kind) < n {
		if time.Now().After(deadline) {
			e.t.Fatalf("%s events = %d, want %d", kind, e.events(kind), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (e *env) state(s session) db.PlaybackSession {
	return e.row(s)
}

func (e *env) segment(s session, tok, name string) {
	e.t.Helper()
	want(e.t, e.get("/v1/play/"+s.id+"/"+name, tok), 200)
}

// create makes a session through the service and returns its error instead of failing.
func (e *env) create(viewer string) (session, error) {
	c, err := e.svc.CreateSession(context.Background(), playback.CreateInput{
		TenantID: e.res.Tenant.ID, ClientID: e.res.Client.ID, AssetID: e.asset.ID, ViewerID: viewer,
	})
	if err != nil {
		return session{}, err
	}
	return session{id: c.SessionID.String(), token: c.Token.Reveal()}, nil
}

// allKinds turns on auto-revoke for every kind a tenant may enable.
func allKinds(s *db.PlaybackSettings) { s.AutoRevoke = db.AutoRevokeKinds }

// ACCEPTANCE: normal playback does not raise an anomaly. The viewer is realistic (master and media
// playlists, the key fetched a few times including a rendition switch and a reload that carries a
// new token from a heartbeat, 120 segments over twelve simulated minutes with a heartbeat every
// minute, then end), and every auto-revoke kind is ON, so a false positive would also revoke.
func TestNormalPlaybackRaisesNoAnomalies(t *testing.T) {
	e := newEnv(t)
	e.useSignals(allKinds)
	s := e.session("viewer-1")
	id := "/v1/play/" + s.id + "/"
	tok := s.token

	want(t, e.get(id+"master.m3u8", tok), 200)
	want(t, e.get(id+"720p/media.m3u8", tok), 200)
	want(t, e.get(keyPath(s), tok), 200)
	e.segment(s, tok, "720p/init.mp4")

	segments := 0
	play := func(rendition string, n int) {
		t.Helper()
		for i := range n {
			e.segment(s, tok, rendition+"/seg-"+string(rune('0'+i%segCount))+".m4s")
			segments++
			e.clk.advance(6 * time.Second)
		}
	}
	beat := func() { e.clk.advance(0); tok = e.beat(s, tok).Token }

	for minute := range 12 {
		switch minute {
		case 3: // the player switches rendition: new media playlist, key fetched again
			want(t, e.get(id+"240p/media.m3u8", tok), 200)
			want(t, e.get(keyPath(s), tok), 200)
			e.segment(s, tok, "240p/init.mp4")
		case 7: // a page reload: a fresh player starts again from the master playlist with the
			// token of the latest heartbeat
			want(t, e.get(id+"master.m3u8", tok), 200)
			want(t, e.get(id+"240p/media.m3u8", tok), 200)
			want(t, e.get(keyPath(s), tok), 200)
		}
		rend := "720p"
		if minute >= 3 {
			rend = "240p"
		}
		play(rend, 10)
		beat()
	}
	if segments != 120 {
		t.Fatalf("segments = %d", segments)
	}
	want(t, e.post(endPath(s), tok), 204)
	e.closeAccess() // flushes the segment counts through the detector

	if c := e.eventCounts(); len(c) != 0 {
		t.Fatalf("normal playback raised events: %v", c)
	}
	st := e.state(s)
	if st.State != db.PlaybackEnded || st.RevokeReason != "" {
		t.Fatalf("session = %+v", st)
	}
	var served int64
	if err := e.pool.QueryRow(context.Background(), "SELECT segments_served FROM playback_sessions WHERE key_served_at IS NOT NULL").Scan(&served); err != nil || served < 120 {
		t.Fatalf("segments counted on the session = %d, %v", served, err)
	}
}

// ACCEPTANCE: a scraper raises anomalies.
func TestScraperSimulationRaisesAnomalies(t *testing.T) {
	t.Run("one viewer creating 15 sessions in two minutes", func(t *testing.T) {
		e := newEnv(t)
		e.useSignals(func(s *db.PlaybackSettings) { s.MaxSessionsPerViewer = 12 })
		made, refused := 0, 0
		for range 15 {
			if _, err := e.create("scraper"); err != nil {
				refused++
			} else {
				made++
			}
			e.clk.advance(8 * time.Second)
		}
		if made != 12 || refused != 3 {
			t.Fatalf("created %d, refused %d", made, refused)
		}
		c := e.eventCounts()
		if c[db.EventRapidSessionCreation] != 1 || c[db.EventSessionLimit] != 1 || len(c) != 2 {
			t.Fatalf("events = %v, want one rapid_session_creation and one session_limit", c)
		}
		var viewer string
		var detail string
		if err := e.pool.QueryRow(context.Background(), "SELECT viewer_id, detail::text FROM playback_events WHERE kind = 'rapid_session_creation' AND session_hash IS NULL").Scan(&viewer, &detail); err != nil {
			t.Fatal(err)
		}
		if viewer != "scraper" || !strings.Contains(detail, `"limit": 10`) || !strings.Contains(detail, `"sessions": 11`) {
			t.Fatalf("viewer %q, detail %s", viewer, detail)
		}
		// A different viewer is not affected.
		if _, err := e.create("viewer-2"); err != nil {
			t.Fatal(err)
		}
		if c := e.eventCounts(); c[db.EventRapidSessionCreation] != 1 || c[db.EventSessionLimit] != 1 {
			t.Fatalf("events after another viewer = %v", c)
		}
	})

	t.Run("a client hammering the key endpoint", func(t *testing.T) {
		e := newEnv(t)
		e.useSignals(nil)
		s := e.session("viewer-1")
		ok, limited := 0, 0
		for range 40 {
			r := e.get(keyPath(s), s.token)
			switch r.status {
			case 200:
				ok++
			case 429:
				limited++
			default:
				t.Fatalf("status %d", r.status)
			}
		}
		if ok != 20 || limited != 20 { // the token bound (20 per token) bites before the rate (30 per minute)
			t.Fatalf("ok %d, limited %d", ok, limited)
		}
		c := e.eventCounts()
		if c[db.EventKeyReplay] != 1 || c[db.EventKeyRate] != 1 || len(c) != 2 {
			t.Fatalf("events = %v, want one key_replay and one key_rate", c)
		}
	})

	t.Run("fifty segments without ever fetching the key", func(t *testing.T) {
		e := newEnv(t)
		e.useSignals(nil)
		s := e.session("viewer-1")
		for i := range 50 {
			e.segment(s, s.token, "240p/seg-"+string(rune('0'+i%segCount))+".m4s")
		}
		e.waitEvents(db.EventSegmentsWithoutKey, 1)
		// More segments do not add events: once per session.
		for range 20 {
			e.segment(s, s.token, "240p/seg-0.m4s")
		}
		e.closeAccess()
		c := e.eventCounts()
		if c[db.EventSegmentsWithoutKey] != 1 || len(c) != 1 {
			t.Fatalf("events = %v, want one segments_without_key", c)
		}
		var detail string
		var viewer string
		if err := e.pool.QueryRow(context.Background(), "SELECT detail::text, viewer_id FROM playback_events").Scan(&detail, &viewer); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(detail, `"limit": 30`) || viewer != "viewer-1" {
			t.Fatalf("detail %s, viewer %q", detail, viewer)
		}
	})
}

// Auto-revoke is off unless the tenant turns a kind on: the events are recorded and nothing else
// changes.
func TestAutoRevokeIsOffByDefault(t *testing.T) {
	e := newEnv(t)
	e.useSignals(nil)
	s := e.session("viewer-1")
	for range 50 {
		e.segment(s, s.token, "240p/seg-0.m4s")
	}
	e.waitEvents(db.EventSegmentsWithoutKey, 1)
	if st := e.state(s); st.State != db.PlaybackActive || st.RevokeReason != "" {
		t.Fatalf("session = %+v, want it untouched", st)
	}
	want(t, e.get(keyPath(s), s.token), 200)
	// Hammering the key records events and still revokes nothing.
	for range 40 {
		e.get(keyPath(s), s.token)
	}
	if c := e.eventCounts(); c[db.EventKeyReplay] != 1 || c[db.EventKeyRate] != 1 {
		t.Fatalf("events = %v", c)
	}
	if st := e.state(s); st.State != db.PlaybackActive {
		t.Fatalf("session = %+v", st)
	}
	if n := e.count("SELECT count(*) FROM audit_events WHERE action LIKE '%auto_revoke'"); n != 0 {
		t.Fatalf("auto-revoke audit rows = %d", n)
	}
}

func (e *env) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func TestAutoRevokeOnSegmentsWithoutKeyRevokesTheSession(t *testing.T) {
	e := newEnv(t)
	e.useSignals(func(s *db.PlaybackSettings) { s.AutoRevoke = []string{db.EventSegmentsWithoutKey} })
	scraper, bystander := e.session("viewer-1"), e.session("viewer-2")
	want(t, e.get(keyPath(bystander), bystander.token), 200)
	for range 50 {
		e.segment(scraper, scraper.token, "240p/seg-0.m4s")
	}
	e.waitEvents(db.EventSegmentsWithoutKey, 1)
	deadline := time.Now().Add(10 * time.Second)
	for e.state(scraper).State != db.PlaybackRevoked {
		if time.Now().After(deadline) {
			t.Fatal("the session was not revoked")
		}
		time.Sleep(10 * time.Millisecond)
	}
	st := e.state(scraper)
	if st.RevokeReason != "auto:segments_without_key" || st.RevokedAt == nil {
		t.Fatalf("session = %+v", st)
	}
	// The key endpoint reads the row on every request, so the key is gone at once. (Segments are
	// checked against the token alone, by design; they are encrypted and useless without the key.)
	want(t, e.get(keyPath(scraper), scraper.token), 401)
	// Another session, that fetched its key, is untouched.
	want(t, e.get(keyPath(bystander), bystander.token), 200)
	if st := e.state(bystander); st.State != db.PlaybackActive {
		t.Fatalf("bystander = %+v", st)
	}

	// The access trail has the revoked row, without an address, and the action is audited.
	rows := e.trail(scraper)
	var revoked []db.AccessLogEntry
	for _, r := range rows {
		if r.Event == db.AccessRevoked {
			revoked = append(revoked, r)
		}
	}
	if len(revoked) != 1 || revoked[0].ViewerID != "viewer-1" || revoked[0].IP != "" || revoked[0].UserAgent != "" {
		t.Fatalf("revoked rows = %+v", revoked)
	}
	if n := e.count("SELECT count(*) FROM audit_events WHERE action = $1 AND client_id IS NULL AND target LIKE '%reason=auto:segments_without_key'", anomaly.AuditAutoRevoke); n != 1 {
		t.Fatalf("auto-revoke audit rows = %d", n)
	}
	// Doing it again changes nothing: still one revoked row, one event.
	if c := e.eventCounts(); c[db.EventSegmentsWithoutKey] != 1 {
		t.Fatalf("events = %v", c)
	}
}

func TestAutoRevokeOnKeyAbuseRevokesTheSession(t *testing.T) {
	for _, kind := range []string{db.EventKeyReplay, db.EventKeyRate} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t)
			e.useSignals(func(s *db.PlaybackSettings) {
				s.AutoRevoke = []string{kind}
				if kind == db.EventKeyRate { // reach the rate line before the token bound
					s.KeyRequestsPerMinute, s.KeyFetchesPerToken = 5, 100
				}
			})
			s := e.session("viewer-1")
			for range 40 {
				e.get(keyPath(s), s.token)
			}
			st := e.state(s)
			if st.State != db.PlaybackRevoked || st.RevokeReason != "auto:"+kind {
				t.Fatalf("session = %+v", st)
			}
			want(t, e.get(keyPath(s), s.token), 401)
			// A fresh session of the same viewer is a new session and plays.
			other := e.session("viewer-1")
			want(t, e.get(keyPath(other), other.token), 200)
		})
	}
}

func TestAutoRevokeOnRapidSessionCreationRevokesTheViewersSessions(t *testing.T) {
	e := newEnv(t)
	e.useSignals(func(s *db.PlaybackSettings) {
		s.MaxSessionsPerViewer = 0 // unlimited, so only the rate can trip
		s.AutoRevoke = []string{db.EventRapidSessionCreation}
	})
	bystander := e.session("viewer-2")
	var made []session
	for range 10 {
		s, err := e.create("scraper")
		if err != nil {
			t.Fatal(err)
		}
		made = append(made, s)
		e.clk.advance(5 * time.Second)
	}
	for _, s := range made {
		if st := e.state(s); st.State != db.PlaybackActive {
			t.Fatalf("revoked before the threshold: %+v", st)
		}
	}
	// The 11th creation crosses the line: every active session of the viewer is revoked,
	// including the one just created.
	last, err := e.create("scraper")
	if err != nil {
		t.Fatal(err)
	}
	made = append(made, last)
	for _, s := range made {
		st := e.state(s)
		if st.State != db.PlaybackRevoked || st.RevokeReason != "auto:rapid_session_creation" {
			t.Fatalf("session = %+v", st)
		}
		want(t, e.get(keyPath(s), s.token), 401)
	}
	if st := e.state(bystander); st.State != db.PlaybackActive {
		t.Fatalf("another viewer's session = %+v", st)
	}
	// The event is deduplicated, the revocation is not: a 12th session is revoked too.
	again, err := e.create("scraper")
	if err != nil {
		t.Fatal(err)
	}
	if st := e.state(again); st.State != db.PlaybackRevoked {
		t.Fatalf("a new session of the scraper = %+v", st)
	}
	if c := e.eventCounts(); c[db.EventRapidSessionCreation] != 1 {
		t.Fatalf("events = %v", c)
	}
	// One revoked row per revoked session in the trail (11 + 1), and an audit row per bulk revoke.
	e.closeAccess()
	if n := e.count("SELECT count(*) FROM playback_access_log WHERE event = 'revoked' AND viewer_id = 'scraper'"); n != 12 {
		t.Fatalf("revoked rows = %d, want 12", n)
	}
	if n := e.count("SELECT count(*) FROM audit_events WHERE action = $1", anomaly.AuditAutoRevokeBulk); n != 2 {
		t.Fatalf("audit rows = %d, want 2", n)
	}
}

// session_limit is information: it is never an auto-revoke kind and revokes nothing.
func TestSessionLimitNeverRevokes(t *testing.T) {
	e := newEnv(t)
	e.useSignals(allKinds)
	var kept []session
	for range 3 {
		kept = append(kept, e.session("viewer-1"))
	}
	if _, err := e.create("viewer-1"); err == nil {
		t.Fatal("the fourth session was created")
	}
	for _, s := range kept {
		if st := e.state(s); st.State != db.PlaybackActive {
			t.Fatalf("session = %+v", st)
		}
	}
	if c := e.eventCounts(); c[db.EventSessionLimit] != 1 || len(c) != 1 {
		t.Fatalf("events = %v", c)
	}
	// The settings refuse session_limit.
	bad := db.DefaultPlaybackSettings()
	bad.AutoRevoke = []string{db.EventSessionLimit}
	if f := playback.ValidateSettings(bad); len(f) != 1 || f[0].Field != "auto_revoke[0]" {
		t.Fatalf("validation = %+v", f)
	}
}

// One event per subject and kind per window, and per session for segments_without_key.
func TestAnomalyEventsAreDeduplicatedPerWindow(t *testing.T) {
	e := newEnv(t)
	e.useSignals(func(s *db.PlaybackSettings) {
		s.MaxSessionsPerViewer = 2
		s.IdleTimeoutSeconds, s.SessionMaxSeconds = 3600, 86400
	})
	a, b := e.session("viewer-1"), e.session("viewer-1")
	refuse := func() {
		t.Helper()
		for range 5 { // a refusal storm
			if _, err := e.create("viewer-1"); err == nil {
				t.Fatal("created past the limit")
			}
		}
	}
	refuse()
	if n := e.events(db.EventSessionLimit); n != 1 {
		t.Fatalf("session_limit events = %d after a storm", n)
	}
	e.clk.advance(9 * time.Minute)
	refuse()
	if n := e.events(db.EventSessionLimit); n != 1 {
		t.Fatalf("session_limit events = %d inside the window", n)
	}
	e.clk.advance(2 * time.Minute)
	refuse()
	if n := e.events(db.EventSessionLimit); n != 2 {
		t.Fatalf("session_limit events = %d after the window, want 2", n)
	}

	// segments_without_key is once per session however long it goes on. Tokens are minted by hand
	// because the clock moved past the sessions' own token.
	long := e.sign(a, token.ScopeSegment, time.Hour)
	for range 40 {
		e.segment(a, long, "240p/seg-0.m4s")
	}
	e.waitEvents(db.EventSegmentsWithoutKey, 1)
	e.clk.advance(30 * time.Minute)
	long = e.sign(a, token.ScopeSegment, time.Hour)
	for range 40 {
		e.segment(a, long, "240p/seg-0.m4s")
	}
	// The other session is its own subject.
	other := e.sign(b, token.ScopeSegment, time.Hour)
	for range 40 {
		e.segment(b, other, "240p/seg-0.m4s")
	}
	e.waitEvents(db.EventSegmentsWithoutKey, 2)
	e.closeAccess()
	if n := e.events(db.EventSegmentsWithoutKey); n != 2 {
		t.Fatalf("segments_without_key events = %d, want one per session", n)
	}
}

func TestZeroThresholdsDisableTheSignals(t *testing.T) {
	e := newEnv(t)
	e.useSignals(func(s *db.PlaybackSettings) {
		s.MaxSessionsPerViewer = 30
		s.AnomalySessionsPerViewer10m, s.AnomalySegmentsWithoutKey = 0, 0
		allKinds(s)
	})
	for range 20 {
		if _, err := e.create("scraper"); err != nil {
			t.Fatal(err)
		}
	}
	s := e.session("viewer-2")
	for range 80 {
		e.segment(s, s.token, "240p/seg-0.m4s")
	}
	e.closeAccess()
	if c := e.eventCounts(); len(c) != 0 {
		t.Fatalf("events = %v with both signals disabled", c)
	}
	if st := e.state(s); st.State != db.PlaybackActive {
		t.Fatalf("session = %+v", st)
	}
}

// failingPool fails what a test tells it to, to show that a database problem is never treated as
// abuse (I11).
type failingPool struct {
	anomaly.Pool
	begin, settings atomic.Bool
}

var errInjected = errors.New("injected database failure")

type errRow struct{}

func (errRow) Scan(...any) error { return errInjected }

func (f *failingPool) Begin(ctx context.Context) (pgx.Tx, error) {
	if f.begin.Load() {
		return nil, errInjected
	}
	return f.Pool.Begin(ctx)
}

func (f *failingPool) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if f.settings.Load() && strings.Contains(sql, "FROM playback_settings") {
		return errRow{}
	}
	return f.Pool.QueryRow(ctx, sql, args...)
}

func (f *failingPool) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return f.Pool.Exec(ctx, sql, args...)
}

func TestADatabaseErrorDuringDetectionNeverRevokes(t *testing.T) {
	e := newEnv(t)
	fp := &failingPool{}
	e.anomalyPool = func(p anomaly.Pool) anomaly.Pool { fp.Pool = p; return fp }
	e.useSignals(allKinds)

	t.Run("the event cannot be stored", func(t *testing.T) {
		fp.begin.Store(true)
		defer fp.begin.Store(false)
		s := e.session("viewer-1")
		for range 40 {
			e.get(keyPath(s), s.token)
		}
		if st := e.state(s); st.State != db.PlaybackActive || st.RevokeReason != "" {
			t.Fatalf("session = %+v: a database error revoked it", st)
		}
		if c := e.eventCounts(); len(c) != 0 {
			t.Fatalf("events = %v", c)
		}
		// The key endpoint still serves a token that has not used its bound.
		e.clk.advance(2 * time.Minute)
		fresh := e.beat(s, s.token)
		want(t, e.get(keyPath(s), fresh.Token), 200)
	})

	t.Run("the settings cannot be read", func(t *testing.T) {
		fp.settings.Store(true)
		defer fp.settings.Store(false)
		s := e.session("viewer-2")
		for range 40 {
			e.get(keyPath(s), s.token)
		}
		// The event is still recorded (the database works), but nothing is revoked.
		if n := e.events(db.EventKeyReplay); n != 1 {
			t.Fatalf("key_replay events = %d", n)
		}
		if st := e.state(s); st.State != db.PlaybackActive {
			t.Fatalf("session = %+v: unreadable settings revoked it", st)
		}
	})

	t.Run("the segment counters cannot be written", func(t *testing.T) {
		fp.begin.Store(true)
		defer fp.begin.Store(false)
		s := e.session("viewer-3")
		for range 50 {
			e.segment(s, s.token, "240p/seg-0.m4s")
		}
		time.Sleep(200 * time.Millisecond)
		if st := e.state(s); st.State != db.PlaybackActive {
			t.Fatalf("session = %+v", st)
		}
	})
}

// Events hold no capability: no session ID, token, hash or address.
func TestAnomalyEventsHoldNoCapabilities(t *testing.T) {
	e := newEnv(t)
	e.useSignals(nil)
	s := e.session("viewer-1")
	for range 40 {
		e.get(keyPath(s), s.token)
	}
	for range 40 {
		e.segment(s, s.token, "240p/seg-0.m4s")
	}
	e.closeAccess()
	var dump string
	if err := e.pool.QueryRow(context.Background(), "SELECT string_agg(row_to_json(l)::text, E'\\n') FROM playback_events l").Scan(&dump); err != nil || dump == "" {
		t.Fatalf("dump %q, %v", dump, err)
	}
	hash := db.SessionHash(mustSession(t, s.id))
	for name, secret := range map[string]string{
		"session ID": s.id, "session ID body": s.id[4:], "token": s.token, "token payload": strings.Split(s.token, ".")[1],
		"key": hex.EncodeToString(e.key),
	} {
		if strings.Contains(dump, secret) {
			t.Errorf("playback_events contains the %s: %s", name, dump)
		}
	}
	// The table does hold the session hash (like the sessions and the access log), and the logs
	// never do.
	if !strings.Contains(dump, `\\x`+hex.EncodeToString(hash)) {
		t.Fatalf("expected the stored hash in the raw dump, to prove the checks above can see bytea: %s", dump)
	}
	logs := e.logs.String()
	for name, secret := range map[string]string{"token": s.token, "session ID": s.id, "session hash": hex.EncodeToString(hash)} {
		if strings.Contains(logs, secret) {
			t.Errorf("the application log contains the %s", name)
		}
	}
}
