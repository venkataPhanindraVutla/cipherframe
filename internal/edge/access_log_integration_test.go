//go:build integration

package edge_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/accesslog"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth/viewerauthtest"
)

// useAccess switches the env to a recorder that writes to the test database. Segment counts are
// written when it is closed (trail closes it), everything else within a few milliseconds. Calling
// it again starts a fresh recorder (the previous one is closed first).
func (e *env) useAccess() {
	e.t.Helper()
	e.closeAccess()
	seg := e.segFlush
	if seg <= 0 {
		seg = time.Hour
	}
	e.access = accesslog.New(accesslog.Options{
		Store: e.repos, Log: e.log, Now: e.clk.Now, FlushInterval: 5 * time.Millisecond, SegmentFlushInterval: seg,
	})
	e.newDetector()
	svc, err := playback.NewService(playback.Deps{Pool: e.pool, Keyring: e.keyring, EdgeURL: "https://media.example.com", Access: e.access, Anomalies: e.anomalies, Now: e.clk.Now})
	if err != nil {
		e.t.Fatal(err)
	}
	e.svc = svc
	e.start()
	e.t.Cleanup(e.closeAccess)
}

func (e *env) closeAccess() {
	if e.access == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	e.access.Close(ctx)
}

// trail flushes the recorder and returns the session's rows in the order they happened.
func (e *env) trail(s session) []db.AccessLogEntry {
	e.t.Helper()
	e.closeAccess()
	sid, err := id.ParseSession(s.id)
	if err != nil {
		e.t.Fatal(err)
	}
	rows, next, err := e.repos.ListSessionAccessLog(context.Background(), e.res.Tenant.ID, db.SessionHash(sid), db.AccessLogQuery{Limit: db.MaxAccessLogPage})
	if err != nil || next != nil {
		e.t.Fatalf("read trail: %v (more pages: %v)", err, next != nil)
	}
	slices.Reverse(rows)
	return rows
}

func kindsOf(rows []db.AccessLogEntry) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Event
	}
	return out
}

func sameKinds(t *testing.T, rows []db.AccessLogEntry, want ...string) {
	t.Helper()
	got := kindsOf(rows)
	if !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

// rowsOf returns every row of the tenant, any session, oldest first.
func (e *env) allRows() []db.AccessLogEntry {
	e.t.Helper()
	e.closeAccess()
	rows, _, err := e.repos.ListAssetAccessLog(context.Background(), e.res.Tenant.ID, e.asset.ID, db.AccessLogQuery{Limit: db.MaxAccessLogPage})
	if err != nil {
		e.t.Fatal(err)
	}
	slices.Reverse(rows)
	return rows
}

func TestAccessTrailFollowsAFullPlayback(t *testing.T) {
	e := newEnv(t)
	e.useAccess()
	s := e.session("viewer-1")
	master := "/v1/play/" + s.id + "/master.m3u8"
	want(t, e.get(master, s.token), 200)
	want(t, e.get("/v1/play/"+s.id+"/240p/media.m3u8", s.token), 200) // media playlists are not logged
	want(t, e.get("/v1/play/"+s.id+"/720p/media.m3u8", s.token), 200)
	want(t, e.get(keyPath(s), s.token), 200)

	// Six heartbeats a minute apart: the first and the one 5 minutes later are logged.
	tok := s.token
	for range 6 {
		e.clk.advance(60 * time.Second)
		tok = e.beat(s, tok).Token
	}
	// Four segment requests that succeed (an init and three media segments) are counted; one that
	// the store does not have, and one with a bad name, are not.
	for _, f := range []string{"240p/init.mp4", "240p/seg-0.m4s", "240p/seg-1.m4s", "720p/seg-0.m4s"} {
		want(t, e.get("/v1/play/"+s.id+"/"+f, tok), 200)
	}
	want(t, e.get("/v1/play/"+s.id+"/240p/seg-99.m4s", tok), 404)
	want(t, e.get("/v1/play/"+s.id+"/240p/seg-x.m4s", tok), 404)
	want(t, e.post(endPath(s), tok), 204)
	want(t, e.post(endPath(s), tok), 204) // repeating an end changes nothing and logs nothing

	rows := e.trail(s)
	var segs []db.AccessLogEntry
	var rest []db.AccessLogEntry
	for _, r := range rows {
		if r.Event == db.AccessSegments {
			segs = append(segs, r)
		} else {
			rest = append(rest, r)
		}
	}
	sameKinds(t, rest, db.AccessSessionCreated, db.AccessPlaylist, db.AccessKey, db.AccessHeartbeat, db.AccessHeartbeat, db.AccessEnd)
	if len(segs) != 1 || segs[0].SegmentsServed != 4 {
		t.Fatalf("segment rows = %+v, want one row counting 4", segs)
	}
	fp := rows[0].SessionFingerprint
	for _, r := range rows {
		if r.ViewerID != "viewer-1" || r.AuthMethod != db.AuthMethodAPIKey || r.AssetID != e.asset.ID || r.SessionFingerprint != fp || len(fp) != 8 {
			t.Fatalf("row = %+v", r)
		}
		if r.IP != "" || r.UserAgent != "" {
			t.Fatalf("row stores the viewer's connection although the tenant never allowed it: %+v", r)
		}
		if r.Event != db.AccessSegments && r.Event != db.AccessSessionCreated && r.RequestID == "" {
			t.Fatalf("an edge row has no request ID: %+v", r)
		}
	}
	// The two heartbeats are 5 minutes apart.
	if d := rest[4].At.Sub(rest[3].At); d < 5*time.Minute {
		t.Fatalf("logged heartbeats are %v apart", d)
	}
	if st := e.access.Stats(); st.Dropped != 0 || st.Throttled != 4 {
		t.Fatalf("stats = %+v, want nothing dropped and 4 heartbeats throttled", st)
	}
}

// Nothing in the table can say what was watched, and no capability ever reaches it or the logs.
func TestAccessTrailHoldsNoCapabilitiesAndNoSegmentDetail(t *testing.T) {
	e := newEnv(t)
	e.useAccess()
	s := e.session("viewer-1")
	for _, p := range []string{"master.m3u8", "240p/media.m3u8", "240p/init.mp4", "240p/seg-0.m4s", "720p/seg-2.m4s"} {
		want(t, e.get("/v1/play/"+s.id+"/"+p, s.token), 200)
	}
	want(t, e.get(keyPath(s), s.token), 200)
	e.trail(s)

	var dump string
	if err := e.pool.QueryRow(context.Background(), "SELECT string_agg(row_to_json(l)::text, E'\\n') FROM playback_access_log l").Scan(&dump); err != nil {
		t.Fatal(err)
	}
	hash := db.SessionHash(mustSession(t, s.id))
	for name, secret := range map[string]string{
		"session ID": s.id, "session ID body": s.id[4:], "token": s.token, "token payload": strings.Split(s.token, ".")[1],
		"init segment": "init", "segment name": "seg-", "rendition 240p": "240p",
		"rendition 720p": "720p", "playlist name": "m3u8", "key": hex.EncodeToString(e.key),
		"key base64": base64.StdEncoding.EncodeToString(e.key),
	} {
		if strings.Contains(dump, secret) {
			t.Errorf("the access log table contains the %s: %s", name, dump)
		}
	}
	// \x is how row_to_json writes bytea: the session hash is stored, but only as the hash.
	if !strings.Contains(dump, `\\x`+hex.EncodeToString(hash)) {
		t.Fatalf("expected the stored hash to be present in the raw dump, to prove the check above can see bytea: %s", dump)
	}
	logs := e.logs.String()
	for name, secret := range map[string]string{"token": s.token, "session ID": s.id, "session hash": hex.EncodeToString(hash)} {
		if strings.Contains(logs, secret) {
			t.Errorf("the application log contains the %s", name)
		}
	}
}

func TestAccessTrailPrivacySettingsDecideWhatIsStored(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.enableJWT("")
	k := viewerauthtest.NewKey(t, "EdDSA", "key-1")
	e.uploadKey(k)

	// Defaults: nothing about the connection is stored, even for requests that carry it.
	e.useAccess()
	s := e.session("viewer-1")
	want(t, e.do("GET", "/v1/play/"+s.id+"/master.m3u8", map[string]string{"Authorization": "Bearer " + s.token, "User-Agent": "TestPlayer/1.0"}), 200)
	for _, r := range e.trail(s) {
		if r.IP != "" || r.UserAgent != "" {
			t.Fatalf("defaults stored %+v", r)
		}
	}

	// IP and user agent on: stored for the viewer's own requests, never for the API-key creation.
	actor := auth.Actor{ClientID: e.res.Client.ID}
	if _, err := e.svc.PutPrivacy(ctx, e.res.Tenant.ID, actor, db.PrivacySettings{StoreIP: true, StoreUserAgent: true}); err != nil {
		t.Fatal(err)
	}
	e.clk.advance(playbackCacheTTL)
	e.useAccess()
	api := e.session("viewer-2")
	want(t, e.do("GET", "/v1/play/"+api.id+"/master.m3u8", map[string]string{"Authorization": "Bearer " + api.token, "User-Agent": "TestPlayer/1.0" + strings.Repeat("x", 400)}), 200)
	rows := e.trail(api)
	sameKinds(t, rows, db.AccessSessionCreated, db.AccessPlaylist)
	if rows[0].IP != "" || rows[0].UserAgent != "" {
		t.Fatalf("an API-key creation stored the embedding server's connection: %+v", rows[0])
	}
	if rows[1].IP != "127.0.0.1" || !strings.HasPrefix(rows[1].UserAgent, "TestPlayer/1.0x") || len([]rune(rows[1].UserAgent)) != 256 {
		t.Fatalf("playlist row = %+v", rows[1])
	}

	// A browser-started session stores the viewer's connection on creation, and a refused one too.
	e.useAccess()
	e.clk.advance(playbackCacheTTL)
	ok := e.wantCreated(e.postJSON(e.sessionsPath(), map[string]any{"asset_id": e.asset.ID.String(), "method": "jwt"},
		map[string]string{"Authorization": "Bearer " + k.Sign(t, e.claims("viewer-3")), "User-Agent": "Browser/9"}))
	denied := e.postJSON(e.sessionsPath(), map[string]any{"asset_id": e.asset.ID.String(), "method": "jwt"},
		map[string]string{"Authorization": "Bearer garbage", "User-Agent": "Attacker/1"})
	want(t, denied, 401)
	jwtRows := e.trail(ok)
	sameKinds(t, jwtRows, db.AccessSessionCreated)
	if r := jwtRows[0]; r.IP != "127.0.0.1" || r.UserAgent != "Browser/9" || r.AuthMethod != db.AuthMethodJWT || r.ViewerID != "viewer-3" {
		t.Fatalf("jwt creation row = %+v", r)
	}
	var denials []db.AccessLogEntry
	for _, r := range e.allRows() {
		if r.Event == db.AccessSessionDenied {
			denials = append(denials, r)
		}
	}
	if len(denials) != 1 || denials[0].ViewerID != "" || denials[0].SessionFingerprint != "" || denials[0].AuthMethod != db.AuthMethodJWT ||
		denials[0].IP != "127.0.0.1" || denials[0].UserAgent != "Attacker/1" || denials[0].AssetID != e.asset.ID {
		t.Fatalf("denied rows = %+v", denials)
	}

	// Switching one off applies to rows written afterwards; the other stays.
	if _, err := e.svc.PutPrivacy(ctx, e.res.Tenant.ID, actor, db.PrivacySettings{StoreIP: false, StoreUserAgent: true}); err != nil {
		t.Fatal(err)
	}
	e.clk.advance(playbackCacheTTL)
	e.useAccess()
	again := e.session("viewer-4")
	want(t, e.do("GET", "/v1/play/"+again.id+"/master.m3u8", map[string]string{"Authorization": "Bearer " + again.token, "User-Agent": "Only/UA"}), 200)
	rows = e.trail(again)
	if rows[1].IP != "" || rows[1].UserAgent != "Only/UA" {
		t.Fatalf("playlist row = %+v", rows[1])
	}
	// The change is in the audit log.
	var n int
	if err := e.pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = $2", e.res.Tenant.ID.UUID(), playback.AuditPrivacyUpdate).Scan(&n); err != nil || n != 2 {
		t.Fatalf("audit events = %d, %v", n, err)
	}
}

func TestAccessTrailRevokeAndExpiry(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) { s.MaxSessionsPerViewer = 0 })
	e.useAccess()
	ctx := context.Background()
	single := e.session("viewer-1")
	b1, b2 := e.session("viewer-2"), e.session("viewer-2")
	idle := e.session("viewer-3")

	e.revokeVia(single, "chargeback")
	e.revokeVia(single, "again") // already revoked: changes nothing, logs nothing
	n, err := e.svc.RevokeSessions(ctx, e.res.Tenant.ID, auth.Actor{ClientID: e.res.Client.ID}, "viewer-2", id.AssetID{}, "bulk")
	if err != nil || n != 2 {
		t.Fatalf("bulk revoke = %d, %v", n, err)
	}
	if n, err := e.svc.RevokeSessions(ctx, e.res.Tenant.ID, auth.Actor{ClientID: e.res.Client.ID}, "viewer-2", id.AssetID{}, "bulk"); err != nil || n != 0 {
		t.Fatalf("repeated bulk revoke = %d, %v", n, err)
	}

	// The sweep ends the idle session and writes its row; a second sweep finds nothing.
	e.clk.advance(time.Hour)
	if n, err := playback.SweepSessions(ctx, e.repos, e.clk.Now(), playback.SweepBatch); err != nil || n != 1 {
		t.Fatalf("sweep = %d, %v", n, err)
	}
	if n, err := playback.SweepSessions(ctx, e.repos, e.clk.Now(), playback.SweepBatch); err != nil || n != 0 {
		t.Fatalf("second sweep = %d, %v", n, err)
	}

	sameKinds(t, e.trail(single), db.AccessSessionCreated, db.AccessRevoked)
	for _, s := range []session{b1, b2} {
		rows := e.trail(s)
		sameKinds(t, rows, db.AccessSessionCreated, db.AccessRevoked)
		if rows[1].ViewerID != "viewer-2" || rows[1].AuthMethod != db.AuthMethodAPIKey || rows[1].IP != "" {
			t.Fatalf("revoked row = %+v", rows[1])
		}
	}
	rows := e.trail(idle)
	sameKinds(t, rows, db.AccessSessionCreated, db.AccessExpired)
	if rows[1].ViewerID != "viewer-3" || rows[1].AuthMethod != db.AuthMethodAPIKey || rows[1].RequestID != "" || rows[1].IP != "" {
		t.Fatalf("expired row = %+v", rows[1])
	}
	// The asset's trail holds all of it, newest first.
	if got := len(e.allRows()); got != 4+3+1 {
		t.Fatalf("asset trail has %d rows, want 8", got)
	}
}

func TestAccessTrailRecordsDeniedCreation(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) { s.MaxSessionsPerViewer = 1 })
	e.useAccess()
	ctx := context.Background()
	first := e.session("viewer-1")
	_, err := e.svc.CreateSession(ctx, playback.CreateInput{TenantID: e.res.Tenant.ID, ClientID: e.res.Client.ID, AssetID: e.asset.ID, ViewerID: "viewer-1"})
	if err == nil {
		t.Fatal("the second session was created")
	}
	pending := readyAssetIn(t, e, db.AssetCommitted)
	if _, err := e.svc.CreateSession(ctx, playback.CreateInput{TenantID: e.res.Tenant.ID, ClientID: e.res.Client.ID, AssetID: pending.ID, ViewerID: "viewer-9"}); err == nil {
		t.Fatal("a session was created on an asset that is not ready")
	}
	// An asset that does not exist is not an access of anything and logs nothing.
	if _, err := e.svc.CreateSession(ctx, playback.CreateInput{TenantID: e.res.Tenant.ID, ClientID: e.res.Client.ID, AssetID: id.New[id.AssetKind](), ViewerID: "viewer-9"}); err == nil {
		t.Fatal("a session was created on an unknown asset")
	}
	_ = first
	e.closeAccess()
	var limit, notReady int
	rows, _, err := e.repos.ListAssetAccessLog(ctx, e.res.Tenant.ID, e.asset.ID, db.AccessLogQuery{Limit: 50, Event: db.AccessSessionDenied})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.ViewerID != "viewer-1" || r.AuthMethod != db.AuthMethodAPIKey || r.SessionFingerprint != "" {
			t.Fatalf("limit row = %+v", r)
		}
		limit++
	}
	rows, _, err = e.repos.ListAssetAccessLog(ctx, e.res.Tenant.ID, pending.ID, db.AccessLogQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Event != db.AccessSessionDenied || r.ViewerID != "viewer-9" {
			t.Fatalf("not-ready row = %+v", r)
		}
		notReady++
	}
	if limit != 1 || notReady != 1 {
		t.Fatalf("denied rows: limit %d, not ready %d", limit, notReady)
	}
}

func readyAssetIn(t *testing.T, e *env, state db.AssetState) db.Asset {
	t.Helper()
	a, err := e.repos.CreateUploadAsset(context.Background(), db.NewUploadAsset{
		ID: id.New[id.AssetKind](), TenantID: e.res.Tenant.ID, ClientID: e.res.Client.ID, SizeBytes: 1000,
		Method: db.UploadTus, SourceKey: "test-fixture-source-" + id.New[id.AssetKind]().String(), ExpiresAt: time.Now().Add(time.Hour).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, next := range []db.AssetState{db.AssetUploading, db.AssetCommitted, db.AssetProcessing, db.AssetReady} {
		if a.State == state {
			break
		}
		if a, err = e.repos.TransitionAsset(context.Background(), e.res.Tenant.ID, a.ID, db.Transition{From: a.State, To: next}); err != nil {
			t.Fatal(err)
		}
	}
	return a
}

func TestAccessTrailKeyDeniedIsLoggedForKnownSessionsOnly(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) { s.KeyFetchesPerToken = 1 })
	e.useAccess()
	s := e.session("viewer-1")
	want(t, e.get(keyPath(s), s.token), 200)
	for range 3 { // over the per-token bound: 429, and one row per minute
		want(t, e.get(keyPath(s), s.token), 429)
	}
	// A garbage token is not a session: nothing is logged for it.
	want(t, e.get(keyPath(s), "garbage"), 401)
	unknown, err := id.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	want(t, e.get("/v1/play/"+unknown.String()+"/key", s.token), 401)

	// Revoked: a valid token for a session that exists is refused with the generic 401, and logged.
	fresh := e.sign(s, token.ScopeKey, 5*time.Minute)
	e.revokeVia(s, "stop")
	for range 3 {
		want(t, e.get(keyPath(s), fresh), 401)
	}
	rows := e.trail(s)
	// Within a minute the later refusals of the same session are not logged again.
	sameKinds(t, rows, db.AccessSessionCreated, db.AccessKey, db.AccessKeyDenied, db.AccessRevoked)
	// A later refusal is logged (here with a fresh recorder: the throttle is per recorder).
	e.useAccess()
	e.clk.advance(2 * time.Minute)
	want(t, e.get(keyPath(s), fresh), 401)
	if got := kindsOf(e.trail(s)); got[len(got)-1] != db.AccessKeyDenied || len(got) != 5 {
		t.Fatalf("events = %v", got)
	}
	// Everything stored is a row of this tenant and session: the garbage requests left nothing.
	if n := len(e.allRows()); n != 5 {
		t.Fatalf("%d rows for the asset, want 5", n)
	}
}

// A database outage or a full queue never fails or slows playback.
func TestAccessTrailOutageDoesNotAffectPlayback(t *testing.T) {
	e := newEnv(t)
	e.useAccess()
	s := e.session("viewer-1")
	if _, err := e.pool.Exec(context.Background(), "ALTER TABLE playback_access_log RENAME TO playback_access_log_away"); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		want(t, e.get("/v1/play/"+s.id+"/master.m3u8", s.token), 200)
	}
	want(t, e.get(keyPath(s), s.token), 200)
	want(t, e.post(endPath(s), s.token), 204)
	// The failed writes are logged and, after the attempts, dropped; nothing else happened.
	deadline := time.Now().Add(10 * time.Second)
	for e.access.Stats().Dropped == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if e.access.Stats().Dropped == 0 {
		t.Fatalf("stats = %+v, want dropped events", e.access.Stats())
	}
	if _, err := e.pool.Exec(context.Background(), "ALTER TABLE playback_access_log_away RENAME TO playback_access_log"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.logs.String(), "access log") {
		t.Fatal("the failure was not logged")
	}
}
