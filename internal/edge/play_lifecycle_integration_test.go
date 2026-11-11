//go:build integration

package edge_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
)

func acao(r reply) string { return r.hdr.Get("Access-Control-Allow-Origin") }

func hbPath(s session) string  { return "/v1/play/" + s.id + "/heartbeat" }
func endPath(s session) string { return "/v1/play/" + s.id + "/end" }

func (e *env) post(path, tok string) reply { return e.do("POST", path, bearer(tok)) }

type heartbeat struct {
	Token                    string    `json:"token"`
	TokenExpiresAt           time.Time `json:"token_expires_at"`
	HeartbeatIntervalSeconds int       `json:"heartbeat_interval_seconds"`
	SessionExpiresAt         time.Time `json:"session_expires_at"`
}

// beat sends a heartbeat that must succeed and returns the response.
func (e *env) beat(s session, tok string) heartbeat {
	e.t.Helper()
	r := e.post(hbPath(s), tok)
	want(e.t, r, 200)
	var hb heartbeat
	if err := json.Unmarshal(r.body, &hb); err != nil {
		e.t.Fatalf("%v: %s", err, r.body)
	}
	return hb
}

func (e *env) row(s session) db.PlaybackSession {
	e.t.Helper()
	sid, err := id.ParseSession(s.id)
	if err != nil {
		e.t.Fatal(err)
	}
	row, err := e.repos.GetPlaybackSession(context.Background(), e.res.Tenant.ID, db.SessionHash(sid))
	if err != nil {
		e.t.Fatal(err)
	}
	return row
}

// revokeVia revokes through the service, as the api does.
func (e *env) revokeVia(s session, reason string) playback.SessionStatus {
	e.t.Helper()
	sid, err := id.ParseSession(s.id)
	if err != nil {
		e.t.Fatal(err)
	}
	st, err := e.svc.RevokeSession(context.Background(), e.res.Tenant.ID, auth.Actor{ClientID: e.res.Client.ID}, sid, reason)
	if err != nil {
		e.t.Fatal(err)
	}
	return st
}

func TestHeartbeatReturnsAFreshTokenAndExtendsTheSession(t *testing.T) {
	e := newEnv(t)
	s := e.session("viewer-1")
	e.clk.advance(60 * time.Second)

	before := e.clk.Now()
	r := e.post(hbPath(s), s.token)
	want(t, r, 200)
	for name, v := range map[string]string{"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "Content-Type": "application/json"} {
		if got := r.hdr.Get(name); got != v {
			t.Errorf("%s = %q, want %q", name, got, v)
		}
	}
	var hb heartbeat
	if err := json.Unmarshal(r.body, &hb); err != nil {
		t.Fatal(err)
	}
	if hb.Token == "" || hb.Token == s.token || hb.HeartbeatIntervalSeconds != 60 {
		t.Fatalf("response = %s", r.body)
	}
	row := e.row(s)
	if !hb.SessionExpiresAt.Equal(row.ExpiresAt) {
		t.Fatalf("session_expires_at = %v, row %v", hb.SessionExpiresAt, row.ExpiresAt)
	}
	if row.LastHeartbeatAt.Before(before.Add(-time.Second)) || row.LastHeartbeatAt.After(e.clk.Now().Add(time.Second)) {
		t.Fatalf("last_heartbeat_at = %v, clock %v", row.LastHeartbeatAt, e.clk.Now())
	}

	// The new token verifies for all three scopes, for this session and tenant, and expires one
	// token lifetime from now.
	for _, sc := range []token.Scope{token.ScopeManifest, token.ScopeKey, token.ScopeSegment} {
		c, err := e.keyring.Open(hb.Token, e.clk.Now(), sc)
		if err != nil {
			t.Fatalf("new token, scope %s: %v", sc, err)
		}
		if c.SessionID != s.id || c.AssetID != e.asset.ID.String() || c.TenantID != e.res.Tenant.ID.String() {
			t.Fatalf("claims = %+v", c)
		}
	}
	if d := hb.TokenExpiresAt.Sub(e.clk.Now()); d < 9*time.Minute || d > 10*time.Minute+time.Second {
		t.Fatalf("token lifetime = %v", d)
	}

	// Both tokens work now: the old one until its own expiry (documented), the new one from here on.
	master := "/v1/play/" + s.id + "/master.m3u8"
	want(t, e.get(master, s.token), 200)
	want(t, e.get(master, hb.Token), 200)
	want(t, e.get(keyPath(s), hb.Token), 200)

	// The heartbeat reset the idle clock: 250 s later the session is alive, although 310 s have
	// passed since creation, and without another heartbeat it dies 300 s after this one.
	e.clk.advance(250 * time.Second)
	want(t, e.get(master, hb.Token), 200)
	e.clk.advance(60 * time.Second)
	want(t, e.get(master, hb.Token), 401)
}

func TestHeartbeatTokenIsCappedAtTheSessionExpiry(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) { s.TokenTTLSeconds, s.SessionMaxSeconds = 600, 300 })
	s := e.session("viewer-1")
	e.clk.advance(100 * time.Second)

	hb := e.beat(s, s.token)
	if hb.TokenExpiresAt.After(hb.SessionExpiresAt) || hb.TokenExpiresAt.Before(hb.SessionExpiresAt.Add(-time.Second)) {
		t.Fatalf("token expires %v, session %v", hb.TokenExpiresAt, hb.SessionExpiresAt)
	}
	c, err := e.keyring.Open(hb.Token, e.clk.Now(), token.ScopeKey)
	if err != nil {
		t.Fatal(err)
	}
	if c.Expiry.After(hb.SessionExpiresAt) {
		t.Fatalf("token claim expiry %v is after the session expiry %v", c.Expiry, hb.SessionExpiresAt)
	}
}

func TestHeartbeatAfterIdleIs401(t *testing.T) {
	e := newEnv(t)
	s := e.session("viewer-1")
	e.clk.advance(301 * time.Second) // idle timeout 300 s; the token (600 s) is still valid
	if _, err := e.keyring.Open(s.token, e.clk.Now(), token.ScopeManifest); err != nil {
		t.Fatalf("the test needs a token that still verifies: %v", err)
	}
	r := e.post(hbPath(s), s.token)
	want(t, r, 401)
	if r.hdr.Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("headers = %v", r.hdr)
	}
	if !e.row(s).LastHeartbeatAt.Before(e.clk.Now().Add(-300 * time.Second)) {
		t.Fatal("an idle session's heartbeat was recorded")
	}
	// The same answer as for a bad token: nothing says why.
	bad := e.post(hbPath(s), "v1.x.1.y")
	want(t, bad, 401)
	if string(bad.body) == "" || strings.Contains(string(r.body), "idle") {
		t.Fatalf("body = %s", r.body)
	}
}

func TestHeartbeatAfterRevokeIs401AndRevocationIsImmediate(t *testing.T) {
	e := newEnv(t)
	s := e.session("viewer-1")
	media := "/v1/play/" + s.id + "/240p/media.m3u8"
	seg := "/v1/play/" + s.id + "/240p/init.mp4"
	want(t, e.get(keyPath(s), s.token), 200)
	want(t, e.get(media, s.token), 200)
	e.clk.advance(60 * time.Second)
	fresh := e.beat(s, s.token)

	st := e.revokeVia(s, "chargeback")
	if st.State != db.PlaybackRevoked || st.RevokeReason != "chargeback" || st.RevokedAt == nil {
		t.Fatalf("status = %+v", st)
	}
	// The tokens still verify; the session behind them does not.
	for _, tok := range []string{s.token, fresh.Token} {
		if _, err := e.keyring.Open(tok, e.clk.Now(), token.ScopeKey); err != nil {
			t.Fatalf("the token stopped verifying: %v", err)
		}
		want(t, e.get(keyPath(s), tok), 401)
		want(t, e.get("/v1/play/"+s.id+"/master.m3u8", tok), 401)
		want(t, e.get(media, tok), 401)
		want(t, e.post(hbPath(s), tok), 401)
	}
	// Documented: segments keep serving until the token expires (they cannot be decrypted
	// without the key).
	want(t, e.get(seg, fresh.Token), 200)
	e.clk.advance(11 * time.Minute)
	want(t, e.get(seg, fresh.Token), 401)

	// Revoking again changes nothing; the session stays revoked, also after an end.
	again := e.revokeVia(s, "second")
	if again.State != db.PlaybackRevoked || again.RevokeReason != "chargeback" {
		t.Fatalf("second revoke = %+v", again)
	}
	if e.row(s).State != db.PlaybackRevoked {
		t.Fatalf("row = %+v", e.row(s))
	}
}

func TestHeartbeatTooFrequentIs429(t *testing.T) {
	e := newEnv(t)
	s := e.session("viewer-1")

	// Right after creation: the creation counts as the previous heartbeat. The gap is a quarter of
	// the 60 s interval, 15 s.
	r := e.post(hbPath(s), s.token)
	want(t, r, 429)
	if n := retryAfter(t, r); n < 1 || n > 15 {
		t.Fatalf("Retry-After = %d", n)
	}
	var p map[string]any
	if err := json.Unmarshal(r.body, &p); err != nil {
		t.Fatal(err)
	}
	if p["code"] != "rate_limited" || p["retryable"] != true {
		t.Fatalf("problem = %s", r.body)
	}
	if strings.Contains(string(r.body), "token") && p["token"] != nil {
		t.Fatalf("a rejected heartbeat returned a token: %s", r.body)
	}
	created := e.row(s).LastHeartbeatAt
	e.clk.advance(10 * time.Second)
	want(t, e.post(hbPath(s), s.token), 429)
	if !e.row(s).LastHeartbeatAt.Equal(created) {
		t.Fatal("a rejected heartbeat was recorded")
	}

	e.clk.advance(6 * time.Second) // 16 s since creation
	hb := e.beat(s, s.token)
	// A script that loops gets one token per gap, not one per request.
	for range 3 {
		r := e.post(hbPath(s), hb.Token)
		want(t, r, 429)
		if n := retryAfter(t, r); n < 14 || n > 15 {
			t.Fatalf("Retry-After = %d", n)
		}
	}
	e.clk.advance(15 * time.Second)
	e.beat(s, hb.Token)
}

// The gap has a floor of 5 seconds for short intervals.
func TestHeartbeatGapFloor(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) { s.HeartbeatIntervalSeconds = 10 }) // a quarter is 2.5 s
	s := e.session("viewer-1")
	e.clk.advance(3 * time.Second)
	want(t, e.post(hbPath(s), s.token), 429)
	e.clk.advance(3 * time.Second)
	want(t, e.post(hbPath(s), s.token), 200)
}

// A session kept alive by heartbeats outlives the idle timeout and the lifetime of every token it
// was given, until its maximum age; then heartbeat, key and playlists answer 401.
func TestSessionLifecycleThroughHeartbeats(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) {
		s.HeartbeatIntervalSeconds, s.IdleTimeoutSeconds, s.TokenTTLSeconds, s.SessionMaxSeconds = 30, 90, 120, 600
	})
	s := e.session("viewer-1")
	row := e.row(s)
	master := "/v1/play/" + s.id + "/master.m3u8"

	tok, beats := s.token, 0
	for e.clk.Now().Add(31 * time.Second).Before(row.ExpiresAt) {
		e.clk.advance(30 * time.Second)
		hb := e.beat(s, tok)
		tok = hb.Token
		beats++
		want(t, e.get(master, tok), 200)
		if hb.TokenExpiresAt.After(hb.SessionExpiresAt) {
			t.Fatalf("token expires after the session")
		}
	}
	if beats < 10 {
		t.Fatalf("only %d heartbeats", beats)
	}
	if elapsed := e.clk.Now().Sub(row.CreatedAt); elapsed < 5*time.Minute {
		t.Fatalf("elapsed = %v: the test did not outlive the idle timeout", elapsed)
	}
	want(t, e.get(keyPath(s), tok), 200)
	// The first token, long past its own 120 s, is dead; the session is not.
	want(t, e.get(master, s.token), 401)

	// Past the maximum age: even a token that would still verify gets nothing.
	e.clk.advance(row.ExpiresAt.Sub(e.clk.Now()) + time.Second)
	long := e.sign(s, token.ScopeManifest|token.ScopeKey|token.ScopeSegment, time.Hour)
	want(t, e.post(hbPath(s), long), 401)
	want(t, e.get(keyPath(s), long), 401)
	want(t, e.get(master, long), 401)
	st, err := e.svc.GetSession(context.Background(), e.res.Tenant.ID, mustSession(t, s.id))
	if err != nil || st.State != db.PlaybackEnded {
		t.Fatalf("status = %+v, %v", st, err)
	}
}

func mustSession(t *testing.T, raw string) id.SessionID {
	t.Helper()
	sid, err := id.ParseSession(raw)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

func TestEndFreesAConcurrencySlotAndIsIdempotent(t *testing.T) {
	e := newEnv(t)
	create := func() (session, error) {
		c, err := e.svc.CreateSession(context.Background(), playback.CreateInput{
			TenantID: e.res.Tenant.ID, ClientID: e.res.Client.ID, AssetID: e.asset.ID, ViewerID: "viewer-1",
		})
		return session{id: c.SessionID.String(), token: c.Token.Reveal()}, err
	}
	var ss []session
	for range 3 {
		s, err := create()
		if err != nil {
			t.Fatal(err)
		}
		ss = append(ss, s)
	}
	_, err := create()
	var ae *errs.Error
	if !errors.As(err, &ae) || ae.Code != errs.SessionLimit {
		t.Fatalf("a 4th session: %v, want session_limit", err)
	}

	r := e.post(endPath(ss[0]), ss[0].token)
	want(t, r, 204)
	if len(r.body) != 0 || r.hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("reply = %+v", r)
	}
	row := e.row(ss[0])
	if row.State != db.PlaybackEnded || row.EndedAt == nil {
		t.Fatalf("row = %+v", row)
	}
	if _, err := create(); err != nil {
		t.Fatalf("the slot was not freed: %v", err)
	}

	// An ended session serves nothing and takes no heartbeat; ending it again is a 204 that
	// changes nothing.
	want(t, e.get(keyPath(ss[0]), ss[0].token), 401)
	want(t, e.get("/v1/play/"+ss[0].id+"/master.m3u8", ss[0].token), 401)
	want(t, e.post(hbPath(ss[0]), ss[0].token), 401)
	endedAt := *row.EndedAt
	e.clk.advance(time.Minute)
	want(t, e.post(endPath(ss[0]), ss[0].token), 204)
	if again := e.row(ss[0]); again.State != db.PlaybackEnded || !again.EndedAt.Equal(endedAt) {
		t.Fatalf("row after a second end = %+v", again)
	}

	// A revoked session stays revoked.
	e.revokeVia(ss[1], "abuse")
	want(t, e.post(endPath(ss[1]), ss[1].token), 204)
	if got := e.row(ss[1]); got.State != db.PlaybackRevoked || got.RevokeReason != "abuse" {
		t.Fatalf("row = %+v", got)
	}

	// An idle session can still be ended, so a late unload does not turn into an error.
	e.clk.advance(400 * time.Second)
	want(t, e.post(endPath(ss[2]), ss[2].token), 204)
	if got := e.row(ss[2]); got.State != db.PlaybackEnded {
		t.Fatalf("row = %+v", got)
	}

	// Token failures are the generic 401, and one session's token ends no other session.
	want(t, e.post(endPath(ss[2]), "v1.x.1.y"), 401)
	want(t, e.do("POST", endPath(ss[2]), nil), 401)
	other := e.session("viewer-2")
	want(t, e.post(endPath(other), ss[2].token), 401)
	want(t, e.post(endPath(session{id: "ses_nope"}), other.token), 404)
	if e.row(other).State != db.PlaybackActive {
		t.Fatal("a rejected end ended the session")
	}
	// The key scope alone is not enough: end needs the manifest scope.
	want(t, e.post(endPath(other), e.sign(other, token.ScopeKey, time.Minute)), 401)
}

func TestLifecycleRoutesCORSAndTokenTransport(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) { s.AllowedOrigins = []string{testOrigin} })
	s := e.session("viewer-1")
	e.clk.advance(20 * time.Second)

	for _, path := range []string{hbPath(s), endPath(s)} {
		pf := e.do("OPTIONS", path, map[string]string{"Origin": testOrigin, "Access-Control-Request-Method": "POST"})
		want(t, pf, 204)
		if acao(pf) != testOrigin || !strings.Contains(pf.hdr.Get("Access-Control-Allow-Methods"), "POST") ||
			pf.hdr.Get("Access-Control-Allow-Headers") != "Authorization" {
			t.Fatalf("%s preflight headers = %v", path, pf.hdr)
		}
		bad := e.do("OPTIONS", path, map[string]string{"Origin": "https://evil.example"})
		want(t, bad, 204)
		if acao(bad) != "" {
			t.Fatalf("%s: preflight for a foreign origin got CORS headers", path)
		}
	}
	h := bearer(s.token)
	h["Origin"] = testOrigin
	r := e.do("POST", hbPath(s), h)
	want(t, r, 200)
	if acao(r) != testOrigin {
		t.Fatalf("heartbeat headers = %v", r.hdr)
	}
	// A failure is readable by the player too.
	h = bearer("v1.x.1.y")
	h["Origin"] = testOrigin
	r = e.do("POST", hbPath(s), h)
	want(t, r, 401)
	if acao(r) != testOrigin {
		t.Fatalf("401 headers = %v", r.hdr)
	}

	// The token in the URL: refused while the tenant has it off, accepted once on; both forms
	// together are a 400.
	want(t, e.do("POST", hbPath(s)+"?t="+url.QueryEscape(s.token), nil), 401)
	e.settings(func(s *db.PlaybackSettings) { s.TokenInURL = true })
	hb := e.do("POST", hbPath(s)+"?t="+url.QueryEscape(s.token), nil)
	want(t, hb, 200)
	want(t, e.do("POST", hbPath(s)+"?t="+url.QueryEscape(s.token), bearer(s.token)), 400)
	e.clk.advance(20 * time.Second)
	want(t, e.do("POST", endPath(s)+"?t="+url.QueryEscape(s.token), nil), 204)

	// Methods: the routes take POST only.
	want(t, e.get(hbPath(s), s.token), 405)
	want(t, e.get(endPath(s), s.token), 405)
}

func TestLifecycleLogsNeverHoldTokensOrSessions(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) { s.TokenInURL = true })
	s := e.session("viewer-1")
	e.post(hbPath(s), s.token) // too soon: 429
	e.clk.advance(20 * time.Second)
	hb := e.beat(s, s.token)
	e.clk.advance(20 * time.Second)
	hb2 := e.do("POST", hbPath(s)+"?t="+url.QueryEscape(hb.Token), nil)
	e.post(hbPath(s), "v1.x.1.y")
	e.revokeVia(s, "r")
	e.post(hbPath(s), hb.Token)
	e.do("POST", endPath(s)+"?t="+url.QueryEscape(hb.Token), nil)
	e.post(endPath(s), hb.Token)

	logs := e.logs.String()
	if logs == "" {
		t.Fatal("nothing was logged: the test proves nothing")
	}
	var second heartbeat
	_ = json.Unmarshal(hb2.body, &second)
	for name, secret := range map[string]string{
		"token": s.token, "new token": hb.Token, "second new token": second.Token, "escaped token": url.QueryEscape(hb.Token),
		"session ID": s.id, "session ID body": s.id[4:], "token payload": strings.Split(hb.Token, ".")[1],
	} {
		if secret != "" && strings.Contains(logs, secret) {
			t.Errorf("the log contains the %s", name)
		}
	}
}
