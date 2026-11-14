//go:build integration

package edge_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/hls"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
)

func keyPath(s session) string { return "/v1/play/" + s.id + "/key" }

// sign mints a token for the session with the given scopes, valid for ttl from the edge's clock.
func (e *env) sign(s session, scopes token.Scope, ttl time.Duration) string {
	e.t.Helper()
	now := e.clk.Now().UTC().Truncate(time.Second)
	tok, err := e.keyring.Sign(token.Claims{
		SessionID: s.id, AssetID: e.asset.ID.String(), TenantID: e.res.Tenant.ID.String(),
		Scopes: scopes, IssuedAt: now, Expiry: now.Add(ttl),
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

// events returns how many playback_events of the kind exist.
func (e *env) events(kind string) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM playback_events WHERE kind = $1", kind).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// fetches returns the count stored for the token, or -1 when it has no row.
func (e *env) fetches(tok string) int {
	e.t.Helper()
	var n int
	err := e.pool.QueryRow(context.Background(), "SELECT fetches FROM playback_key_fetches WHERE token_hash = $1", db.TokenHash(tok)).Scan(&n)
	if err != nil {
		return -1
	}
	return n
}

func (e *env) sessionSQL(sid, set string) {
	e.t.Helper()
	parsed, err := id.ParseSession(sid)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.pool.Exec(context.Background(), "UPDATE playback_sessions SET "+set+" WHERE id_hash = $1", db.SessionHash(parsed)); err != nil {
		e.t.Fatal(err)
	}
}

func retryAfter(t *testing.T, r reply) int {
	t.Helper()
	n, err := strconv.Atoi(r.hdr.Get("Retry-After"))
	if err != nil || n < 1 {
		t.Fatalf("Retry-After = %q", r.hdr.Get("Retry-After"))
	}
	return n
}

var reKeyIV = regexp.MustCompile(`#EXT-X-KEY:METHOD=AES-128,URI="([^"]+)",IV=0x([0-9A-Fa-f]{32})`)

// TestKeyEndToEnd is the acceptance test of the milestone: a player's whole sequence, from the
// master playlist to decrypted bytes, using only what the playlists say.
func TestKeyEndToEnd(t *testing.T) {
	e := newEnv(t)
	s := e.session("viewer-1")
	base := "/v1/play/" + s.id + "/master.m3u8"

	master := e.get(base, s.token)
	want(t, master, 200)
	variants := uris(t, master.body)
	mediaPath := resolve(t, base, variants[0])
	media := e.get(mediaPath, s.token)
	want(t, media, 200)

	matches := reKeyIV.FindAllStringSubmatch(string(media.body), -1)
	if len(matches) != segCount {
		t.Fatalf("EXT-X-KEY tags = %d, want %d\n%s", len(matches), segCount, media.body)
	}
	keyURI := resolve(t, mediaPath, matches[0][1])
	if keyURI != keyPath(s) {
		t.Fatalf("key URI resolves to %q", keyURI)
	}
	k := e.get(keyURI, s.token)
	want(t, k, 200)
	if len(k.body) != hls.KeyBytes {
		t.Fatalf("key length = %d", len(k.body))
	}
	for name, v := range map[string]string{
		"Content-Type": "application/octet-stream", "Cache-Control": "no-store, private", "Pragma": "no-cache",
		"Referrer-Policy": "no-referrer", "Content-Length": "16",
	} {
		if got := k.hdr.Get(name); got != v {
			t.Errorf("%s = %q, want %q", name, got, v)
		}
	}
	if !bytes.Equal(k.body, e.key) {
		t.Fatal("the key endpoint returned a different key than the asset's")
	}

	// Decrypt every segment with the fetched key and the IV from its own EXT-X-KEY tag.
	segs := 0
	for i, m := range matches {
		raw, err := hex.DecodeString(m[2])
		if err != nil || len(raw) != hls.IVBytes {
			t.Fatalf("IV %q: %v", m[2], err)
		}
		var iv hls.IV
		copy(iv[:], raw)
		name := fmt.Sprintf("seg-%d.m4s", i)
		seg := e.get(resolve(t, mediaPath, name), s.token)
		want(t, seg, 200)
		plain, err := hls.DecryptSegment(k.body, iv, seg.body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(plain, e.plain["240p/"+name]) {
			t.Fatalf("%s: decrypted bytes differ from the plaintext", name)
		}
		segs++
	}
	if segs != segCount {
		t.Fatalf("decrypted %d segments", segs)
	}
}

// A revoked session gets 401 at the key endpoint although its token still verifies.
func TestKeyRevokedSessionIs401WhileTokenVerifies(t *testing.T) {
	e := newEnv(t)
	s := e.session("viewer-1")
	want(t, e.get(keyPath(s), s.token), 200)

	e.revoke(s.id)
	if _, err := e.keyring.Open(s.token, e.clk.Now(), token.ScopeKey); err != nil {
		t.Fatalf("the token no longer verifies: %v", err)
	}
	r := e.get(keyPath(s), s.token)
	want(t, r, 401)
	if r.hdr.Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("headers = %v", r.hdr)
	}
	if strings.Contains(string(r.body), "revok") {
		t.Fatalf("the 401 says why: %s", r.body)
	}
}

func TestKeySessionAndTokenChecks(t *testing.T) {
	cases := map[string]func(e *env, s session) string{
		"idle": func(e *env, s session) string {
			e.sessionSQL(s.id, "last_heartbeat_at = now() - interval '1 hour'")
			return s.token
		},
		"expired": func(e *env, s session) string {
			e.sessionSQL(s.id, "expires_at = now() - interval '1 second', created_at = now() - interval '1 day'")
			return s.token
		},
		"ended": func(e *env, s session) string {
			e.sessionSQL(s.id, "state = 'ended', ended_at = now()")
			return s.token
		},
		"segment-only token": func(e *env, s session) string { return e.sign(s, token.ScopeSegment, time.Minute) },
		"manifest-only token": func(e *env, s session) string {
			return e.sign(s, token.ScopeManifest, time.Minute)
		},
		"expired token": func(e *env, s session) string {
			tok := e.sign(s, token.ScopeKey, time.Minute)
			e.clk.advance(2 * time.Minute)
			return tok
		},
		"garbage": func(*env, session) string { return "v1.x.1.y" },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			s := e.session("viewer-1")
			tok := setup(e, s)
			r := e.get(keyPath(s), tok)
			want(t, r, 401)
			if e.fetches(tok) > 0 {
				t.Fatal("a refused request used a key fetch")
			}
		})
	}
	// A token for another session is refused.
	t.Run("another session", func(t *testing.T) {
		e := newEnv(t)
		a, b := e.session("viewer-a"), e.session("viewer-b")
		want(t, e.get(keyPath(a), b.token), 401)
	})
}

// An asset that is no longer ready, or whose content key was destroyed, is the same 401.
func TestKeyAssetGoneIs401(t *testing.T) {
	t.Run("deleted", func(t *testing.T) {
		e := newEnv(t)
		s := e.session("viewer-1")
		if _, err := e.repos.RequestAssetDeletion(context.Background(), e.res.Tenant.ID, e.asset.ID, db.DeletionRequested, time.Now()); err != nil {
			t.Fatal(err)
		}
		want(t, e.get(keyPath(s), s.token), 401)
	})
	t.Run("key destroyed", func(t *testing.T) {
		e := newEnv(t)
		s := e.session("viewer-1")
		err := db.Tx(context.Background(), e.pool, func(tx *db.Repos) error {
			_, err := e.mgr.Destroy(context.Background(), tx, e.res.Tenant.ID, e.asset.ID)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		want(t, e.get(keyPath(s), s.token), 401)
		if n := e.fetches(s.token); n != 0 {
			t.Fatalf("fetches = %d, want the reserved fetch given back", n)
		}
	})
}

func TestKeyPerTokenBound(t *testing.T) {
	e := newEnv(t)
	s := e.session("viewer-1")
	p := keyPath(s)
	for i := range 20 {
		r := e.get(p, s.token)
		want(t, r, 200)
		if !bytes.Equal(r.body, e.key) {
			t.Fatalf("fetch %d: wrong key", i)
		}
	}
	for range 3 { // several rejected requests, one event
		r := e.get(p, s.token)
		want(t, r, 429)
		if got := retryAfter(t, r); got != 60 { // the heartbeat interval
			t.Fatalf("Retry-After = %d, want the heartbeat interval", got)
		}
		if !strings.Contains(string(r.body), `"code":"rate_limited"`) || r.hdr.Get("Content-Type") != "application/problem+json" {
			t.Fatalf("body %s, headers %v", r.body, r.hdr)
		}
		if bytes.Contains(r.body, e.key) {
			t.Fatal("the 429 carries the key")
		}
	}
	if n := e.events(db.EventKeyReplay); n != 1 {
		t.Fatalf("key_replay events = %d, want 1", n)
	}
	if n := e.fetches(s.token); n != 20 {
		t.Fatalf("stored fetches = %d, rejected requests must not count", n)
	}
	// The event names no token or session ID.
	var detail string
	if err := e.pool.QueryRow(context.Background(), "SELECT detail::text FROM playback_events WHERE kind = 'key_replay'").Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(detail, s.id) || strings.Contains(detail, s.token) {
		t.Fatalf("detail = %s", detail)
	}

	// A fresh token for the same session works again (window: 24 requests so far, bound 30).
	fresh := e.sign(s, token.ScopeKey|token.ScopeManifest|token.ScopeSegment, 5*time.Minute)
	want(t, e.get(p, fresh), 200)
	// The old token is still over its bound, with no second event.
	want(t, e.get(p, s.token), 429)
	if n := e.events(db.EventKeyReplay); n != 1 {
		t.Fatalf("key_replay events = %d, want 1", n)
	}
}

func TestKeyPerMinuteBound(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) { s.KeyRequestsPerMinute = 3 })
	s := e.session("viewer-1")
	p := keyPath(s)
	for range 3 {
		want(t, e.get(p, s.token), 200)
	}
	var wait int
	for range 4 { // rejected requests count too and record one event
		r := e.get(p, s.token)
		want(t, r, 429)
		wait = retryAfter(t, r)
		if wait > 60 {
			t.Fatalf("Retry-After = %d", wait)
		}
	}
	if n := e.events(db.EventKeyRate); n != 1 {
		t.Fatalf("key_rate events = %d, want 1", n)
	}
	if n := e.events(db.EventKeyReplay); n != 0 {
		t.Fatalf("key_replay events = %d", n)
	}
	// Still inside the window after most of it has passed.
	e.clk.advance(time.Duration(wait-1) * time.Second)
	want(t, e.get(p, s.token), 429)
	// The next window starts afterwards.
	e.clk.advance(2 * time.Second)
	want(t, e.get(p, s.token), 200)
	for range 2 {
		want(t, e.get(p, s.token), 200)
	}
	want(t, e.get(p, s.token), 429)
	if n := e.events(db.EventKeyRate); n != 1 {
		t.Fatalf("key_rate events = %d, want one per 10-minute event window (the key window is 1 minute)", n)
	}
}

// Two bounds on two sessions do not interfere.
func TestKeyBoundsAreIndependentPerSession(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) { s.KeyRequestsPerMinute = 2 })
	a, b := e.session("viewer-a"), e.session("viewer-b")
	for range 2 {
		want(t, e.get(keyPath(a), a.token), 200)
	}
	want(t, e.get(keyPath(a), a.token), 429)
	want(t, e.get(keyPath(b), b.token), 200)
}

func TestKeyConcurrentRequestsNeverExceedTheBound(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) { s.KeyFetchesPerToken = 20; s.KeyRequestsPerMinute = 600 })
	s := e.session("viewer-1")
	const total = 50
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		statuses = map[int]int{}
	)
	start := make(chan struct{})
	for range total {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req, err := http.NewRequestWithContext(context.Background(), "GET", e.srv.URL+keyPath(s), nil)
			if err != nil {
				t.Error(err)
				return
			}
			req.Header.Set("Authorization", "Bearer "+s.token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			_ = resp.Body.Close()
			mu.Lock()
			statuses[resp.StatusCode]++
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()
	if statuses[200] != 20 || statuses[429] != total-20 {
		t.Fatalf("statuses = %v, want exactly 20 successes", statuses)
	}
	if n := e.events(db.EventKeyReplay); n != 1 {
		t.Fatalf("key_replay events = %d, want 1 for %d rejected requests", n, total-20)
	}
	if n := e.fetches(s.token); n != 20 {
		t.Fatalf("stored fetches = %d", n)
	}
}

// A key service outage is a 503 (never a 401), and uses up no fetch.
func TestKeyServiceOutageIs503AndConsumesNothing(t *testing.T) {
	e := newEnv(t)
	s := e.session("viewer-1")
	e.kms.SetOutage(true)
	for range 3 {
		r := e.get(keyPath(s), s.token)
		want(t, r, 503)
		if !strings.Contains(string(r.body), `"code":"dependency_unavailable"`) {
			t.Fatalf("body %s", r.body)
		}
	}
	if n := e.fetches(s.token); n != 0 {
		t.Fatalf("stored fetches = %d after failures, want 0", n)
	}
	e.kms.SetOutage(false)
	// All 20 fetches are still there.
	for i := range 20 {
		if r := e.get(keyPath(s), s.token); r.status != 200 {
			// the per-minute window (30) is shared with the failures above
			t.Fatalf("fetch %d: status %d", i, r.status)
		}
	}
	want(t, e.get(keyPath(s), s.token), 429)
}

// failingKeyStore fails one step of the key flow the way the database layer reports an outage.
type failingKeyStore struct {
	edge.KeyStore
	step string
}

func (f failingKeyStore) down() error {
	return errs.Wrap(errs.DependencyUnavailable, "database unavailable", fmt.Errorf("test: %s down", f.step))
}

func (f failingKeyStore) GetAsset(ctx context.Context, t id.TenantID, a id.AssetID) (db.Asset, error) {
	if f.step == "asset" {
		return db.Asset{}, f.down()
	}
	return f.KeyStore.GetAsset(ctx, t, a)
}

func (f failingKeyStore) BumpPlaybackKeyWindow(ctx context.Context, t id.TenantID, h []byte, now time.Time) (time.Time, int, error) {
	if f.step == "window" {
		return time.Time{}, 0, f.down()
	}
	return f.KeyStore.BumpPlaybackKeyWindow(ctx, t, h, now)
}

func (f failingKeyStore) ReservePlaybackKeyFetch(ctx context.Context, th, sh []byte, exp time.Time, limit int) (bool, error) {
	if f.step == "reserve" {
		return false, f.down()
	}
	return f.KeyStore.ReservePlaybackKeyFetch(ctx, th, sh, exp, limit)
}

// A database outage at any step is a 503, never a 401 or a 404 (I11).
func TestKeyDatabaseOutageIs503(t *testing.T) {
	for _, step := range []string{"asset", "window", "reserve"} {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t)
			e.keyStore = func(real edge.KeyStore) edge.KeyStore { return failingKeyStore{KeyStore: real, step: step} }
			e.start()
			s := e.session("viewer-1")
			r := e.get(keyPath(s), s.token)
			want(t, r, 503)
			if !strings.Contains(string(r.body), `"code":"dependency_unavailable"`) {
				t.Fatalf("body %s", r.body)
			}
		})
	}
}

func TestKeyTokenInURLAndCORS(t *testing.T) {
	e := newEnv(t)
	s := e.session("viewer-1")
	p := keyPath(s)
	q := "?t=" + url.QueryEscape(s.token)

	// t is refused while token_in_url is off, and both forms are a 400.
	want(t, e.do("GET", p+q, nil), 401)
	e.settings(func(st *db.PlaybackSettings) { st.TokenInURL = true; st.AllowedOrigins = []string{testOrigin} })
	r := e.do("GET", p+q, nil)
	want(t, r, 200)
	if !bytes.Equal(r.body, e.key) {
		t.Fatal("wrong key through ?t=")
	}
	want(t, e.do("GET", p+q, bearer(s.token)), 400)
	want(t, e.do("GET", p+q+"&t=x", nil), 400)

	// CORS: the exact allowed origin only, with Vary.
	r = e.do("GET", p, map[string]string{"Authorization": "Bearer " + s.token, "Origin": testOrigin})
	want(t, r, 200)
	if r.hdr.Get("Access-Control-Allow-Origin") != testOrigin || r.hdr.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("headers = %v", r.hdr)
	}
	if !strings.Contains(strings.Join(r.hdr.Values("Vary"), ","), "Origin") {
		t.Fatalf("Vary = %v", r.hdr.Values("Vary"))
	}
	r = e.do("GET", p, map[string]string{"Authorization": "Bearer " + s.token, "Origin": "https://evil.example.com"})
	want(t, r, 200)
	if r.hdr.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("another origin got %v", r.hdr)
	}
	// A refusal is readable by the allowed origin, so a player can refresh its token.
	e.revoke(s.id)
	r = e.do("GET", p, map[string]string{"Authorization": "Bearer " + s.token, "Origin": testOrigin})
	want(t, r, 401)
	if r.hdr.Get("Access-Control-Allow-Origin") != testOrigin {
		t.Fatalf("401 headers = %v", r.hdr)
	}
	// The preflight needs no token.
	r = e.do("OPTIONS", p, map[string]string{"Origin": testOrigin, "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization"})
	want(t, r, 204)
	if r.hdr.Get("Access-Control-Allow-Origin") != testOrigin || r.hdr.Get("Access-Control-Allow-Headers") != "Authorization" {
		t.Fatalf("preflight headers = %v", r.hdr)
	}
	r = e.do("OPTIONS", p, map[string]string{"Origin": "https://evil.example.com"})
	want(t, r, 204)
	if r.hdr.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("preflight for another origin: %v", r.hdr)
	}
}

// The key never reaches a cache or a log, and neither do tokens or session IDs.
func TestKeyLogsNeverHoldSecrets(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) {
		s.TokenInURL = true
		s.AllowedOrigins = []string{testOrigin}
		s.KeyFetchesPerToken = 2
		s.KeyRequestsPerMinute = 5
	})
	s := e.session("viewer-1")
	p := keyPath(s)
	q := "?t=" + url.QueryEscape(s.token)
	want(t, e.do("GET", p+q, nil), 200)
	e.do("GET", p+q, map[string]string{"Origin": testOrigin})
	e.do("GET", p+q, nil)            // over the token bound: 429
	e.do("GET", p+q, nil)            // 429 again
	e.do("GET", p+"?t=garbage", nil) // 401
	e.kms.SetOutage(true)
	other := e.sign(s, token.ScopeKey, time.Minute)
	oq := "?t=" + url.QueryEscape(other)
	e.do("GET", p+oq, nil) // 503
	e.kms.SetOutage(false)
	e.do("GET", p+oq, nil) // over the window: 429
	e.revoke(s.id)
	e.do("GET", p+q, nil)

	logs := e.logs.String()
	if logs == "" {
		t.Fatal("nothing was logged: the test proves nothing")
	}
	secrets := map[string]string{
		"token": s.token, "escaped token": url.QueryEscape(s.token), "session ID": s.id, "session ID body": s.id[4:],
		"token payload": strings.Split(s.token, ".")[1], "second token": other,
		"key hex": hex.EncodeToString(e.key), "key base64": base64.StdEncoding.EncodeToString(e.key),
		"key base64url": base64.RawURLEncoding.EncodeToString(e.key), "key base64 raw": strings.TrimRight(base64.StdEncoding.EncodeToString(e.key), "="),
		"key bytes": string(e.key), "token hash": hex.EncodeToString(db.TokenHash(s.token)),
	}
	for name, secret := range secrets {
		if strings.Contains(logs, secret) {
			t.Errorf("the log contains the %s", name)
		}
	}
}

// The sweeper removes counters of expired tokens and keeps live ones.
func TestKeyFetchSweep(t *testing.T) {
	e := newEnv(t)
	s := e.session("viewer-1")
	short := e.sign(s, token.ScopeKey, 2*time.Minute)
	long := e.sign(s, token.ScopeKey, time.Hour)
	want(t, e.get(keyPath(s), short), 200)
	want(t, e.get(keyPath(s), long), 200)

	n, err := playback.SweepKeyFetches(context.Background(), e.repos, e.clk.Now())
	if err != nil || n != 0 {
		t.Fatalf("early sweep deleted %d, %v", n, err)
	}
	e.clk.advance(10 * time.Minute)
	n, err = playback.SweepKeyFetches(context.Background(), e.repos, e.clk.Now())
	if err != nil || n != 1 {
		t.Fatalf("sweep deleted %d, %v; want only the expired token's row", n, err)
	}
	if e.fetches(short) != -1 || e.fetches(long) != 1 {
		t.Fatalf("rows after sweep: short %d long %d", e.fetches(short), e.fetches(long))
	}
}
