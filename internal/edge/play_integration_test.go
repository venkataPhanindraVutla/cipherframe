//go:build integration

package edge_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge"
	"github.com/venkataPhanindraVutla/cipherframe/internal/hls"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/kmstest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/local"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/storagetest"
)

func TestMain(m *testing.M) {
	code := dbtest.Run(m)
	storagetest.Terminate()
	os.Exit(code)
}

type pepper struct{}

func (pepper) Get(v int) (config.Secret, bool) {
	return config.NewSecret(strings.Repeat("p", 32)), v == 1
}
func (pepper) Current() (int, config.Secret) { return 1, config.NewSecret(strings.Repeat("p", 32)) }

// syncBuf is a log sink that is safe to write from the server's goroutines.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// clock is the edge's time source: real time plus an offset the tests advance, so the 30 second
// settings cache can be expired without sleeping.
type clock struct{ offset atomic.Int64 }

func (c *clock) Now() time.Time { return time.Now().Add(time.Duration(c.offset.Load())) }

func (c *clock) advance(d time.Duration) { c.offset.Add(int64(d)) }

// countingStore counts the calls that reach the object store, and can be made to fail.
type countingStore struct {
	storage.Store
	calls atomic.Int64
	err   atomic.Pointer[error]
}

func (c *countingStore) Get(ctx context.Context, key string, r *storage.Range) (io.ReadCloser, storage.ObjectInfo, error) {
	c.calls.Add(1)
	if e := c.err.Load(); e != nil {
		return nil, storage.ObjectInfo{}, *e
	}
	return c.Store.Get(ctx, key, r)
}

func (c *countingStore) Head(ctx context.Context, key string) (storage.ObjectInfo, error) {
	c.calls.Add(1)
	return c.Store.Head(ctx, key)
}

func (c *countingStore) List(ctx context.Context, prefix, cursor string, limit int) (storage.Page, error) {
	c.calls.Add(1)
	return c.Store.List(ctx, prefix, cursor, limit)
}

const (
	testOrigin = "https://app.example.com"
	segCount   = 3
	segSize    = 300 << 10
)

type env struct {
	t       *testing.T
	pool    *pgxpool.Pool
	repos   *db.Repos
	res     auth.BootstrapResult
	asset   db.Asset
	svc     *playback.Service
	keyring *token.Keyring
	store   *countingStore
	clk     *clock
	logs    *syncBuf
	srv     *httptest.Server
	// objects holds the bytes stored per object name ("240p/init.mp4", "240p/seg-1.m4s"): the
	// encrypted segments. plain holds the plaintext each segment was encrypted from.
	objects map[string][]byte
	plain   map[string][]byte
	// kms is the key provider under the content key manager, with fault injection.
	kms *kmstest.Faulty
	// key is the asset's content key, for the test to decrypt with.
	key []byte
	mgr *contentkey.Manager
	log *slog.Logger
	// keyStore, when set, wraps the database-backed key store the edge uses (fault injection).
	keyStore func(edge.KeyStore) edge.KeyStore
	// vx tunes the browser-session route (play_session_integration_test.go); nil means defaults.
	vx *viewerExtras
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	pool := dbtest.NewMigrated(t)
	repos := db.New(pool)
	res, err := auth.NewManager(pool, pepper{}, nil).Bootstrap(ctx, "acme", "acme client")
	if err != nil {
		t.Fatal(err)
	}
	asset := readyAsset(t, repos, res)

	buckets, err := storage.New(ctx, storagetest.Shared(t).Config())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{
		t: t, pool: pool, repos: repos, res: res, asset: asset, clk: &clock{}, logs: &syncBuf{},
		store: &countingStore{Store: buckets.Delivery}, objects: map[string][]byte{}, plain: map[string][]byte{},
	}
	e.log = slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	lp, err := local.NewFromKeys(config.Development, map[int][]byte{1: bytes.Repeat([]byte{0x41}, config.KEKBytes)}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.kms = kmstest.NewFaulty(lp)
	reg, err := kms.NewRegistry(e.kms)
	if err != nil {
		t.Fatal(err)
	}
	e.mgr = contentkey.NewManager(pool, reg, e.log)
	var ck contentkey.ContentKey
	if err := db.Tx(ctx, pool, func(tx *db.Repos) (err error) {
		ck, err = e.mgr.Create(ctx, tx, res.Tenant.ID, asset.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.key = ck.Bytes()
	ck.Zero()
	e.publish(ctx)

	e.keyring, err = token.NewKeyring(map[int][]byte{1: []byte("test-fixture-playback-token-key-0123456789")}, 1)
	if err != nil {
		t.Fatal(err)
	}
	e.svc, err = playback.NewService(playback.Deps{Pool: pool, Keyring: e.keyring, EdgeURL: "https://media.example.com", Now: e.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	e.start()
	return e
}

func readyAsset(t *testing.T, repos *db.Repos, res auth.BootstrapResult) db.Asset {
	t.Helper()
	ctx := context.Background()
	a, err := repos.CreateUploadAsset(ctx, db.NewUploadAsset{
		ID: id.New[id.AssetKind](), TenantID: res.Tenant.ID, ClientID: res.Client.ID, SizeBytes: 1000,
		Method: db.UploadTus, SourceKey: "test-fixture-source-" + id.New[id.AssetKind]().String(),
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, next := range []db.AssetState{db.AssetUploading, db.AssetCommitted, db.AssetProcessing, db.AssetReady} {
		if a, err = repos.TransitionAsset(ctx, res.Tenant.ID, a.ID, db.Transition{From: a.State, To: next}); err != nil {
			t.Fatal(err)
		}
	}
	return a
}

// publish writes what the pipeline writes for an asset with two renditions.
func (e *env) publish(ctx context.Context) {
	e.t.Helper()
	put := func(key string, body []byte) {
		if err := e.store.Put(ctx, key, bytes.NewReader(body), int64(len(body)), "application/octet-stream"); err != nil {
			e.t.Fatal(err)
		}
	}
	tn, as := e.res.Tenant.ID, e.asset.ID
	var variants []hls.Variant
	for i, name := range []string{"240p", "720p"} {
		r, err := keys.ParseRendition(name)
		if err != nil {
			e.t.Fatal(err)
		}
		initBytes := randBytes(e.t, 1<<10)
		e.objects[name+"/init.mp4"] = initBytes
		put(keys.InitSegment(tn, as, r), initBytes)
		pl := hls.MediaPlaylist{InitURI: "init.mp4"}
		for n := range segCount {
			iv := hls.IV{byte(n + 1)}
			plain := randBytes(e.t, segSize)
			b, err := hls.EncryptSegment(e.key, iv, plain)
			if err != nil {
				e.t.Fatal(err)
			}
			e.objects[fmt.Sprintf("%s/seg-%d.m4s", name, n)] = b
			e.plain[fmt.Sprintf("%s/seg-%d.m4s", name, n)] = plain
			put(keys.Segment(tn, as, r, n), b)
			pl.Segments = append(pl.Segments, hls.Segment{URI: fmt.Sprintf("seg-%d.m4s", n), Duration: 6 * time.Second, IV: iv})
		}
		text, err := hls.RenderMedia(pl)
		if err != nil {
			e.t.Fatal(err)
		}
		put(keys.Playlist(tn, as, r), []byte(text))
		variants = append(variants, hls.Variant{
			URI: name + "/playlist.m3u8", Bandwidth: int64(1000 * (i + 1)), AverageBandwidth: int64(900 * (i + 1)),
			Width: 426 * (i + 1), Height: 240 * (i + 1), Codecs: "avc1.64001f,mp4a.40.2", FrameRate: 30,
		})
	}
	master, err := hls.RenderMaster(variants)
	if err != nil {
		e.t.Fatal(err)
	}
	put(keys.Master(tn, as), []byte(master))
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// start (re)builds the edge handler. A new Playback has empty caches.
func (e *env) start() {
	e.t.Helper()
	if e.srv != nil {
		e.srv.Close()
	}
	var ks edge.KeyStore = e.repos
	if e.keyStore != nil {
		ks = e.keyStore(ks)
	}
	p, err := edge.NewPlayback(edge.PlaybackDeps{
		Keyring: e.keyring, Store: e.repos, Delivery: e.store, KeyStore: ks, ContentKeys: e.mgr, Viewer: e.viewerDeps(), Now: e.clk.Now,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.srv = httptest.NewServer(edge.New(edge.Deps{Log: e.log, Playback: p}).Handler())
	e.t.Cleanup(e.srv.Close)
}

func (e *env) settings(edit func(*db.PlaybackSettings)) {
	e.t.Helper()
	s := db.DefaultPlaybackSettings()
	edit(&s)
	if _, err := e.repos.PutPlaybackSettings(context.Background(), e.res.Tenant.ID, s, time.Now().UTC()); err != nil {
		e.t.Fatal(err)
	}
	e.clk.advance(playbackCacheTTL) // the edge may have cached the old settings
}

// playbackCacheTTL mirrors the edge's 30 second settings cache.
const playbackCacheTTL = 31 * time.Second

type session struct {
	id    string
	token string
}

func (e *env) session(viewer string) session {
	e.t.Helper()
	c, err := e.svc.CreateSession(context.Background(), playback.CreateInput{
		TenantID: e.res.Tenant.ID, ClientID: e.res.Client.ID, AssetID: e.asset.ID, ViewerID: viewer,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return session{id: c.SessionID.String(), token: c.Token.Reveal()}
}

type reply struct {
	status int
	hdr    http.Header
	body   []byte
}

func (e *env) do(method, path string, hdr map[string]string) reply {
	e.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, e.srv.URL+path, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return reply{resp.StatusCode, resp.Header, b}
}

func bearer(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

func (e *env) get(path, tok string) reply { return e.do("GET", path, bearer(tok)) }

func want(t *testing.T, r reply, status int) {
	t.Helper()
	if r.status != status {
		t.Fatalf("status = %d, want %d; body %s", r.status, status, r.body)
	}
}

func (e *env) revoke(sid string) {
	e.t.Helper()
	parsed, err := id.ParseSession(sid)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.pool.Exec(context.Background(),
		"UPDATE playback_sessions SET state = 'revoked', revoked_at = now(), revoke_reason = 'test' WHERE id_hash = $1", db.SessionHash(parsed)); err != nil {
		e.t.Fatal(err)
	}
}

func resolve(t *testing.T, base, ref string) string {
	t.Helper()
	b, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	r, err := url.Parse(ref)
	if err != nil {
		t.Fatal(err)
	}
	return b.ResolveReference(r).RequestURI()
}

func lines(b []byte) []string { return strings.Split(strings.TrimSpace(string(b)), "\n") }

// uriLines returns the non-tag lines and the URI="..." values of a playlist.
func uris(t *testing.T, body []byte) []string {
	t.Helper()
	var out []string
	for _, l := range lines(body) {
		switch {
		case !strings.HasPrefix(l, "#"):
			out = append(out, l)
		case strings.Contains(l, `URI="`):
			s := l[strings.Index(l, `URI="`)+5:]
			out = append(out, s[:strings.Index(s, `"`)])
		}
	}
	return out
}

func TestPlaybackHeaderFlow(t *testing.T) {
	e := newEnv(t)
	s := e.session("viewer-1")
	base := "/v1/play/" + s.id + "/master.m3u8"

	m := e.get(base, s.token)
	want(t, m, 200)
	if ct := m.hdr.Get("Content-Type"); ct != "application/vnd.apple.mpegurl" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if m.hdr.Get("Cache-Control") != "no-store" || m.hdr.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("headers = %v", m.hdr)
	}
	if m.hdr.Get("Content-Length") != fmt.Sprint(len(m.body)) {
		t.Fatalf("Content-Length = %q, body %d", m.hdr.Get("Content-Length"), len(m.body))
	}
	variants := uris(t, m.body)
	if len(variants) != 2 || variants[0] != "240p/media.m3u8" || variants[1] != "720p/media.m3u8" {
		t.Fatalf("variants = %v\n%s", variants, m.body)
	}
	if strings.Contains(string(m.body), s.token) || strings.Contains(string(m.body), "?") {
		t.Fatal("header mode must not put a token or query in the playlist")
	}

	mediaPath := resolve(t, base, variants[0])
	if mediaPath != "/v1/play/"+s.id+"/240p/media.m3u8" {
		t.Fatalf("resolved variant = %q", mediaPath)
	}
	media := e.get(mediaPath, s.token)
	want(t, media, 200)
	if media.hdr.Get("Cache-Control") != "no-store" || media.hdr.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("headers = %v", media.hdr)
	}
	ref := uris(t, media.body)
	// init, then one key and one segment per segment, in order.
	if len(ref) != 1+2*segCount || ref[0] != "init.mp4" {
		t.Fatalf("uris = %v\n%s", ref, media.body)
	}
	if strings.Contains(string(media.body), hls.KeyURI) {
		t.Fatal("the key placeholder survived")
	}
	if got := resolve(t, mediaPath, ref[1]); got != "/v1/play/"+s.id+"/key" {
		t.Fatalf("key URI resolves to %q", got)
	}

	// The init segment and every media segment are the bytes the pipeline stored.
	for _, name := range []string{"init.mp4", "seg-0.m4s", "seg-1.m4s", "seg-2.m4s"} {
		r := e.get(resolve(t, mediaPath, name), s.token)
		want(t, r, 200)
		if !bytes.Equal(r.body, e.objects["240p/"+name]) {
			t.Fatalf("%s: body differs from the stored object", name)
		}
		wantType := "video/iso.segment"
		if name == "init.mp4" {
			wantType = "video/mp4"
		}
		if r.hdr.Get("Content-Type") != wantType {
			t.Fatalf("%s: Content-Type = %q, want %q", name, r.hdr.Get("Content-Type"), wantType)
		}
		if r.hdr.Get("Content-Length") != fmt.Sprint(len(r.body)) {
			t.Fatalf("%s: Content-Length = %q", name, r.hdr.Get("Content-Length"))
		}
		if r.hdr.Get("Referrer-Policy") != "no-referrer" || r.hdr.Get("Cache-Control") != "private, max-age=300" {
			t.Fatalf("%s: headers = %v", name, r.hdr)
		}
	}
	// The other rendition is served too.
	want(t, e.get("/v1/play/"+s.id+"/720p/media.m3u8", s.token), 200)
}

func TestTokenInURL(t *testing.T) {
	e := newEnv(t)
	s := e.session("viewer-1")
	master := "/v1/play/" + s.id + "/master.m3u8"

	// Off by default: the query form is refused, even with a valid token.
	r := e.do("GET", master+"?t="+url.QueryEscape(s.token), nil)
	want(t, r, 401)
	if r.hdr.Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q", r.hdr.Get("WWW-Authenticate"))
	}
	want(t, e.get(master, s.token), 200)

	// Both forms together are a 400, whatever the setting.
	both := e.do("GET", master+"?t="+url.QueryEscape(s.token), bearer(s.token))
	want(t, both, 400)
	e.settings(func(s *db.PlaybackSettings) { s.TokenInURL = true })
	want(t, e.do("GET", master+"?t="+url.QueryEscape(s.token), bearer(s.token)), 400)
	want(t, e.do("GET", master+"?t=a&t=b", nil), 400)
	want(t, e.do("GET", master, nil), 401) // neither

	// On: the query form works and every URI of the playlists carries the token.
	m := e.do("GET", master+"?t="+url.QueryEscape(s.token), nil)
	want(t, m, 200)
	suffix := "?t=" + url.QueryEscape(s.token)
	variants := uris(t, m.body)
	if len(variants) != 2 {
		t.Fatalf("variants = %v", variants)
	}
	for _, v := range variants {
		if !strings.HasSuffix(v, suffix) {
			t.Fatalf("variant %q lacks the token", v)
		}
	}
	mediaPath := resolve(t, master, variants[0])
	media := e.do("GET", mediaPath, nil)
	want(t, media, 200)
	ref := uris(t, media.body)
	if len(ref) != 1+2*segCount {
		t.Fatalf("uris = %v", ref)
	}
	for _, u := range ref {
		if !strings.HasSuffix(u, suffix) {
			t.Fatalf("URI %q lacks the token", u)
		}
	}
	seg := e.do("GET", resolve(t, mediaPath, ref[2]), nil) // the first media segment (ref[0] is init, ref[1] the key)
	want(t, seg, 200)
	if !bytes.Equal(seg.body, e.objects["240p/seg-0.m4s"]) || seg.hdr.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("segment fetched with the URL token is wrong")
	}
	// The header form still works when the setting is on.
	want(t, e.get(master, s.token), 200)
}

func TestTokenFailuresAreOneAnswer(t *testing.T) {
	e := newEnv(t)
	a, b := e.session("viewer-a"), e.session("viewer-b")
	seg := "/v1/play/" + a.id + "/240p/seg-0.m4s"
	master := "/v1/play/" + a.id + "/master.m3u8"

	mint := func(scopes token.Scope, session string, exp time.Duration) string {
		now := time.Now()
		tok, err := e.keyring.Sign(token.Claims{
			SessionID: session, AssetID: e.asset.ID.String(), TenantID: e.res.Tenant.ID.String(),
			Scopes: scopes, IssuedAt: now.Add(-time.Minute), Expiry: now.Add(exp),
		})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	other, err := token.NewKeyring(map[int][]byte{1: []byte("test-fixture-another-token-key-0123456789")}, 1)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := other.Sign(token.Claims{
		SessionID: a.id, AssetID: e.asset.ID.String(), TenantID: e.res.Tenant.ID.String(),
		Scopes: token.ScopeManifest | token.ScopeSegment, IssuedAt: time.Now().Add(-time.Minute), Expiry: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, path, tok string
	}{
		{"another session's token on a playlist", master, b.token},
		{"another session's token on a segment", seg, b.token},
		{"segment-only token on a playlist", master, mint(token.ScopeSegment, a.id, time.Hour)},
		{"manifest-only token on a segment", seg, mint(token.ScopeManifest, a.id, time.Hour)},
		{"key-only token on a segment", seg, mint(token.ScopeKey, a.id, time.Hour)},
		{"expired token", seg, mint(token.ScopeSegment, a.id, -time.Second)},
		{"token signed with another key", seg, foreign},
		{"garbage", seg, "garbage"},
		{"empty bearer", seg, ""},
	}
	var details []string
	for _, c := range cases {
		r := e.do("GET", c.path, map[string]string{"Authorization": "Bearer " + c.tok})
		if r.status != 401 || r.hdr.Get("WWW-Authenticate") != "Bearer" {
			t.Fatalf("%s: status %d, body %s", c.name, r.status, r.body)
		}
		var pb struct{ Code, Detail string }
		if err := json.Unmarshal(r.body, &pb); err != nil {
			t.Fatal(err)
		}
		details = append(details, pb.Code+": "+pb.Detail)
	}
	// Whatever the cause, the code and detail are the same.
	for _, d := range details[1:] {
		if d != details[0] {
			t.Fatalf("401 details differ:\n%s\n%s", details[0], d)
		}
	}
	// And the right tokens work: a segment-only token on a segment, a manifest-only one on a playlist.
	want(t, e.get(seg, mint(token.ScopeSegment, a.id, time.Hour)), 200)
	want(t, e.get(master, mint(token.ScopeManifest, a.id, time.Hour)), 200)
	// A non-bearer scheme and two Authorization headers are refused too.
	want(t, e.do("GET", seg, map[string]string{"Authorization": "Basic abc"}), 401)
	// A malformed session in the path is a 404, before any token is looked at.
	want(t, e.get("/v1/play/ses_nope/master.m3u8", a.token), 404)
}

func TestRevokedSessionLosesPlaylistsButSegmentsLastUntilTokenExpiry(t *testing.T) {
	e := newEnv(t)
	s := e.session("viewer-1")
	master := "/v1/play/" + s.id + "/master.m3u8"
	media := "/v1/play/" + s.id + "/240p/media.m3u8"
	seg := "/v1/play/" + s.id + "/240p/seg-0.m4s"
	want(t, e.get(master, s.token), 200)

	e.revoke(s.id)
	want(t, e.get(master, s.token), 401)
	want(t, e.get(media, s.token), 401)
	// Documented behaviour (ADR 0028): segments are stateless and stay available until the token
	// expires; they are unreadable without the key, which the key endpoint refuses at once.
	want(t, e.get(seg, s.token), 200)
}

func TestPlaylistSessionChecks(t *testing.T) {
	for name, mutate := range map[string]string{
		"ended":   "UPDATE playback_sessions SET state = 'ended', ended_at = now() WHERE id_hash = $1",
		"idle":    "UPDATE playback_sessions SET last_heartbeat_at = now() - interval '301 seconds' WHERE id_hash = $1",
		"expired": "UPDATE playback_sessions SET created_at = now() - interval '5 hours', last_heartbeat_at = now(), expires_at = now() - interval '1 hour' WHERE id_hash = $1",
		"deleted": "DELETE FROM playback_sessions WHERE id_hash = $1",
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			s := e.session("viewer-1")
			master := "/v1/play/" + s.id + "/master.m3u8"
			want(t, e.get(master, s.token), 200)
			parsed, err := id.ParseSession(s.id)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.pool.Exec(context.Background(), mutate, db.SessionHash(parsed)); err != nil {
				t.Fatal(err)
			}
			want(t, e.get(master, s.token), 401)
			want(t, e.get("/v1/play/"+s.id+"/240p/media.m3u8", s.token), 401)
			want(t, e.get("/v1/play/"+s.id+"/240p/init.mp4", s.token), 200) // stateless
		})
	}
}

func TestPathAllowlistNeverReachesStorage(t *testing.T) {
	e := newEnv(t)
	s := e.session("viewer-1")
	p := "/v1/play/" + s.id
	cases := []string{
		p + "/240p/../720p/init.mp4",
		p + "/../240p/init.mp4",
		p + "/240p/..",
		p + "/%2e%2e/240p/init.mp4",
		p + "/240p/%2e%2e%2finit.mp4",
		p + "/240p/..%2finit.mp4",
		p + "/240p%2f..%2f720p/init.mp4",
		p + "/240p%2fx/init.mp4",
		p + "/240p/a%2fb.m4s",
		p + "/240p/%5c..%5cinit.mp4",
		p + "/240p/init.mp4%00",
		p + "/240p/init.mp4/",
		p + "/240p//init.mp4",
		p + "//240p/init.mp4",
		p + "/240P/init.mp4",
		p + "/240p/INIT.MP4",
		p + "/240p/init.mp4.bak",
		p + "/240p/seg-01.m4s",
		p + "/240p/seg--1.m4s",
		p + "/240p/seg-1.m4s%20",
		p + "/240p/seg-1234567890.m4s",
		p + "/240p/seg-.m4s",
		p + "/240p/playlist.m3u8",
		p + "/240p/media.m3u8.bak",
		p + "/" + strings.Repeat("a", 17) + "/init.mp4",
		p + "/a-b/init.mp4",
		p + "/.hidden/init.mp4",
		p + "/hls/master.m3u8",
	}
	for _, c := range cases {
		before := e.store.calls.Load()
		r := e.get(c, s.token)
		if r.status != 404 {
			t.Errorf("GET %s: status %d, want 404 (%s)", c, r.status, r.body)
		}
		if after := e.store.calls.Load(); after != before {
			t.Errorf("GET %s reached the object store", c)
		}
	}
	// Well-formed names of things that do not exist are 404 too, found by the store.
	for _, c := range []string{p + "/360p/init.mp4", p + "/240p/seg-99.m4s", p + "/360p/media.m3u8"} {
		want(t, e.get(c, s.token), 404)
	}
	// "key" is a route of its own, not a rendition: with a rendition and a file it is not served.
	want(t, e.get(p+"/key/init.mp4", s.token), 404)
}

func TestCORS(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) { s.AllowedOrigins = []string{testOrigin} })
	s := e.session("viewer-1")
	paths := []string{
		"/v1/play/" + s.id + "/master.m3u8",
		"/v1/play/" + s.id + "/240p/media.m3u8",
		"/v1/play/" + s.id + "/240p/seg-0.m4s",
	}
	acao := func(r reply) string { return r.hdr.Get("Access-Control-Allow-Origin") }
	for _, p := range paths {
		// Allowed origin: exactly that origin, and responses vary on Origin.
		r := e.do("GET", p, map[string]string{"Authorization": "Bearer " + s.token, "Origin": testOrigin})
		want(t, r, 200)
		if acao(r) != testOrigin || !strings.Contains(r.hdr.Get("Vary"), "Origin") || r.hdr.Get("Access-Control-Allow-Credentials") != "" {
			t.Fatalf("%s: headers = %v", p, r.hdr)
		}
		// Other origins (including near misses) and no origin: no CORS headers, same success.
		for _, o := range []string{"https://evil.example.com", testOrigin + ".evil.com", "http://app.example.com", "https://APP.example.com", testOrigin + "/", "null"} {
			r := e.do("GET", p, map[string]string{"Authorization": "Bearer " + s.token, "Origin": o})
			want(t, r, 200)
			if len(r.hdr.Values("Access-Control-Allow-Origin")) != 0 || !strings.Contains(r.hdr.Get("Vary"), "Origin") {
				t.Fatalf("%s: origin %q got %v", p, o, r.hdr)
			}
		}
		r = e.get(p, s.token)
		want(t, r, 200)
		if acao(r) != "" || !strings.Contains(r.hdr.Get("Vary"), "Origin") {
			t.Fatalf("%s: no-origin request got %v", p, r.hdr)
		}

		// Preflight: no token needed; 204 with the headers for an allowed origin only.
		pf := e.do("OPTIONS", p, map[string]string{"Origin": testOrigin, "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization"})
		want(t, pf, 204)
		if acao(pf) != testOrigin || pf.hdr.Get("Access-Control-Allow-Methods") != "GET, POST, OPTIONS" ||
			pf.hdr.Get("Access-Control-Allow-Headers") != "Authorization" || pf.hdr.Get("Access-Control-Allow-Credentials") != "" ||
			!strings.Contains(pf.hdr.Get("Vary"), "Origin") {
			t.Fatalf("%s: preflight headers = %v", p, pf.hdr)
		}
		bad := e.do("OPTIONS", p, map[string]string{"Origin": "https://evil.example.com", "Access-Control-Request-Method": "GET"})
		want(t, bad, 204)
		if len(bad.hdr.Values("Access-Control-Allow-Origin")) != 0 || bad.hdr.Get("Access-Control-Allow-Methods") != "" {
			t.Fatalf("%s: preflight for a bad origin got %v", p, bad.hdr)
		}
	}
	// A 401 still carries the CORS headers, so a browser player can read it and refresh its token.
	r := e.do("GET", paths[2], map[string]string{"Authorization": "Bearer garbage", "Origin": testOrigin})
	want(t, r, 401)
	if acao(r) != testOrigin {
		t.Fatalf("401 headers = %v", r.hdr)
	}
	// A made-up session gets no CORS headers (and a preflight for it is still just a 204).
	ghost, err := id.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	pf := e.do("OPTIONS", "/v1/play/"+ghost.String()+"/master.m3u8", map[string]string{"Origin": testOrigin})
	want(t, pf, 204)
	if len(pf.hdr.Values("Access-Control-Allow-Origin")) != 0 {
		t.Fatalf("preflight for an unknown session got %v", pf.hdr)
	}
	// A preflight for a path that is not a playback route is not answered by the gate.
	if r := e.do("OPTIONS", "/v1/play/"+s.id+"/240p/other.txt", map[string]string{"Origin": testOrigin}); r.status == 204 {
		t.Fatal("preflight answered for a path that is not a route")
	}
	// A tenant with no allowed origins gets none.
	e.settings(func(s *db.PlaybackSettings) {})
	r = e.do("GET", paths[0], map[string]string{"Authorization": "Bearer " + s.token, "Origin": testOrigin})
	want(t, r, 200)
	if acao(r) != "" {
		t.Fatalf("tenant without origins got %v", r.hdr)
	}
}

func TestStorageFailuresAreNotNotFound(t *testing.T) {
	e := newEnv(t)
	s := e.session("viewer-1")
	paths := []string{
		"/v1/play/" + s.id + "/master.m3u8",
		"/v1/play/" + s.id + "/240p/media.m3u8",
		"/v1/play/" + s.id + "/240p/seg-0.m4s",
	}
	for name, tc := range map[string]struct {
		err    error
		status int
	}{
		"unavailable": {&storage.Error{Kind: storage.Unavailable, Op: "get", Role: keys.Delivery, HTTPStatus: 503}, 503},
		"timeout":     {&storage.Error{Kind: storage.Timeout, Op: "get", Role: keys.Delivery}, 504},
		"denied":      {&storage.Error{Kind: storage.PermissionDenied, Op: "get", Role: keys.Delivery, Code: "AccessDenied"}, 500},
		"missing":     {&storage.Error{Kind: storage.NotFound, Op: "get", Role: keys.Delivery, Code: "NoSuchKey"}, 404},
	} {
		t.Run(name, func(t *testing.T) {
			e.store.err.Store(&tc.err)
			t.Cleanup(func() { e.store.err.Store(nil) })
			for _, p := range paths {
				want(t, e.get(p, s.token), tc.status)
			}
		})
	}
	e.store.err.Store(nil)
	want(t, e.get(paths[2], s.token), 200)
}

// TestLogsNeverHoldTokensOrSessions drives every kind of request, with the token in the header and
// in the URL, successes and failures, and scans what was logged.
func TestLogsNeverHoldTokensOrSessions(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) { s.TokenInURL = true; s.AllowedOrigins = []string{testOrigin} })
	s := e.session("viewer-1")
	q := "?t=" + url.QueryEscape(s.token)
	p := "/v1/play/" + s.id
	e.get(p+"/master.m3u8", s.token)
	e.do("GET", p+"/master.m3u8"+q, nil)
	e.do("GET", p+"/240p/media.m3u8"+q, nil)
	e.do("GET", p+"/240p/seg-0.m4s"+q, map[string]string{"Origin": testOrigin})
	e.do("GET", p+"/240p/seg-0.m4s"+q+"&x=1", bearer(s.token)) // both forms: 400
	e.do("GET", p+"/240p/seg-0.m4s?t=garbage", nil)
	e.do("OPTIONS", p+"/master.m3u8", map[string]string{"Origin": testOrigin})
	e.do("GET", p+"/240p/%2e%2e/init.mp4"+q, nil)
	e.do("GET", p+"/360p/init.mp4"+q, nil)
	e.revoke(s.id)
	e.do("GET", p+"/master.m3u8"+q, nil)
	err := error(&storage.Error{Kind: storage.Unavailable, Op: "get", Role: keys.Delivery})
	e.store.err.Store(&err)
	e.do("GET", p+"/240p/seg-0.m4s"+q, nil)
	e.do("GET", p+"/240p/init.mp4?t="+s.token, nil)

	logs := e.logs.String()
	if logs == "" {
		t.Fatal("nothing was logged: the test proves nothing")
	}
	for name, secret := range map[string]string{
		"token": s.token, "escaped token": url.QueryEscape(s.token), "session ID": s.id, "session ID body": s.id[4:],
		"token payload": strings.Split(s.token, ".")[1], "t parameter": "t=", "object key": "/hls/", "tenant ID": e.res.Tenant.ID.String(),
	} {
		if strings.Contains(logs, secret) {
			t.Errorf("the log contains the %s", name)
		}
	}
}
