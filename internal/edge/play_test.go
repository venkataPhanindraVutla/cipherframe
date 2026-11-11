package edge

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
)

func TestTTLCache(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	c := newTTLCache[string, int](3, 30*time.Second, clock)

	c.put("a", 1)
	if v, ok := c.get("a"); !ok || v != 1 {
		t.Fatalf("get a = %d, %v", v, ok)
	}
	now = now.Add(29 * time.Second)
	if _, ok := c.get("a"); !ok {
		t.Fatal("entry expired early")
	}
	now = now.Add(time.Second)
	if _, ok := c.get("a"); ok {
		t.Fatal("entry outlived its TTL")
	}

	// The cache never grows past its bound, however many keys arrive.
	for i := range 100 {
		c.put(string(rune('A'+i%26))+string(rune('a'+i/26)), i)
		if len(c.m) > 3 {
			t.Fatalf("size = %d, bound 3", len(c.m))
		}
	}
	// A full cache prefers to drop expired entries over live ones.
	c = newTTLCache[string, int](2, 30*time.Second, clock)
	c.put("old", 1)
	now = now.Add(31 * time.Second)
	c.put("live", 2)
	c.put("new", 3)
	if _, ok := c.get("live"); !ok {
		t.Fatal("a live entry was dropped while an expired one existed")
	}
	if _, ok := c.get("new"); !ok {
		t.Fatal("the new entry is missing")
	}
}

func TestPlaybackTokenExtraction(t *testing.T) {
	req := func(target string, hdr ...string) *http.Request {
		r := httptest.NewRequestWithContext(context.Background(), "GET", target, nil)
		for _, h := range hdr {
			r.Header.Add("Authorization", h)
		}
		return r
	}
	cases := []struct {
		name     string
		r        *http.Request
		tok      string
		query    bool
		wantCode errs.Code
	}{
		{"header", req("/x", "Bearer abc"), "abc", false, ""},
		{"scheme is case-insensitive", req("/x", "bearer abc"), "abc", false, ""},
		{"query", req("/x?t=abc"), "abc", true, ""},
		{"neither", req("/x"), "", false, errs.Unauthenticated},
		{"both", req("/x?t=abc", "Bearer abc"), "", false, errs.InvalidRequest},
		{"both, query empty", req("/x?t=", "Bearer abc"), "", false, errs.InvalidRequest},
		{"query twice", req("/x?t=a&t=b"), "", false, errs.InvalidRequest},
		{"wrong scheme", req("/x", "Basic abc"), "", false, errs.Unauthenticated},
		{"two headers", req("/x", "Bearer a", "Bearer b"), "", false, errs.Unauthenticated},
		{"space in token", req("/x", "Bearer a b"), "", false, errs.Unauthenticated},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tok, fromQuery, err := playbackToken(c.r)
			if c.wantCode != "" {
				var e *errs.Error
				if !errors.As(err, &e) || e.Code != c.wantCode {
					t.Fatalf("err = %v, want %s", err, c.wantCode)
				}
				return
			}
			if err != nil || tok != c.tok || fromQuery != c.query {
				t.Fatalf("got %q, %v, %v", tok, fromQuery, err)
			}
		})
	}
}

// zeroStore serves a segment of the given size as a lazy stream and records how much of it was
// read, so a test can tell whether the handler buffered the object.
type zeroStore struct {
	storage.DeliveryStore
	size int64
	read atomic.Int64
	done chan struct{}
}

type countingZeros struct {
	left int64
	s    *zeroStore
}

func (c *countingZeros) Read(p []byte) (int, error) {
	if c.left == 0 {
		return 0, io.EOF
	}
	n := min(int64(len(p)), c.left)
	clear(p[:n])
	c.left -= n
	c.s.read.Add(n)
	return int(n), nil
}

func (c *countingZeros) Close() error {
	select {
	case <-c.s.done:
	default:
		close(c.s.done)
	}
	return nil
}

func (z *zeroStore) Get(context.Context, string, *storage.Range) (io.ReadCloser, storage.ObjectInfo, error) {
	return &countingZeros{left: z.size, s: z}, storage.ObjectInfo{Size: z.size}, nil
}

type settingsOnlyStore struct{}

func (settingsOnlyStore) GetPlaybackSettings(context.Context, id.TenantID) (db.PlaybackSettings, error) {
	return db.DefaultPlaybackSettings(), nil
}

func (settingsOnlyStore) GetPlaybackSession(context.Context, id.TenantID, []byte) (db.PlaybackSession, error) {
	return db.PlaybackSession{}, errs.New(errs.InternalError, "a segment request must not read the session")
}

func (settingsOnlyStore) PlaybackSessionTenant(context.Context, []byte) (id.TenantID, error) {
	return id.TenantID{}, errs.New(errs.InternalError, "a successful segment request must not look up the session's tenant")
}

func (settingsOnlyStore) HeartbeatPlaybackSession(context.Context, id.TenantID, []byte, id.AssetID, time.Time, time.Duration, time.Duration) (db.PlaybackSession, db.HeartbeatOutcome, time.Duration, error) {
	return db.PlaybackSession{}, db.HeartbeatUnusable, 0, errs.New(errs.InternalError, "a segment request must not heartbeat")
}

func (settingsOnlyStore) EndPlaybackSession(context.Context, id.TenantID, []byte, time.Time) (bool, error) {
	return false, errs.New(errs.InternalError, "a segment request must not end the session")
}

// TestSegmentIsStreamed proves a segment is not buffered: a client that reads a little and hangs
// up makes the handler stop reading the (1 GiB) object long before the end, and the object is
// closed.
func TestSegmentIsStreamed(t *testing.T) {
	const size = 1 << 30
	keyring, err := token.NewKeyring(map[int][]byte{1: []byte("test-fixture-playback-token-key-0123456789")}, 1)
	if err != nil {
		t.Fatal(err)
	}
	store := &zeroStore{size: size, done: make(chan struct{})}
	p, err := NewPlayback(PlaybackDeps{Keyring: keyring, Store: settingsOnlyStore{}, Delivery: store})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Deps{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Playback: p}).Handler())
	t.Cleanup(srv.Close)

	sid, err := id.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok, err := keyring.Sign(token.Claims{
		SessionID: sid.String(), AssetID: id.New[id.AssetKind]().String(), TenantID: id.New[id.TenantKind]().String(),
		Scopes: token.ScopeSegment, IssuedAt: now, Expiry: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), "GET", srv.URL+"/v1/play/"+sid.String()+"/720p/seg-0.m4s", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || resp.ContentLength != size {
		t.Fatalf("status %d, Content-Length %d", resp.StatusCode, resp.ContentLength)
	}
	if _, err := io.ReadFull(resp.Body, make([]byte, 64<<10)); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	select {
	case <-store.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the object was never closed after the client hung up")
	}
	if n := store.read.Load(); n > 256<<20 {
		t.Fatalf("handler read %d bytes of a %d byte object for a client that took 64 KiB", n, int64(size))
	}
}

func TestPresignTTL(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 500_000_000, time.UTC)
	for _, tc := range []struct {
		name string
		exp  time.Time
		want time.Duration
		ok   bool
	}{
		{"long token is capped", now.Add(time.Hour), 10 * time.Minute, true},
		{"exactly the cap", now.Add(10 * time.Minute), 10 * time.Minute, true},
		{"short token", now.Add(90*time.Second + 700*time.Millisecond), 90 * time.Second, true},
		{"one second", now.Add(time.Second), time.Second, true},
		{"under a second", now.Add(999 * time.Millisecond), 0, false},
		{"expired", now.Add(-time.Second), 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := presignTTL(tc.exp, now)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("presignTTL = %s, %v; want %s, %v", got, ok, tc.want, tc.ok)
			}
			if ok && now.Add(got).After(tc.exp) {
				t.Fatal("the URL would outlive the token")
			}
		})
	}
}
