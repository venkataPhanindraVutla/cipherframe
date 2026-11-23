//go:build integration

package edge_test

import (
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/cdn"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
)

// CDN delivery (ADR 0062, M10-1): media playlists carry CDN-signed URLs under the presigned expiry
// rule; the key, the master playlist and the thumbnails stay on edge.

const cdnHost = "cdn.example.com"

// cdnEnv is an edge with a Cloud CDN signer (HMAC, so no key generation) and delivery set to cdn.
func cdnEnv(t *testing.T, edit func(*db.PlaybackSettings)) *env {
	t.Helper()
	e := newEnv(t)
	var err error
	if e.cdn, err = cdn.NewCloudCDN("https://"+cdnHost, "test-key", []byte("AAECAwQFBgcICQoLDA0ODw==")); err != nil {
		t.Fatal(err)
	}
	e.settings(func(s *db.PlaybackSettings) {
		s.Delivery = db.DeliveryCDN
		if edit != nil {
			edit(s)
		}
	})
	e.start()
	return e
}

// cdnExpiry returns the Expires parameter of a signed CDN URL.
func cdnExpiry(t *testing.T, raw string) time.Time {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil || u.Host != cdnHost || u.Scheme != "https" {
		t.Fatal("segment URI is not a signed URL of the CDN")
	}
	q := u.Query()
	n, err := strconv.ParseInt(q.Get("Expires"), 10, 64)
	if err != nil || q.Get("KeyName") != "test-key" || q.Get("Signature") == "" {
		t.Fatal("the signed URL lacks Expires, KeyName or Signature")
	}
	return time.Unix(n, 0)
}

func TestCDNPlaylistCarriesSignedCDNURLs(t *testing.T) {
	e := cdnEnv(t, nil)
	s := e.session("viewer-1")
	_, media := mediaOf(e, s, "240p")

	m := e.get("/v1/play/"+s.id+"/master.m3u8", s.token)
	want(t, m, 200)
	if v := uris(t, m.body); len(v) != 2 || v[0] != "240p/media.m3u8" || strings.Contains(string(m.body), "?") {
		t.Fatalf("master playlist changed: %v", v)
	}
	initURL, segURLs := mediaURIs(t, media.body)
	prefix := "/t/" + e.res.Tenant.ID.String() + "/a/" + e.asset.ID.String() + "/"
	for _, u := range append([]string{initURL}, segURLs...) {
		cdnExpiry(t, u)
		if p, _ := url.Parse(u); !strings.HasPrefix(p.Path, prefix) {
			t.Fatal("a segment URL is outside the asset's delivery prefix")
		}
	}
	// The key stays on edge, relative, without a token.
	if m := reKeyIV.FindAllStringSubmatch(string(media.body), -1); len(m) != segCount || m[0][1] != "../key" {
		t.Fatalf("key tags: %v", m)
	}
	// The proxy route still works in this mode, like in presigned.
	want(t, e.get("/v1/play/"+s.id+"/240p/seg-0.m4s", s.token), 200)
}

func TestCDNExpiryFollowsThePresignedRule(t *testing.T) {
	e := cdnEnv(t, func(s *db.PlaybackSettings) { s.TokenTTLSeconds = 3600 })
	s := e.session("viewer-1")
	now := e.clk.Now()

	// A one-hour token: ten minutes.
	_, media := mediaOf(e, s, "720p")
	initURL, segURLs := mediaURIs(t, media.body)
	for _, u := range append([]string{initURL}, segURLs...) {
		if got := cdnExpiry(t, u); !got.Equal(now.Truncate(time.Second).Add(10 * time.Minute)) {
			t.Fatalf("expiry %s from %s, want 10 minutes", got, now)
		}
	}

	// A token with 5 minutes left: the URL ends with the token.
	short := e.sign(s, token.ScopeManifest, 5*time.Minute)
	r := e.get("/v1/play/"+s.id+"/720p/media.m3u8", short)
	want(t, r, 200)
	sc, err := e.keyring.Open(short, e.clk.Now(), token.ScopeManifest)
	if err != nil {
		t.Fatal(err)
	}
	initURL, _ = mediaURIs(t, r.body)
	if got := cdnExpiry(t, initURL); got.After(sc.Expiry) || sc.Expiry.Sub(got) > time.Second {
		t.Fatalf("expiry %s for a token that ends at %s", got, sc.Expiry)
	}

	// Renewed on refetch: the clock moves, the new URL expires later.
	e.clk.advance(3 * time.Minute)
	long := e.sign(s, token.ScopeManifest, time.Hour)
	r = e.get("/v1/play/"+s.id+"/720p/media.m3u8", long)
	want(t, r, 200)
	again, _ := mediaURIs(t, r.body)
	if !cdnExpiry(t, again).After(cdnExpiry(t, initURL)) {
		t.Fatal("a refetch did not renew the expiry")
	}

	// Under a second left: unauthorized, like presigned.
	want(t, e.get("/v1/play/"+s.id+"/240p/media.m3u8", e.sign(s, token.ScopeManifest, time.Second)), 401)
}

// A tenant that still has cdn after the operator removed the CDN is served as proxy.
func TestCDNWithoutASignerFallsBackToProxy(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) { s.Delivery = db.DeliveryCDN })
	s := e.session("viewer-1")
	_, media := mediaOf(e, s, "240p")
	for _, u := range uris(t, media.body) {
		if strings.Contains(u, "://") || strings.Contains(u, "?") {
			t.Fatalf("proxy fallback produced an absolute or signed URI: %q", u)
		}
	}
}

func TestCDNURLsNeverReachTheLogs(t *testing.T) {
	e := cdnEnv(t, func(s *db.PlaybackSettings) { s.TokenInURL = true })
	s := e.session("viewer-1")
	q := "?t=" + url.QueryEscape(s.token)
	p := "/v1/play/" + s.id
	r := e.do("GET", p+"/240p/media.m3u8"+q, nil)
	want(t, r, 200)
	initURL, _ := mediaURIs(t, r.body)
	e.do("GET", p+"/999p/media.m3u8"+q, nil)
	e.revoke(s.id)
	e.do("GET", p+"/240p/media.m3u8"+q, nil)

	logs := e.logs.String()
	if logs == "" {
		t.Fatal("nothing was logged: the test proves nothing")
	}
	u, _ := url.Parse(initURL)
	for name, secret := range map[string]string{ //nolint:gosec // G101: names of strings that must not be logged
		"signature param": "Signature=", "key name": "KeyName=", "signature value": u.Query().Get("Signature"),
		"object path": u.Path, "token": s.token, "session ID": s.id,
	} {
		if strings.Contains(logs, secret) {
			t.Errorf("the log contains the %s", name)
		}
	}
}
