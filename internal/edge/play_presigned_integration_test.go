//go:build integration

package edge_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/hls"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
)

// Presigned delivery (ADR 0032, M4-5): media playlists carry presigned storage URLs for the init
// and media segments; everything else is as in proxy mode.

func (e *env) presigned() {
	e.t.Helper()
	e.settings(func(s *db.PlaybackSettings) { s.Delivery = db.DeliveryPresigned })
}

// plainGet fetches a URL with a client that sends nothing but the request: no token, no cookies.
func plainGet(t *testing.T, raw string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("plain GET failed: %v", errNoURL(err))
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, b
}

// errNoURL keeps a presigned URL out of a test failure message.
func errNoURL(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}

// mediaURIs returns the init URI, and the media segment URIs in order, of a media playlist.
func mediaURIs(t *testing.T, body []byte) (init string, segs []string) {
	t.Helper()
	for _, l := range lines(body) {
		switch {
		case strings.HasPrefix(l, "#EXT-X-MAP:URI=\""):
			init = strings.TrimSuffix(strings.TrimPrefix(l, "#EXT-X-MAP:URI=\""), "\"")
		case !strings.HasPrefix(l, "#"):
			segs = append(segs, l)
		}
	}
	if init == "" || len(segs) != segCount {
		t.Fatalf("init %v, %d segments", init != "", len(segs))
	}
	return init, segs
}

func mediaOf(e *env, s session, rendition string) (path string, r reply) {
	e.t.Helper()
	path = "/v1/play/" + s.id + "/" + rendition + "/media.m3u8"
	r = e.get(path, s.token)
	want(e.t, r, 200)
	return path, r
}

// expiryOf returns the lifetime in seconds and the signing time of a presigned URL.
func expiryOf(t *testing.T, raw string) (time.Time, time.Duration) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal("unparsable presigned URL")
	}
	q := u.Query()
	signed, err := time.Parse("20060102T150405Z", q.Get("X-Amz-Date"))
	if err != nil {
		t.Fatalf("X-Amz-Date: %v", err)
	}
	n, err := strconv.Atoi(q.Get("X-Amz-Expires"))
	if err != nil {
		t.Fatalf("X-Amz-Expires: %v", err)
	}
	return signed, time.Duration(n) * time.Second
}

func TestPresignedPlaylistServesStorageURLsAndDecrypts(t *testing.T) {
	e := newEnv(t)
	e.presigned()
	s := e.session("viewer-1")
	mediaPath, media := mediaOf(e, s, "240p")

	// The master playlist is unchanged.
	m := e.get("/v1/play/"+s.id+"/master.m3u8", s.token)
	want(t, m, 200)
	if v := uris(t, m.body); len(v) != 2 || v[0] != "240p/media.m3u8" || strings.Contains(string(m.body), "?") {
		t.Fatalf("master playlist changed: %v", v)
	}

	initURL, segURLs := mediaURIs(t, media.body)
	// The key stays on edge, without a token in the URL.
	matches := reKeyIV.FindAllStringSubmatch(string(media.body), -1)
	if len(matches) != segCount || matches[0][1] != "../key" {
		t.Fatalf("key tags: %v", matches)
	}
	for _, u := range append([]string{initURL}, segURLs...) {
		p, err := url.Parse(u)
		if err != nil || !p.IsAbs() || strings.HasPrefix(u, e.srv.URL) || p.Query().Get("X-Amz-Signature") == "" {
			t.Fatalf("segment URI is not a presigned storage URL")
		}
	}

	// Every presigned URL answers a plain request with exactly the stored ciphertext.
	status, body := plainGet(t, initURL)
	if status != 200 || !bytes.Equal(body, e.objects["240p/init.mp4"]) {
		t.Fatalf("init: status %d", status)
	}
	k := e.get(resolve(t, mediaPath, matches[0][1]), s.token)
	want(t, k, 200)
	for i, u := range segURLs {
		status, body := plainGet(t, u)
		name := fmt.Sprintf("240p/seg-%d.m4s", i)
		if status != 200 || !bytes.Equal(body, e.objects[name]) {
			t.Fatalf("%s: status %d, bytes equal %v", name, status, bytes.Equal(body, e.objects[name]))
		}
		// And with the key from the key endpoint they decrypt to the plaintext.
		raw, err := hex.DecodeString(matches[i][2])
		if err != nil {
			t.Fatal(err)
		}
		var iv hls.IV
		copy(iv[:], raw)
		plain, err := hls.DecryptSegment(k.body, iv, body)
		if err != nil || !bytes.Equal(plain, e.plain[name]) {
			t.Fatalf("%s: decrypt failed or differs: %v", name, err)
		}
	}

	// The proxy route keeps working in this mode.
	seg := e.get(resolve(t, mediaPath, "seg-0.m4s"), s.token)
	want(t, seg, 200)
	if !bytes.Equal(seg.body, e.objects["240p/seg-0.m4s"]) {
		t.Fatal("proxy segment differs in presigned mode")
	}
}

func TestPresignedExpiryNeverExceedsTokenExpiry(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) { s.Delivery = db.DeliveryPresigned; s.TokenTTLSeconds = 3600 })
	s := e.session("viewer-1")
	// A one-hour token: the URL is capped at ten minutes.
	_, media := mediaOf(e, s, "720p")
	initURL, segURLs := mediaURIs(t, media.body)
	claims, err := e.keyring.Open(s.token, e.clk.Now(), token.ScopeManifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range append([]string{initURL}, segURLs...) {
		signed, life := expiryOf(t, u)
		if life != 10*time.Minute {
			t.Fatalf("lifetime = %s, want 10m", life)
		}
		if signed.Add(life).After(claims.Expiry) {
			t.Fatal("the URL outlives the token")
		}
	}

	// A token with 5 minutes left: the URL ends no later than the token.
	short := e.sign(s, token.ScopeManifest, 5*time.Minute)
	r := e.get("/v1/play/"+s.id+"/720p/media.m3u8", short)
	want(t, r, 200)
	sc, err := e.keyring.Open(short, e.clk.Now(), token.ScopeManifest)
	if err != nil {
		t.Fatal(err)
	}
	initURL, _ = mediaURIs(t, r.body)
	signed, life := expiryOf(t, initURL)
	if life > 5*time.Minute || life < 4*time.Minute || signed.Add(life).After(sc.Expiry) {
		t.Fatalf("lifetime %s for a 5 minute token", life)
	}
}

// With about two seconds left on the token, the URL works at once and storage refuses it after
// its expiry; with under a second left, the playlist is refused.
func TestPresignedURLExpiresInStorage(t *testing.T) {
	e := newEnv(t)
	e.presigned()
	s := e.session("viewer-1")
	tok := e.sign(s, token.ScopeManifest, 3*time.Second) // 2 to 3 seconds are left when it is used
	r := e.get("/v1/play/"+s.id+"/240p/media.m3u8", tok)
	want(t, r, 200)
	initURL, _ := mediaURIs(t, r.body)
	signed, life := expiryOf(t, initURL)
	if life < time.Second || life > 3*time.Second {
		t.Fatalf("lifetime = %s", life)
	}
	if status, _ := plainGet(t, initURL); status != 200 {
		t.Fatalf("fresh URL: status %d", status)
	}
	time.Sleep(time.Until(signed.Add(life)) + 2*time.Second)
	if status, _ := plainGet(t, initURL); status != 403 {
		t.Fatalf("expired URL: status %d, want 403", status)
	}

	// Less than a second left: unauthorized, not a URL that dies at once. The token is valid for
	// this request (the guard may or may not pass it) but cannot be given a usable URL.
	tok = e.sign(s, token.ScopeManifest, 1*time.Second)
	want(t, e.get("/v1/play/"+s.id+"/240p/media.m3u8", tok), 401)
}

func TestDeliverySettingSwitchTakesEffectAfterTheCacheTTL(t *testing.T) {
	e := newEnv(t)
	s := e.session("viewer-1")
	path := "/v1/play/" + s.id + "/240p/media.m3u8"
	proxied := func() {
		t.Helper()
		r := e.get(path, s.token)
		want(t, r, 200)
		for _, u := range uris(t, r.body) {
			if strings.Contains(u, "://") || strings.Contains(u, "?") {
				t.Fatalf("proxy mode produced an absolute or signed URI: %q", u)
			}
		}
	}
	proxied() // the default, and the settings are now cached

	// Written to the database but not yet seen: the cache still answers (within its TTL).
	set := db.DefaultPlaybackSettings()
	set.Delivery = db.DeliveryPresigned
	if _, err := e.repos.PutPlaybackSettings(context.Background(), e.res.Tenant.ID, set, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	proxied()
	e.clk.advance(playbackCacheTTL)
	r := e.get(path, s.token)
	want(t, r, 200)
	if init, _ := mediaURIs(t, r.body); !strings.Contains(init, "X-Amz-Signature=") {
		t.Fatal("presigned mode did not take effect after the cache TTL")
	}

	// And back.
	set.Delivery = db.DeliveryProxy
	if _, err := e.repos.PutPlaybackSettings(context.Background(), e.res.Tenant.ID, set, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	e.clk.advance(playbackCacheTTL)
	proxied()
}

func TestPresignedURLsAndTokensNeverReachTheLogs(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) { s.Delivery = db.DeliveryPresigned; s.TokenInURL = true })
	s := e.session("viewer-1")
	q := "?t=" + url.QueryEscape(s.token)
	p := "/v1/play/" + s.id
	r := e.do("GET", p+"/240p/media.m3u8"+q, nil)
	want(t, r, 200)
	initURL, _ := mediaURIs(t, r.body)
	plainGet(t, initURL)
	e.do("GET", p+"/240p/media.m3u8?t=garbage", nil)
	e.do("GET", p+"/999p/media.m3u8"+q, nil)
	// A segment fetch that fails storage-side must not leak the URL either.
	e.revoke(s.id)
	e.do("GET", p+"/240p/media.m3u8"+q, nil)

	logs := e.logs.String()
	if logs == "" {
		t.Fatal("nothing was logged: the test proves nothing")
	}
	u, _ := url.Parse(initURL)
	//nolint:gosec // G101: the map names strings that must not appear in logs; none is a credential
	for name, secret := range map[string]string{
		"signature": "X-Amz-Signature", "credential": "X-Amz-Credential", "signature value": u.Query().Get("X-Amz-Signature"),
		"object path": u.Path, "token": s.token, "session ID": s.id,
	} {
		if strings.Contains(logs, secret) {
			t.Errorf("the log contains the %s", name)
		}
	}
}
