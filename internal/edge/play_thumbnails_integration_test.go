//go:build integration

package edge_test

import (
	"bytes"
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// thumbs are the three objects of one variant, each carrying the variant's name so a test can tell
// whose image it got.
type thumbs struct{ poster, sprite, track []byte }

func thumbsOf(variant keys.Variant) thumbs {
	return thumbs{
		poster: []byte("\xff\xd8\xff-poster-of-" + variant.String()),
		sprite: []byte("\xff\xd8\xff-sprite-of-" + variant.String()),
		track:  []byte("WEBVTT\n\n00:00:00.000 --> 00:00:10.000\nsprite.jpg#xywh=0,0,160,90\n\n00:00:10.000 --> 00:00:14.000\nsprite.jpg#xywh=160,0,160,90\n"),
	}
}

// putThumbs stores a variant's poster, sprite sheet and track where the pipeline does.
func (e *env) putThumbs(variant keys.Variant) thumbs {
	e.t.Helper()
	th := thumbsOf(variant)
	tn, as := e.res.Tenant.ID, e.asset.ID
	for _, o := range []struct {
		key  string
		body []byte
		typ  string
	}{
		{keys.VariantPoster(tn, as, variant), th.poster, "image/jpeg"},
		{keys.VariantSprite(tn, as, variant), th.sprite, "image/jpeg"},
		{keys.VariantThumbnails(tn, as, variant), th.track, "text/vtt"},
	} {
		if err := e.store.Put(context.Background(), o.key, bytes.NewReader(o.body), int64(len(o.body)), o.typ); err != nil {
			e.t.Fatal(err)
		}
	}
	return th
}

func thumbPaths(s session) (poster, sprite, track string) {
	base := "/v1/play/" + s.id + "/"
	return base + "poster.jpg", base + "sprite.jpg", base + "thumbnails.vtt"
}

func TestThumbnailsAreServedThroughTheSession(t *testing.T) {
	e := newEnv(t)
	th := e.putThumbs(keys.Original)
	s := e.session("viewer-1")
	poster, sprite, track := thumbPaths(s)

	for _, c := range []struct {
		path, typ string
		body      []byte
	}{{poster, "image/jpeg", th.poster}, {sprite, "image/jpeg", th.sprite}, {track, "text/vtt", th.track}} {
		r := e.get(c.path, s.token)
		want(t, r, 200)
		if !bytes.Equal(r.body, c.body) || r.hdr.Get("Content-Type") != c.typ || r.hdr.Get("Cache-Control") != "no-store" ||
			r.hdr.Get("Referrer-Policy") != "no-referrer" || r.hdr.Get("Content-Length") == "" {
			t.Errorf("%s: type %q, cache %q, %d bytes", c.path, r.hdr.Get("Content-Type"), r.hdr.Get("Cache-Control"), len(r.body))
		}
	}

	// The cues name the sprite relatively: it resolves to the session's own sprite route.
	if got := resolve(t, track, "sprite.jpg"); got != sprite {
		t.Errorf("the track's sprite resolves to %q, want %q", got, sprite)
	}

	// The same guard as the media playlists: a token, a usable session, the manifest scope.
	for _, p := range []string{poster, sprite, track} {
		want(t, e.do("GET", p, nil), 401)
		want(t, e.get(p, "not-a-token"), 401)
		want(t, e.get(p, e.sign(s, token.ScopeSegment, time.Minute)), 401) // a segment-scope token is not enough
		want(t, e.get(p, e.sign(s, token.ScopeKey, time.Minute)), 401)
	}
	other := e.session("viewer-2")
	for _, p := range []string{poster, sprite, track} {
		want(t, e.get(p, other.token), 401) // a token of another session
	}
	e.revoke(s.id)
	for _, p := range []string{poster, sprite, track} {
		want(t, e.get(p, s.token), 401)
	}
	// Unknown names under the session are not routes.
	want(t, e.get("/v1/play/"+other.id+"/banner.jpg", other.token), 404)
	want(t, e.get("/v1/play/"+other.id+"/poster.jpg/extra", other.token), 404)
}

func TestAssetWithoutThumbnailsAnswers404(t *testing.T) {
	e := newEnv(t)
	s := e.session("viewer-1")
	for _, p := range []string{"poster.jpg", "sprite.jpg", "thumbnails.vtt"} {
		want(t, e.get("/v1/play/"+s.id+"/"+p, s.token), 404)
	}
}

func TestThumbnailTrackCarriesTheTokenWhenTheTenantAsksForIt(t *testing.T) {
	e := newEnv(t)
	e.putThumbs(keys.Original)
	e.settings(func(s *db.PlaybackSettings) { s.TokenInURL = true })
	s := e.session("viewer-1")
	_, _, track := thumbPaths(s)
	suffix := "?t=" + url.QueryEscape(s.token)

	r := e.do("GET", track+suffix, nil)
	want(t, r, 200)
	if got := strings.Count(string(r.body), "sprite.jpg?t="+url.QueryEscape(s.token)+"#xywh="); got != 2 {
		t.Fatalf("%d sprite references carry the token:\n%s", got, r.body)
	}
	// The rewritten reference works as written, and fails without a token.
	ref := resolve(t, track, "sprite.jpg?t="+url.QueryEscape(s.token))
	want(t, e.do("GET", ref, nil), 200)
	want(t, e.do("GET", strings.SplitN(ref, "?", 2)[0], nil), 401)
	// Without token_in_url the header is the only way in and the track holds no token.
	e.settings(func(s *db.PlaybackSettings) { s.TokenInURL = false })
	plain := e.get(track, s.token)
	want(t, plain, 200)
	if strings.Contains(string(plain.body), "?t=") {
		t.Errorf("the track holds a token although tokens in URLs are off:\n%s", plain.body)
	}
	want(t, e.do("GET", track+suffix, nil), 401)
}

// A session bound to the masked variant gets the masked variant's images and never the original's,
// not even when the masked variant has none (invariant: faces are personal data, ADR 0036).
func TestMaskedSessionNeverGetsOriginalImages(t *testing.T) {
	e := newEnv(t)
	e.setMasking(db.MaskingReady)
	e.publishMasked()
	orig := e.putThumbs(keys.Original)
	msk := e.sessionOf("")
	if row := e.row(msk); row.Variant != keys.Masked {
		t.Fatalf("session row: %+v", row)
	}
	poster, sprite, track := thumbPaths(msk)

	// The masked variant has no images yet: 404, never the original's.
	for _, p := range []string{poster, sprite, track} {
		r := e.get(p, msk.token)
		want(t, r, 404)
		if bytes.Contains(r.body, []byte("-of-original")) {
			t.Fatal("a masked session was answered with an original image")
		}
	}

	masked := e.putThumbs(keys.Masked)
	for _, c := range []struct {
		path string
		body []byte
		bad  []byte
	}{{poster, masked.poster, orig.poster}, {sprite, masked.sprite, orig.sprite}} {
		r := e.get(c.path, msk.token)
		want(t, r, 200)
		if !bytes.Equal(r.body, c.body) || bytes.Equal(r.body, c.bad) {
			t.Errorf("%s: masked session got %q", c.path, r.body)
		}
	}
	// The original session still gets its own.
	os := e.sessionOf(keys.Original)
	op, osp, _ := thumbPaths(os)
	if r := e.get(op, os.token); !bytes.Equal(r.body, orig.poster) {
		t.Errorf("original session poster = %q", r.body)
	}
	if r := e.get(osp, os.token); !bytes.Equal(r.body, orig.sprite) {
		t.Errorf("original session sprite = %q", r.body)
	}
	// A token that says original on a masked session's row is refused where the row is read.
	forged, err := e.keyring.Sign(token.Claims{
		SessionID: msk.id, AssetID: e.asset.ID.String(), TenantID: e.res.Tenant.ID.String(), Variant: keys.Original.String(),
		Scopes: token.ScopeManifest, IssuedAt: e.clk.Now(), Expiry: e.clk.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{poster, sprite, track} {
		want(t, e.get(p, forged), 401)
	}
}

// Thumbnails are images of faces and unencrypted: they are always served by the edge, even when the
// tenant's segments are presigned, and no thumbnail URL is ever a storage URL (ADR 0032, 0046).
func TestPresignedTenantsStillGetProxiedThumbnails(t *testing.T) {
	e := newEnv(t)
	e.presigned()
	th := e.putThumbs(keys.Original)
	s := e.session("viewer-1")
	poster, sprite, track := thumbPaths(s)

	for _, c := range []struct {
		path string
		body []byte
	}{{poster, th.poster}, {sprite, th.sprite}, {track, th.track}} {
		r := e.get(c.path, s.token)
		want(t, r, 200) // served here: not a redirect to storage
		if !bytes.Equal(r.body, c.body) || r.hdr.Get("Location") != "" {
			t.Errorf("%s: %d bytes, location %q", c.path, len(r.body), r.hdr.Get("Location"))
		}
		if strings.Contains(string(r.body), "X-Amz-") || strings.Contains(string(r.body), "http") {
			t.Errorf("%s names a storage URL", c.path)
		}
	}
	// The master and the media playlists of a presigned tenant do not mention thumbnails or storage
	// for them; only the segments are presigned.
	m := e.get("/v1/play/"+s.id+"/master.m3u8", s.token)
	want(t, m, 200)
	if strings.Contains(string(m.body), "poster") || strings.Contains(string(m.body), "sprite") || strings.Contains(string(m.body), "thumbnails") {
		t.Errorf("the master playlist mentions thumbnails:\n%s", m.body)
	}
	// A request for the thumbnails does not need a presign-capable token lifetime either: a token
	// about to expire is a plain 401 or 200, never a presigned redirect.
	short := e.sign(s, token.ScopeManifest, 3*time.Second)
	if r := e.get(poster, short); r.status != 200 || !bytes.Equal(r.body, th.poster) {
		t.Errorf("short-lived token: status %d", r.status)
	}
}

func TestThumbnailPreflightNeedsNoToken(t *testing.T) {
	e := newEnv(t)
	s := e.session("viewer-1")
	poster, _, track := thumbPaths(s)
	for _, p := range []string{poster, track} {
		r := e.do("OPTIONS", p, map[string]string{"Origin": "https://example.invalid", "Access-Control-Request-Method": "GET"})
		want(t, r, 204)
	}
}
