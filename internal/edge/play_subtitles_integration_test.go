//go:build integration

package edge_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

const trackText = "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nHello\n\n"

// addTrack stores a track of the asset the way the subtitle service does: the object in the
// delivery bucket and the metadata row.
func (e *env) addTrack(asset db.Asset, tenant auth.BootstrapResult, lang, label string, def bool, text string) id.SubtitleID {
	e.t.Helper()
	ctx := context.Background()
	tid := id.New[id.SubtitleKind]()
	if err := e.store.Put(ctx, keys.Subtitle(tenant.Tenant.ID, asset.ID, tid), strings.NewReader(text), int64(len(text)), "text/vtt"); err != nil {
		e.t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(text))
	if _, err := e.repos.InsertSubtitle(ctx, db.Subtitle{
		ID: tid, AssetID: asset.ID, TenantID: tenant.Tenant.ID, Language: lang, Label: label, Default: def, Origin: db.SubtitleUpload,
		CueCount: 1, DurationMS: 90_500, SizeBytes: int64(len(text)), SHA256: sum[:],
	}); err != nil {
		e.t.Fatal(err)
	}
	return tid
}

func mediaLines(body []byte) []string {
	var out []string
	for _, l := range lines(body) {
		if strings.HasPrefix(l, "#EXT-X-MEDIA:") {
			out = append(out, l)
		}
	}
	return out
}

func TestSubtitlesAreListedAndServedThroughTheSession(t *testing.T) {
	e := newEnv(t)
	en := e.addTrack(e.asset, e.res, "en", "English", true, trackText)
	fr := e.addTrack(e.asset, e.res, "fr", "Français", false, "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nBonjour\n\n")
	s := e.session("viewer-1")
	base := "/v1/play/" + s.id + "/master.m3u8"

	m := e.get(base, s.token)
	want(t, m, 200)
	media := mediaLines(m.body)
	if len(media) != 2 || !strings.Contains(media[0], `NAME="English",LANGUAGE="en",DEFAULT=YES`) || !strings.Contains(media[1], `NAME="Français",LANGUAGE="fr",DEFAULT=NO`) {
		t.Fatalf("EXT-X-MEDIA lines = %v", media)
	}
	for _, l := range lines(m.body) {
		if strings.HasPrefix(l, "#EXT-X-STREAM-INF:") && !strings.HasSuffix(l, `,SUBTITLES="subs"`) {
			t.Errorf("a variant does not name the subtitle group: %s", l)
		}
	}
	if strings.Contains(string(m.body), s.token) || strings.Contains(string(m.body), "t/ten_") {
		t.Error("the master carries a token or a storage key")
	}
	refs := uris(t, m.body)
	if len(refs) != 4 || refs[0] != "subtitles/"+en.String()+"/media.m3u8" || refs[1] != "subtitles/"+fr.String()+"/media.m3u8" {
		t.Fatalf("uris = %v", refs)
	}

	// The media playlist: one WebVTT segment as long as the video.
	mediaPath := resolve(t, base, refs[0])
	if mediaPath != "/v1/play/"+s.id+"/subtitles/"+en.String()+"/media.m3u8" {
		t.Fatalf("resolved playlist = %q", mediaPath)
	}
	pl := e.get(mediaPath, s.token)
	want(t, pl, 200)
	if pl.hdr.Get("Content-Type") != "application/vnd.apple.mpegurl" || pl.hdr.Get("Cache-Control") != "no-store" || pl.hdr.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("headers = %v", pl.hdr)
	}
	if !strings.Contains(string(pl.body), "#EXTINF:90.500,\ntrack.vtt\n") || !strings.Contains(string(pl.body), "#EXT-X-TARGETDURATION:91\n") || !strings.HasSuffix(string(pl.body), "#EXT-X-ENDLIST\n") {
		t.Fatalf("playlist = %s", pl.body)
	}

	// The file is the stored track, as text/vtt, never cached.
	file := e.get(resolve(t, mediaPath, "track.vtt"), s.token)
	want(t, file, 200)
	if !bytes.Equal(file.body, []byte(trackText)) {
		t.Fatalf("file = %q", file.body)
	}
	if file.hdr.Get("Content-Type") != "text/vtt" || file.hdr.Get("Cache-Control") != "no-store" || file.hdr.Get("Referrer-Policy") != "no-referrer" ||
		file.hdr.Get("Content-Length") == "" {
		t.Fatalf("headers = %v", file.hdr)
	}
	other := e.get("/v1/play/"+s.id+"/subtitles/"+fr.String()+"/track.vtt", s.token)
	want(t, other, 200)
	if !strings.Contains(string(other.body), "Bonjour") {
		t.Fatalf("second track = %q", other.body)
	}

	// Deleting a track makes it vanish from the master and from the routes.
	if _, err := e.repos.DeleteSubtitle(context.Background(), e.res.Tenant.ID, e.asset.ID, en); err != nil {
		t.Fatal(err)
	}
	if got := mediaLines(e.get(base, s.token).body); len(got) != 1 {
		t.Errorf("master after delete lists %d tracks", len(got))
	}
	want(t, e.get(mediaPath, s.token), 404)
	want(t, e.get("/v1/play/"+s.id+"/subtitles/"+en.String()+"/track.vtt", s.token), 404)
}

func TestMasterWithoutSubtitlesIsUnchanged(t *testing.T) {
	e := newEnv(t)
	s := e.session("viewer-1")
	m := e.get("/v1/play/"+s.id+"/master.m3u8", s.token)
	want(t, m, 200)
	if strings.Contains(string(m.body), "SUBTITLES") || strings.Contains(string(m.body), "EXT-X-MEDIA") {
		t.Fatalf("master = %s", m.body)
	}
}

func TestSubtitleURIsCarryTheTokenWhenTheTenantAsksForIt(t *testing.T) {
	e := newEnv(t)
	tid := e.addTrack(e.asset, e.res, "en", "English", false, trackText)
	e.settings(func(s *db.PlaybackSettings) { s.TokenInURL = true })
	s := e.session("viewer-1")
	suffix := "?t=" + url.QueryEscape(s.token)
	master := "/v1/play/" + s.id + "/master.m3u8"

	m := e.do("GET", master+suffix, nil)
	want(t, m, 200)
	refs := uris(t, m.body)
	if len(refs) != 3 || !strings.HasSuffix(refs[0], suffix) {
		t.Fatalf("uris = %v", refs)
	}
	pl := e.do("GET", resolve(t, master, refs[0]), nil)
	want(t, pl, 200)
	fileRef := uris(t, pl.body)
	if len(fileRef) != 1 || fileRef[0] != "track.vtt"+suffix {
		t.Fatalf("playlist uris = %v", fileRef)
	}
	file := e.do("GET", resolve(t, resolve(t, master, refs[0]), fileRef[0]), nil)
	want(t, file, 200)
	if string(file.body) != trackText {
		t.Fatalf("file = %q", file.body)
	}
	_ = tid
}

func TestSubtitleRoutesCheckWhatThePlaylistsCheck(t *testing.T) {
	e := newEnv(t)
	tid := e.addTrack(e.asset, e.res, "en", "English", false, trackText)
	a, b := e.session("viewer-a"), e.session("viewer-b")
	playlist := "/v1/play/" + a.id + "/subtitles/" + tid.String() + "/media.m3u8"
	file := "/v1/play/" + a.id + "/subtitles/" + tid.String() + "/track.vtt"

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
	var details []string
	for _, path := range []string{playlist, file} {
		for name, tok := range map[string]string{
			"no token":           "",
			"another session":    b.token,
			"segment scope":      mint(token.ScopeSegment, a.id, time.Hour),
			"key scope":          mint(token.ScopeKey, a.id, time.Hour),
			"expired":            mint(token.ScopeManifest, a.id, -time.Second),
			"garbage":            "garbage",
			"manifest, wrong id": mint(token.ScopeManifest, b.id, time.Hour),
		} {
			hdr := map[string]string{}
			if tok != "" {
				hdr = bearer(tok)
			}
			r := e.do("GET", path, hdr)
			if r.status != 401 || r.hdr.Get("WWW-Authenticate") != "Bearer" {
				t.Fatalf("%s on %s: status %d: %s", name, path, r.status, r.body)
			}
			var pb struct{ Code, Detail string }
			if err := json.Unmarshal(r.body, &pb); err != nil {
				t.Fatal(err)
			}
			details = append(details, pb.Code+": "+pb.Detail)
		}
	}
	for _, d := range details[1:] {
		if d != details[0] {
			t.Fatalf("401 details differ:\n%s\n%s", details[0], d)
		}
	}
	// A query token is refused unless the tenant allows it, and both forms together are a 400.
	want(t, e.do("GET", file+"?t="+url.QueryEscape(a.token), nil), 401)
	want(t, e.do("GET", file+"?t="+url.QueryEscape(a.token), bearer(a.token)), 400)

	// A manifest-scope token works on both routes; a revoked session loses both at once (the
	// subtitles are not encrypted, so the session is all that guards them).
	want(t, e.get(playlist, mint(token.ScopeManifest, a.id, time.Hour)), 200)
	want(t, e.get(file, a.token), 200)
	e.revoke(a.id)
	want(t, e.get(playlist, a.token), 401)
	want(t, e.get(file, a.token), 401)
	want(t, e.get("/v1/play/"+b.id+"/subtitles/"+tid.String()+"/track.vtt", b.token), 200)
}

func TestSubtitleRoutesNeverCrossAssetsOrTenants(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	mine := e.addTrack(e.asset, e.res, "en", "Mine", false, trackText)
	// Another asset of the same tenant, and an asset of another tenant, each with a track.
	sibling := readyAsset(t, e.repos, e.res)
	siblingTrack := e.addTrack(sibling, e.res, "en", "Sibling", false, "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nSIBLING-SECRET\n\n")
	otherRes, err := auth.NewManager(e.pool, pepper{}, nil).Bootstrap(ctx, "other", "other client")
	if err != nil {
		t.Fatal(err)
	}
	foreign := readyAsset(t, e.repos, otherRes)
	foreignTrack := e.addTrack(foreign, otherRes, "en", "Foreign", false, "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nFOREIGN-SECRET\n\n")

	s := e.session("viewer-1")
	want(t, e.get("/v1/play/"+s.id+"/subtitles/"+mine.String()+"/track.vtt", s.token), 200)
	for _, tid := range []id.SubtitleID{siblingTrack, foreignTrack} {
		for _, file := range []string{"media.m3u8", "track.vtt"} {
			r := e.get("/v1/play/"+s.id+"/subtitles/"+tid.String()+"/"+file, s.token)
			if r.status != 404 || strings.Contains(string(r.body), "SECRET") {
				t.Fatalf("another asset's or tenant's track on %s: status %d %s", file, r.status, r.body)
			}
		}
	}
	// The master lists only this asset's tracks.
	m := e.get("/v1/play/"+s.id+"/master.m3u8", s.token)
	if got := mediaLines(m.body); len(got) != 1 || strings.Contains(string(m.body), siblingTrack.String()) || strings.Contains(string(m.body), foreignTrack.String()) {
		t.Fatalf("master = %s", m.body)
	}
	// A malformed ID is a 404 before any token is looked at.
	for _, bad := range []string{"nope", "sub_x", "..%2f..", "ast_00000000000000000000000000"} {
		want(t, e.get("/v1/play/"+s.id+"/subtitles/"+bad+"/track.vtt", s.token), 404)
		want(t, e.do("GET", "/v1/play/"+s.id+"/subtitles/"+bad+"/media.m3u8", nil), 404)
	}
}

// Labels and languages are tenant text. Whatever is in the database, the master playlist keeps its
// shape.
func TestSubtitleLabelCannotBreakThePlaylist(t *testing.T) {
	e := newEnv(t)
	e.addTrack(e.asset, e.res, "en\"\n#EXT-X-ENDLIST", "x\",DEFAULT=YES,URI=\"https://evil.example/x\n#EXT-X-KEY:METHOD=NONE", false, trackText)
	s := e.session("viewer-1")
	m := e.get("/v1/play/"+s.id+"/master.m3u8", s.token)
	want(t, m, 200)
	for _, l := range lines(m.body) {
		ok := strings.HasPrefix(l, "#EXT-X-MEDIA:") || strings.HasPrefix(l, "#EXT-X-STREAM-INF:") ||
			l == "#EXTM3U" || l == "#EXT-X-VERSION:7" || l == "#EXT-X-INDEPENDENT-SEGMENTS" || strings.HasSuffix(l, "/media.m3u8")
		if !ok {
			t.Errorf("an injected line: %q", l)
		}
	}
	if got := mediaLines(m.body); len(got) != 1 || strings.Count(got[0], `"`)%2 != 0 || strings.Contains(got[0], "\r") {
		t.Errorf("the EXT-X-MEDIA line is malformed: %v", got)
	}
}

func TestSubtitlePreflight(t *testing.T) {
	e := newEnv(t)
	tid := e.addTrack(e.asset, e.res, "en", "English", false, trackText)
	e.settings(func(s *db.PlaybackSettings) { s.AllowedOrigins = []string{testOrigin} })
	s := e.session("viewer-1")
	for _, file := range []string{"media.m3u8", "track.vtt"} {
		r := e.do("OPTIONS", "/v1/play/"+s.id+"/subtitles/"+tid.String()+"/"+file, map[string]string{
			"Origin": testOrigin, "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "Authorization",
		})
		want(t, r, 204)
		if r.hdr.Get("Access-Control-Allow-Origin") != testOrigin {
			t.Errorf("%s: preflight headers = %v", file, r.hdr)
		}
	}
	got := e.do("GET", "/v1/play/"+s.id+"/subtitles/"+tid.String()+"/track.vtt", map[string]string{"Authorization": "Bearer " + s.token, "Origin": testOrigin})
	want(t, got, 200)
	if got.hdr.Get("Access-Control-Allow-Origin") != testOrigin {
		t.Errorf("CORS header missing on the file: %v", got.hdr)
	}
}
