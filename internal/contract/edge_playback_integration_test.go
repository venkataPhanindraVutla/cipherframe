//go:build integration

package contract

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge"
	"github.com/venkataPhanindraVutla/cipherframe/internal/hls"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/local"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/storagetest"
)

func init() {
	// The playback responses are not JSON: the validator checks their headers and content type,
	// and treats the bodies as opaque bytes.
	for _, ct := range []string{"application/vnd.apple.mpegurl", "video/mp4", "video/iso.segment", "application/octet-stream"} {
		openapi3filter.RegisterBodyDecoder(ct, openapi3filter.FileBodyDecoder)
	}
}

// TestEdgePlaybackOperationsMatchSpec drives the four session-scoped playback operations through
// the real edge handler chain, against a real database and object store, and validates every
// request and response (200 with each content type, 400, 401, 404 and, for the key, 429) against the spec.
func TestEdgePlaybackOperationsMatchSpec(t *testing.T) {
	doc := loadSpec(t)
	ctx := context.Background()
	pool := dbtest.NewMigrated(t)
	repos := db.New(pool)
	mgr := auth.NewManager(pool, onePepper{}, nil)
	res, err := mgr.Bootstrap(ctx, "contract", "contract client")
	if err != nil {
		t.Fatal(err)
	}
	asset := readyAsset(t, repos, res, db.AssetReady)

	buckets, err := storage.New(ctx, storagetest.Shared(t).Config())
	if err != nil {
		t.Fatal(err)
	}
	put := func(key string, body []byte) {
		if err := buckets.Delivery.Put(ctx, key, bytes.NewReader(body), int64(len(body)), "application/octet-stream"); err != nil {
			t.Fatal(err)
		}
	}
	rend, err := keys.ParseRendition("480p")
	if err != nil {
		t.Fatal(err)
	}
	put(keys.InitSegment(res.Tenant.ID, asset.ID, rend), []byte("init-bytes"))
	put(keys.Segment(res.Tenant.ID, asset.ID, rend, 0), bytes.Repeat([]byte{7}, 4096))
	mediaText, err := hls.RenderMedia(hls.MediaPlaylist{InitURI: "init.mp4", Segments: []hls.Segment{{URI: "seg-0.m4s", Duration: 6 * time.Second}}})
	if err != nil {
		t.Fatal(err)
	}
	put(keys.Playlist(res.Tenant.ID, asset.ID, rend), []byte(mediaText))
	masterText, err := hls.RenderMaster([]hls.Variant{{
		URI: "480p/playlist.m3u8", Bandwidth: 1000, AverageBandwidth: 900, Width: 854, Height: 480, Codecs: "avc1.64001f,mp4a.40.2", FrameRate: 30,
	}})
	if err != nil {
		t.Fatal(err)
	}
	put(keys.Master(res.Tenant.ID, asset.ID), []byte(masterText))

	keyring, err := token.NewKeyring(map[int][]byte{1: []byte("test-fixture-playback-token-key-0123456789")}, 1)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := playback.NewService(playback.Deps{Pool: pool, Keyring: keyring, EdgeURL: "https://media.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := svc.CreateSession(ctx, playback.CreateInput{TenantID: res.Tenant.ID, ClientID: res.Client.ID, AssetID: asset.ID, ViewerID: "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	sid, tok := created.SessionID.String(), created.Token.Reveal()

	lp, err := local.NewFromKeys(config.Development, map[int][]byte{1: bytes.Repeat([]byte{0x41}, config.KEKBytes)}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := kms.NewRegistry(lp)
	if err != nil {
		t.Fatal(err)
	}
	keyMgr := contentkey.NewManager(pool, reg, nil)
	if err := db.Tx(ctx, pool, func(tx *db.Repos) error {
		ck, err := keyMgr.Create(ctx, tx, res.Tenant.ID, asset.ID)
		ck.Zero()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	p, err := edge.NewPlayback(edge.PlaybackDeps{Keyring: keyring, Store: repos, Delivery: buckets.Delivery, KeyStore: repos, ContentKeys: keyMgr})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(edge.New(edge.Deps{Log: log, Playback: p}).Handler())
	t.Cleanup(srv.Close)

	covered := map[string]bool{}
	call := func(path string, hdr map[string]string, wantStatus int) {
		t.Helper()
		ex := do(t, srv.URL, "GET", path, hdr)
		if ex.resp.StatusCode != wantStatus {
			t.Fatalf("GET %s: status %d, want %d: %s", path, ex.resp.StatusCode, wantStatus, ex.body)
		}
		if op := validate(t, doc, ex); op != "" && wantStatus == 200 {
			covered[op] = true
		}
	}
	auth := map[string]string{"Authorization": "Bearer " + tok}
	base := "/v1/play/" + sid
	call(base+"/master.m3u8", auth, 200)
	call(base+"/480p/media.m3u8", auth, 200)
	call(base+"/480p/init.mp4", auth, 200)
	call(base+"/480p/seg-0.m4s", auth, 200)

	call(base+"/master.m3u8", nil, 401)
	call(base+"/480p/seg-0.m4s", map[string]string{"Authorization": "Bearer nope"}, 401)
	call(base+"/master.m3u8?t="+url.QueryEscape(tok), nil, 401) // token_in_url is off
	call(base+"/master.m3u8?t="+url.QueryEscape(tok), auth, 400)
	call(base+"/720p/media.m3u8", auth, 404)
	call(base+"/480p/seg-9.m4s", auth, 404)
	// A file name outside the spec's pattern is a request the spec does not allow, and a valid 404.
	// The key: 200, 401 (no token, wrong scope), and 429 after the per-token bound (default 20).
	call(base+"/key", auth, 200)
	call(base+"/key", nil, 401)
	call(base+"/key", map[string]string{"Authorization": "Bearer nope"}, 401)
	call(base+"/key?t="+url.QueryEscape(tok), auth, 400)
	for range 19 {
		if ex := do(t, srv.URL, "GET", base+"/key", auth); ex.resp.StatusCode != 200 {
			t.Fatalf("key status %d: %s", ex.resp.StatusCode, ex.body)
		}
	}
	rl := do(t, srv.URL, "GET", base+"/key", auth)
	if rl.resp.StatusCode != 429 || rl.resp.Header.Get("Retry-After") == "" {
		t.Fatalf("key status %d, Retry-After %q", rl.resp.StatusCode, rl.resp.Header.Get("Retry-After"))
	}
	validate(t, doc, rl)

	ex := do(t, srv.URL, "GET", base+"/480p/other.bin", auth)
	if ex.resp.StatusCode != 404 {
		t.Fatalf("status %d: %s", ex.resp.StatusCode, ex.body)
	}
	validateProblem(t, doc, ex)

	for _, op := range []string{"getPlaybackMaster", "getPlaybackMedia", "getPlaybackSegment", "getPlaybackKey"} {
		if !covered[op] {
			t.Fatalf("%s was not exercised with a 200 response; covered = %v", op, covered)
		}
	}
}
