//go:build integration

package edge_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/hls"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// After a re-key (ADR 0068) a session is bound to the key generation it started on: it reads that
// generation's playlists and segments, and only a session of the asset's current generation gets
// the key. A session that started before the switch is refused the key (401) and starts a new one.
func TestSessionsAreBoundToTheKeyGenerationTheyStartedOn(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	old := e.session("viewer-old") // generation 0

	// What the re-key wrote for generation 1: one other segment and a playlist with another IV.
	r, _ := keys.ParseRendition("240p")
	fresh := []byte("generation one ciphertext")
	if err := e.store.Put(ctx, keys.VariantSegmentGen(e.res.Tenant.ID, e.asset.ID, keys.Original, r, 0, 1), bytes.NewReader(fresh), int64(len(fresh)), "application/octet-stream"); err != nil {
		t.Fatal(err)
	}
	pl, err := hls.RenderMedia(hls.MediaPlaylist{
		InitURI:  "init.mp4",
		Segments: []hls.Segment{{URI: "seg-0.m4s", Duration: 6 * time.Second, IV: hls.IV{0xEE}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.Put(ctx, keys.VariantPlaylistGen(e.res.Tenant.ID, e.asset.ID, keys.Original, r, 1), strings.NewReader(pl), int64(len(pl)), "application/vnd.apple.mpegurl"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `UPDATE assets SET key_generation = 1 WHERE id = $1`, e.asset.ID.UUID()); err != nil {
		t.Fatal(err)
	}

	// The session from before reads generation 0 and no longer gets a key.
	want(t, e.get(keyPath(old), old.token), 401)
	seg := e.get("/v1/play/"+old.id+"/240p/seg-0.m4s", old.token)
	want(t, seg, 200)
	if !bytes.Equal(seg.body, e.objects["240p/seg-0.m4s"]) {
		t.Fatal("a generation 0 session was served another generation's segment")
	}

	// A session started afterwards is on generation 1: its key, playlist and segments.
	cur := e.session("viewer-new")
	want(t, e.get(keyPath(cur), cur.token), 200)
	seg = e.get("/v1/play/"+cur.id+"/240p/seg-0.m4s", cur.token)
	want(t, seg, 200)
	if !bytes.Equal(seg.body, fresh) {
		t.Fatal("a generation 1 session was not served generation 1's segment")
	}
	media := e.get("/v1/play/"+cur.id+"/240p/media.m3u8", cur.token)
	want(t, media, 200)
	if !strings.Contains(string(media.body), "IV=0xEE") {
		t.Fatalf("playlist of another generation: %s", media.body)
	}

	// A heartbeat keeps the generation: the fresh token still reads generation 1.
	e.clk.advance(time.Minute)
	hb := e.beat(cur, cur.token)
	seg = e.get("/v1/play/"+cur.id+"/240p/seg-0.m4s", hb.Token)
	want(t, seg, 200)
	if !bytes.Equal(seg.body, fresh) {
		t.Fatal("the heartbeat token left generation 1")
	}
	want(t, e.get(keyPath(cur), hb.Token), 200)
}
