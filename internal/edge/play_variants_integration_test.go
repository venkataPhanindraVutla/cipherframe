//go:build integration

package edge_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/hls"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth/viewerauthtest"
)

// maskedVariant is what enableMasking publishes: the masked variant's own key and bytes.
type maskedVariant struct {
	key   []byte
	init  []byte
	plain []byte // the plaintext of segment 0
	seg   []byte // segment 0 encrypted under key
}

// setMasking marks the env's asset as created with mask_faces and in the given masking state.
func (e *env) setMasking(state string) {
	e.t.Helper()
	if _, err := e.pool.Exec(context.Background(),
		"UPDATE assets SET mask_faces = true, masking_state = $2 WHERE id = $1", e.asset.ID.UUID(), state); err != nil {
		e.t.Fatal(err)
	}
}

// publishMasked gives the asset a masked variant: a second content key and a second HLS tree, with
// one rendition of one segment, all different from the original's.
func (e *env) publishMasked() maskedVariant {
	e.t.Helper()
	ctx := context.Background()
	tn, as := e.res.Tenant.ID, e.asset.ID
	var maskedKey []byte
	if err := db.Tx(ctx, e.pool, func(tx *db.Repos) error {
		k, err := e.mgr.Create(ctx, tx, tn, as, keys.Masked)
		if err != nil {
			return err
		}
		maskedKey = k.Bytes()
		k.Zero()
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
	m := maskedVariant{key: maskedKey, init: randBytes(e.t, 1<<10), plain: randBytes(e.t, segSize)}
	iv := hls.IV{9}
	var err error
	if m.seg, err = hls.EncryptSegment(m.key, iv, m.plain); err != nil {
		e.t.Fatal(err)
	}
	put := func(key string, body []byte) {
		if err := e.store.Put(ctx, key, bytes.NewReader(body), int64(len(body)), "application/octet-stream"); err != nil {
			e.t.Fatal(err)
		}
	}
	r, err := keys.ParseRendition("240p")
	if err != nil {
		e.t.Fatal(err)
	}
	put(keys.VariantInitSegment(tn, as, keys.Masked, r), m.init)
	put(keys.VariantSegment(tn, as, keys.Masked, r, 0), m.seg)
	pl, err := hls.RenderMedia(hls.MediaPlaylist{InitURI: "init.mp4", Segments: []hls.Segment{{URI: "seg-0.m4s", Duration: 6 * time.Second, IV: iv}}})
	if err != nil {
		e.t.Fatal(err)
	}
	put(keys.VariantPlaylist(tn, as, keys.Masked, r), []byte(pl))
	master, err := hls.RenderMaster([]hls.Variant{{
		URI: "240p/playlist.m3u8", Bandwidth: 1000, AverageBandwidth: 900, Width: 426, Height: 240, Codecs: "avc1.64001f,mp4a.40.2", FrameRate: 30,
	}})
	if err != nil {
		e.t.Fatal(err)
	}
	put(keys.VariantMaster(tn, as, keys.Masked), []byte(master))
	return m
}

func (e *env) sessionOf(v keys.Variant) session {
	e.t.Helper()
	c, err := e.svc.CreateSession(context.Background(), playback.CreateInput{
		TenantID: e.res.Tenant.ID, ClientID: e.res.Client.ID, AssetID: e.asset.ID, Variant: v, ViewerID: "viewer-" + string(v),
	})
	if err != nil {
		e.t.Fatal(err)
	}
	if v != "" && c.Variant != v {
		e.t.Fatalf("session variant = %q, want %q", c.Variant, v)
	}
	return session{id: c.SessionID.String(), token: c.Token.Reveal()}
}

// A session reads the playlists, the segments and the key of its own variant and of no other.
func TestVariantSessionsServeOnlyTheirOwnVariant(t *testing.T) {
	e := newEnv(t)
	e.setMasking(db.MaskingReady)
	m := e.publishMasked()

	orig := e.sessionOf(keys.Original)
	msk := e.sessionOf("") // the default for a masking asset
	if row := e.row(msk); row.Variant != keys.Masked {
		t.Fatalf("default session row: %+v", row)
	}

	// The master playlists differ: the original has two renditions, the masked one.
	om := e.get("/v1/play/"+orig.id+"/master.m3u8", orig.token)
	mm := e.get("/v1/play/"+msk.id+"/master.m3u8", msk.token)
	want(t, om, 200)
	want(t, mm, 200)
	if len(uris(t, om.body)) != 2 || len(uris(t, mm.body)) != 1 {
		t.Fatalf("masters: original %v, masked %v", uris(t, om.body), uris(t, mm.body))
	}
	// The masked session cannot reach the original's 720p rendition; the original session cannot
	// reach anything the masked tree has that the original lacks.
	want(t, e.get("/v1/play/"+msk.id+"/720p/media.m3u8", msk.token), 404)
	want(t, e.get("/v1/play/"+msk.id+"/720p/seg-0.m4s", msk.token), 404)

	// Segments: the same path, different bytes, each its own variant's.
	oi := e.get("/v1/play/"+orig.id+"/240p/init.mp4", orig.token)
	mi := e.get("/v1/play/"+msk.id+"/240p/init.mp4", msk.token)
	want(t, oi, 200)
	want(t, mi, 200)
	if !bytes.Equal(oi.body, e.objects["240p/init.mp4"]) || !bytes.Equal(mi.body, m.init) || bytes.Equal(oi.body, mi.body) {
		t.Fatal("an init segment came from the wrong variant")
	}
	os0 := e.get("/v1/play/"+orig.id+"/240p/seg-0.m4s", orig.token)
	ms0 := e.get("/v1/play/"+msk.id+"/240p/seg-0.m4s", msk.token)
	want(t, os0, 200)
	want(t, ms0, 200)
	if !bytes.Equal(os0.body, e.objects["240p/seg-0.m4s"]) || !bytes.Equal(ms0.body, m.seg) || bytes.Equal(os0.body, ms0.body) {
		t.Fatal("a media segment came from the wrong variant")
	}

	// Keys: each session gets its own variant's key, and the other one does not decrypt.
	ok := e.get(keyPath(orig), orig.token)
	mk := e.get(keyPath(msk), msk.token)
	want(t, ok, 200)
	want(t, mk, 200)
	if !bytes.Equal(ok.body, e.key) || !bytes.Equal(mk.body, m.key) || bytes.Equal(ok.body, mk.body) {
		t.Fatal("a session got the key of the wrong variant")
	}
	if _, err := hls.DecryptSegment(mk.body, hls.IV{9}, ms0.body); err != nil {
		t.Fatalf("the masked key does not decrypt the masked segment: %v", err)
	}
	if got, err := hls.DecryptSegment(ok.body, hls.IV{9}, ms0.body); err == nil && bytes.Equal(got, m.plain) {
		t.Fatal("the original key decrypts the masked segment")
	}
	if got, err := hls.DecryptSegment(mk.body, hls.IV{1}, os0.body); err == nil && bytes.Equal(got, e.plain["240p/seg-0.m4s"]) {
		t.Fatal("the masked key decrypts the original segment")
	}

	// A token that names the other variant than the session row is refused where the row is read.
	forged, err := e.keyring.Sign(token.Claims{
		SessionID: msk.id, AssetID: e.asset.ID.String(), TenantID: e.res.Tenant.ID.String(), Variant: keys.Original.String(),
		Scopes: token.ScopeManifest | token.ScopeKey | token.ScopeSegment, IssuedAt: e.clk.Now(), Expiry: e.clk.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	want(t, e.get("/v1/play/"+msk.id+"/master.m3u8", forged), 401)
	want(t, e.get(keyPath(msk), forged), 401)
	// And an unknown variant in a token is never served.
	bogus, err := e.keyring.Sign(token.Claims{
		SessionID: msk.id, AssetID: e.asset.ID.String(), TenantID: e.res.Tenant.ID.String(), Variant: "other",
		Scopes: token.ScopeManifest | token.ScopeKey | token.ScopeSegment, IssuedAt: e.clk.Now(), Expiry: e.clk.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	want(t, e.get("/v1/play/"+msk.id+"/240p/seg-0.m4s", bogus), 401)

	// A heartbeat keeps the session on its variant.
	e.clk.advance(time.Minute)
	fresh := e.beat(msk, msk.token)
	if got := e.get("/v1/play/"+msk.id+"/240p/seg-0.m4s", fresh.Token); !bytes.Equal(got.body, m.seg) {
		t.Fatal("the refreshed token reads another variant")
	}
}

func TestSessionVariantResolution(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) { s.MaxSessionsPerViewer = 0 })
	create := func(v keys.Variant) error {
		_, err := e.svc.CreateSession(context.Background(), playback.CreateInput{
			TenantID: e.res.Tenant.ID, ClientID: e.res.Client.ID, AssetID: e.asset.ID, Variant: v, ViewerID: "viewer-r",
		})
		return err
	}
	code := func(err error) errs.Code {
		var ee *errs.Error
		if err == nil {
			return ""
		}
		if !errors.As(err, &ee) {
			t.Fatalf("not an app error: %v", err)
		}
		return ee.Code
	}

	// An asset without masking: only the original.
	if err := create(""); err != nil {
		t.Fatal(err)
	}
	if got := code(create(keys.Masked)); got != errs.VariantUnavailable {
		t.Fatalf("masked on a plain asset: %q", got)
	}
	if got := code(create("other")); got != errs.InvalidRequest {
		t.Fatalf("unknown variant: %q", got)
	}

	// A masking asset: the default is masked, and it never falls back to the original.
	for _, state := range []string{db.MaskingPending, db.MaskingFailed} {
		e.setMasking(state)
		if got := code(create("")); got != errs.VariantNotReady {
			t.Fatalf("default while %s: %q", state, got)
		}
		if got := code(create(keys.Masked)); got != errs.VariantNotReady {
			t.Fatalf("masked while %s: %q", state, got)
		}
		if err := create(keys.Original); err != nil { // asking for the original is explicit and allowed
			t.Fatalf("original while %s: %v", state, err)
		}
	}
	e.setMasking(db.MaskingReady)
	if err := create(""); err != nil {
		t.Fatal(err)
	}
}

// The viewer never chooses the variant: the embedding application does, with a JWT claim or by
// approving the variant it is told about in the callback.
func TestBrowserSessionVariantIsDecidedByTheApplication(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *db.PlaybackSettings) { s.MaxSessionsPerViewer = 0 })
	e.setMasking(db.MaskingReady)
	e.publishMasked()
	e.enableJWT("")
	k := viewerauthtest.NewKey(t, "EdDSA", "key-variant")
	e.uploadKey(k)

	variantOf := func(r reply) string {
		t.Helper()
		want(t, r, 201)
		v, _ := decode(t, r)["variant"].(string)
		return v
	}
	jwtWith := func(variant any, body map[string]any) reply {
		c := e.claims("viewer-v")
		if variant != nil {
			c["variant"] = variant
		}
		body["asset_id"], body["method"] = e.asset.ID.String(), "jwt"
		return e.postJSON(e.sessionsPath(), body, bearer(k.Sign(t, c)))
	}

	// No claim: the asset's default, masked.
	if got := variantOf(jwtWith(nil, map[string]any{})); got != "masked" {
		t.Fatalf("no claim: %q", got)
	}
	// The application's claim wins.
	if got := variantOf(jwtWith("original", map[string]any{})); got != "original" {
		t.Fatalf("claim original: %q", got)
	}
	if got := variantOf(jwtWith("masked", map[string]any{"variant": "masked"})); got != "masked" {
		t.Fatalf("claim masked, body masked: %q", got)
	}
	// A body that asks for something else than the application decided is a 403, whichever way.
	want(t, jwtWith(nil, map[string]any{"variant": "original"}), 403)
	want(t, jwtWith("masked", map[string]any{"variant": "original"}), 403)
	want(t, jwtWith("original", map[string]any{"variant": "masked"}), 403)
	// A claim that is not a variant is a plain denial.
	want(t, jwtWith("sepia", map[string]any{}), 401)
	want(t, jwtWith(7, map[string]any{}), 401)

	// A masked claim for an asset that has no masked variant is a 409, not a fallback.
	e.setMasking(db.MaskingPending)
	r := jwtWith("masked", map[string]any{})
	want(t, r, 409)
	if decode(t, r)["code"] != string(errs.VariantNotReady) {
		t.Fatalf("pending: %s", r.body)
	}
	if got := variantOf(jwtWith("original", map[string]any{})); got != "original" {
		t.Fatalf("claim original while pending: %q", got)
	}
	if _, err := e.pool.Exec(context.Background(), "UPDATE assets SET mask_faces = false, masking_state = NULL WHERE id = $1", e.asset.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	r = jwtWith("masked", map[string]any{})
	want(t, r, 409)
	if decode(t, r)["code"] != string(errs.VariantUnavailable) {
		t.Fatalf("no masking: %s", r.body)
	}
	e.setMasking(db.MaskingReady)

	// Callback: the tenant is told the variant, and the viewer cannot pick another one.
	rec := &recorder{h: answer(200, allowAnswer)}
	srv := e.tlsServer(rec)
	e.rotate()
	e.enableCallback(srv.URL + "/authorize-test-fixture")
	told := func() string {
		_, _, body := rec.last()
		var got map[string]string
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		return got["variant"]
	}
	if got := variantOf(e.viaCallback(vTicket)); got != "masked" || told() != "masked" {
		t.Fatalf("callback: session %q, told %q", got, told())
	}
	want(t, e.postJSON(e.sessionsPath(), map[string]any{"asset_id": e.asset.ID.String(), "method": "callback", "ticket": vTicket, "variant": "original"}, nil), 403)
	if got := variantOf(e.postJSON(e.sessionsPath(), map[string]any{"asset_id": e.asset.ID.String(), "method": "callback", "ticket": vTicket, "variant": "masked"}, nil)); got != "masked" {
		t.Fatalf("callback with the decided variant: %q", got)
	}
	// An asset without masking: the callback is told "original".
	if _, err := e.pool.Exec(context.Background(), "UPDATE assets SET mask_faces = false, masking_state = NULL WHERE id = $1", e.asset.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	if got := variantOf(e.viaCallback(vTicket)); got != "original" || told() != "original" {
		t.Fatalf("callback on a plain asset: session %q, told %q", got, told())
	}
}
