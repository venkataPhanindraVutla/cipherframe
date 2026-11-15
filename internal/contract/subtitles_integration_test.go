//go:build integration

package contract

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/dsse"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/local"
	"github.com/venkataPhanindraVutla/cipherframe/internal/signing"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/storagetest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/subtitles"
)

// TestSubtitleOperationsMatchSpec drives the five subtitle and transcript operations through the
// real API handler chain, against a real database and object store, and validates every request
// and response (201, 200, 204 and the error statuses) against the spec.
func TestSubtitleOperationsMatchSpec(t *testing.T) {
	doc := loadSpec(t)
	ctx := context.Background()
	pool := dbtest.NewMigrated(t)
	repos := db.New(pool)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	lp, err := local.NewFromKeys(config.Development, map[int][]byte{1: bytes.Repeat([]byte{0x41}, config.KEKBytes)}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := kms.NewRegistry(lp)
	if err != nil {
		t.Fatal(err)
	}
	signer := signing.NewManager(pool, reg, log)
	t.Cleanup(signer.Close)
	if err := signer.EnsureCurrent(ctx); err != nil {
		t.Fatal(err)
	}
	buckets, err := storage.New(ctx, storagetest.Shared(t).Config())
	if err != nil {
		t.Fatal(err)
	}
	svc, err := subtitles.New(subtitles.Deps{Pool: pool, Delivery: buckets.Delivery, Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	am := auth.NewManager(pool, onePepper{}, nil)
	res, err := am.Bootstrap(ctx, "contract", "contract client")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.New(api.Deps{
		Log: log, Verifier: auth.NewVerifier(repos, onePepper{}, log, nil), Manager: am, Signing: signer,
		KeySet: signing.NewKeySet(repos, 1, nil), Repos: repos, Subtitles: svc,
	}).Handler())
	t.Cleanup(srv.Close)

	a := readyAsset(t, repos, res, db.AssetReady)
	if _, err := pool.Exec(ctx, `UPDATE assets SET duration_ms = 600000 WHERE id = $1`, a.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	obj := manifest.StoredObject{Path: "master.m3u8", SHA256: sha256.Sum256([]byte("master")), Size: 6}
	built, err := manifest.Build(manifest.Input{
		AssetID: a.ID.String(), TenantID: res.Tenant.ID.String(), CreatedAt: time.Now(), PipelineVersion: "v0",
		Encoder: manifest.Encoder{FFmpeg: "ffmpeg", VideoCodec: "libx264", Preset: "medium", FrameRate: "25/1", SegmentSeconds: 6, KeyframeSeconds: 2, Encryption: "AES-128"},
		Renditions: []manifest.RenditionInput{{
			Name: "720p", Width: 1280, Height: 720, Bandwidth: 1000, Init: manifest.StoredObject{Path: "720p/init.mp4", SHA256: obj.SHA256, Size: 1},
			Segments: []manifest.StoredObject{{Path: "720p/seg-0.m4s", SHA256: obj.SHA256, Size: 1}},
			Playlist: manifest.StoredObject{Path: "720p/playlist.m3u8", SHA256: obj.SHA256, Size: 1},
		}},
		Master: obj, SourceSHA256: sha256.Sum256([]byte("src")), SourceSize: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	keyID, sig, err := signer.Sign(ctx, dsse.PAE(manifest.PayloadType, built.Canonical))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := (&dsse.Envelope{PayloadType: manifest.PayloadType, Payload: built.Canonical, Signatures: []dsse.Signature{{KeyID: keyID, Sig: sig}}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(built.Canonical)
	if err := repos.InsertManifest(ctx, db.AssetManifest{
		AssetID: a.ID, TenantID: res.Tenant.ID, KeyID: keyID, PayloadSHA256: sum[:], TopRoot: built.TopRoot[:], Envelope: enc,
	}); err != nil {
		t.Fatal(err)
	}

	hdr := map[string]string{"Authorization": "Bearer " + res.Secret.Reveal()}
	covered := map[string]bool{}
	call := func(method, path string, ctype string, body []byte, wantStatus int) []byte {
		t.Helper()
		h := map[string]string{"Authorization": hdr["Authorization"]}
		if ctype != "" {
			h["Content-Type"] = ctype
		}
		ex := doBody(t, srv.URL, method, path, h, body)
		if ex.resp.StatusCode != wantStatus {
			t.Fatalf("%s %s: status %d, want %d: %s", method, path, ex.resp.StatusCode, wantStatus, ex.body)
		}
		if op := validate(t, doc, ex); op != "" && wantStatus < 300 {
			covered[op] = true
		}
		return ex.body
	}
	form := func(file, lang, label string) (string, []byte) {
		const b = "contractboundary"
		var buf strings.Builder
		for _, p := range [][2]string{{"file", file}, {"language", lang}, {"label", label}} {
			buf.WriteString("--" + b + "\r\nContent-Disposition: form-data; name=\"" + p[0] + "\"")
			if p[0] == "file" {
				buf.WriteString("; filename=\"x.vtt\"")
			}
			buf.WriteString("\r\n\r\n" + p[1] + "\r\n")
		}
		buf.WriteString("--" + b + "--\r\n")
		return "multipart/form-data; boundary=" + b, []byte(buf.String())
	}
	json1 := func(v any) []byte { b, _ := json.Marshal(v); return b }

	aid := a.ID.String()
	base := "/v1/assets/" + aid
	const vtt = "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nHello\n"
	ct, body := form(vtt, "en", "English")
	var created struct{ ID string }
	if err := json.Unmarshal(call("POST", base+"/subtitles", ct, body, 201), &created); err != nil {
		t.Fatal(err)
	}
	call("POST", base+"/transcripts", "application/json",
		json1(map[string]any{"language": "fr", "label": "Français", "default": true, "cues": []map[string]any{{"start": 1, "end": 2.5, "text": "Bonjour", "speaker": "Ann"}}}), 201)
	call("GET", base+"/subtitles", "", nil, 200)
	call("GET", base+"/subtitles/"+created.ID, "", nil, 200)

	// Error statuses are valid Problems.
	ct, body = form(vtt, "not a tag", "English")
	call("POST", base+"/subtitles", ct, body, 400)
	ct, body = form("garbage", "en", "English")
	call("POST", base+"/subtitles", ct, body, 400)
	call("POST", base+"/transcripts", "application/json", json1(map[string]any{"language": "en", "label": "x", "cues": []any{}}), 400)
	ct, body = form(vtt, "en", "English")
	call("POST", "/v1/assets/ast_00000000000000000000000001/subtitles", ct, body, 404)
	call("GET", "/v1/assets/ast_00000000000000000000000001/subtitles", "", nil, 404)
	call("GET", base+"/subtitles/sub_00000000000000000000000001", "", nil, 404)
	call("DELETE", base+"/subtitles/sub_00000000000000000000000001", "", nil, 404)
	big := strings.Repeat("x", subtitles.MaxBytes+1)
	ct, body = form("WEBVTT\n\n00:00:01.000 --> 00:00:02.000\n"+big, "en", "English")
	call("POST", base+"/subtitles", ct, body, 413)

	call("DELETE", base+"/subtitles/"+created.ID, "", nil, 204)
	call("GET", base+"/subtitles/"+created.ID, "", nil, 404)

	for _, op := range []string{"createAssetSubtitle", "importAssetTranscript", "listAssetSubtitles", "getAssetSubtitle", "deleteAssetSubtitle"} {
		if !covered[op] {
			t.Errorf("%s was not exercised with a 2xx response; covered = %v", op, covered)
		}
	}
}
