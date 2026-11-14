// Package offlinetest builds a synthetic HLS tree with a signed manifest and a key set, for tests
// of the offline verifier. It is test support: it creates keys, which the verifier never needs.
package offlinetest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/dsse"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
)

// Key is a signing key of a fixture.
type Key struct {
	ID   string
	Priv ed25519.PrivateKey
}

// NewKey returns a deterministic test key from seed.
func NewKey(id, seed string) Key {
	s := sha256.Sum256([]byte("test-fixture-" + seed))
	return Key{id, ed25519.NewKeyFromSeed(s[:])}
}

// KeySetJSON returns a published-format key set. statuses maps key id to "active" or "retired".
func KeySetJSON(keys []Key, statuses map[string]string) []byte {
	type k struct {
		KeyID     string `json:"keyid"`
		Alg       string `json:"alg"`
		PublicKey string `json:"public_key"`
		Status    string `json:"status"`
		CreatedAt string `json:"created_at"`
	}
	var out struct {
		Keys []k `json:"keys"`
	}
	for _, key := range keys {
		pub := key.Priv.Public().(ed25519.PublicKey)
		out.Keys = append(out.Keys, k{key.ID, "ed25519", base64.StdEncoding.EncodeToString(pub), statuses[key.ID], "2026-11-12T09:00:00Z"})
	}
	b, _ := json.Marshal(out)
	return b
}

// Sign signs the canonical manifest and returns the encoded envelope.
func Sign(t testing.TB, canonical []byte, key Key) []byte {
	t.Helper()
	env, err := dsse.Sign(manifest.PayloadType, canonical, dsse.SigningKey{KeyID: key.ID, Key: key.Priv})
	if err != nil {
		t.Fatal(err)
	}
	b, err := env.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Fixture is a written HLS tree (original and masked variants) and its manifest.
type Fixture struct {
	Original, Masked string // directories
	Built            *manifest.Built
	Files            map[string][]string // variant -> manifest paths
}

func write(t testing.TB, dir, tag string) ([]manifest.RenditionInput, manifest.StoredObject, []string) {
	t.Helper()
	var paths []string
	obj := func(p, content string) manifest.StoredObject {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(tag+content), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
		return manifest.StoredObject{Path: p, SHA256: sha256.Sum256([]byte(tag + content)), Size: int64(len(tag + content))}
	}
	rends := []manifest.RenditionInput{
		{
			Name: "720p", Width: 1280, Height: 720, Bandwidth: 2500000,
			Init:     obj("720p/init.mp4", "init-720"),
			Segments: []manifest.StoredObject{obj("720p/seg-0.m4s", "s720-0"), obj("720p/seg-1.m4s", "s720-1"), obj("720p/seg-2.m4s", "s720-2")},
			Playlist: obj("720p/playlist.m3u8", "pl-720"),
		},
		{
			Name: "480p", Width: 854, Height: 480, Bandwidth: 900000,
			Init:     obj("480p/init.mp4", "init-480"),
			Segments: []manifest.StoredObject{obj("480p/seg-0.m4s", "s480-0"), obj("480p/seg-1.m4s", "s480-1")},
			Playlist: obj("480p/playlist.m3u8", "pl-480"),
		},
	}
	return rends, obj("master.m3u8", "master"), paths
}

// New writes the trees under t.TempDir() and builds the manifest with a masked section.
func New(t testing.TB) *Fixture {
	t.Helper()
	root := t.TempDir()
	f := &Fixture{Original: filepath.Join(root, "orig"), Masked: filepath.Join(root, "masked"), Files: map[string][]string{}}
	rends, master, paths := write(t, f.Original, "")
	f.Files["original"] = paths
	built, err := manifest.Build(manifest.Input{
		AssetID: "ast_00000000000000000000000001", TenantID: "ten_00000000000000000000000001",
		CreatedAt: time.Date(2026, 11, 12, 10, 30, 15, 0, time.UTC), PipelineVersion: "v0.0.0-test",
		Encoder: manifest.Encoder{
			FFmpeg: "ffmpeg version test-fixture", VideoCodec: "libx264", Preset: "medium", FrameRate: "25/1",
			SegmentSeconds: 6, KeyframeSeconds: 2, Encryption: "AES-128",
			Rungs: []manifest.Rung{{Name: "720p", CRF: 23, MaxrateKbps: 3000, BufsizeKbps: 6000, AudioKbps: 128}},
		},
		Renditions: rends, Master: master, SourceSHA256: sha256.Sum256([]byte("source")), SourceSize: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	mrends, mmaster, mpaths := write(t, f.Masked, "masked-")
	f.Files["masked"] = mpaths
	f.Built, err = manifest.WithMasked(built.Manifest, manifest.MaskedInput{
		CreatedAt: time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC), FacesDetected: 3, Frames: 100,
		Rungs:      []manifest.Rung{{Name: "720p", CRF: 23, MaxrateKbps: 3000, BufsizeKbps: 6000, AudioKbps: 128}},
		Renditions: mrends, Master: mmaster,
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
