package manifest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/dsse"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/merkle"
)

var update = flag.Bool("update", false, "rewrite the golden file")

func obj(path, content string) StoredObject {
	return StoredObject{Path: path, SHA256: sha256.Sum256([]byte(content)), Size: int64(len(content))}
}

func fixedInput() Input {
	return Input{
		AssetID:         "ast_00000000000000000000000001",
		TenantID:        "ten_00000000000000000000000001",
		CreatedAt:       time.Date(2026, 11, 12, 10, 30, 15, 999, time.UTC),
		PipelineVersion: "v0.0.0-test",
		Encoder: Encoder{
			FFmpeg: "ffmpeg version test-fixture", VideoCodec: "libx264", Preset: "medium", FrameRate: "30000/1001",
			SegmentSeconds: 6, KeyframeSeconds: 2, Encryption: "AES-128",
			Rungs: []Rung{
				{Name: "720p", CRF: 23, MaxrateKbps: 3000, BufsizeKbps: 6000, AudioKbps: 128},
				{Name: "480p", CRF: 24, MaxrateKbps: 1200, BufsizeKbps: 2400, AudioKbps: 96},
			},
		},
		Renditions: []RenditionInput{
			{
				Name: "720p", Width: 1280, Height: 720, Bandwidth: 2500000,
				Init:     obj("720p/init.mp4", "init-720"),
				Segments: []StoredObject{obj("720p/seg-0.m4s", "s720-0"), obj("720p/seg-1.m4s", "s720-1"), obj("720p/seg-2.m4s", "s720-2")},
				Playlist: obj("720p/playlist.m3u8", "pl-720"),
			},
			{
				Name: "480p", Width: 854, Height: 480, Bandwidth: 900000,
				Init:     obj("480p/init.mp4", "init-480"),
				Segments: []StoredObject{obj("480p/seg-0.m4s", "s480-0"), obj("480p/seg-1.m4s", "s480-1")},
				Playlist: obj("480p/playlist.m3u8", "pl-480"),
			},
		},
		Master:       obj("master.m3u8", "master"),
		SourceSHA256: sha256.Sum256([]byte("source")),
		SourceSize:   123456,
	}
}

func mustBuild(t *testing.T, in Input) *Built {
	t.Helper()
	b, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBuildGolden(t *testing.T) {
	b := mustBuild(t, fixedInput())
	again := mustBuild(t, fixedInput())
	if !bytes.Equal(b.Canonical, again.Canonical) {
		t.Fatal("two builds of the same input differ")
	}
	const golden = "testdata/golden.json"
	if *update {
		if err := os.WriteFile(golden, b.Canonical, 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.Canonical, want) {
		t.Fatalf("canonical bytes differ from %s (run with -update if the change is intended)\n got: %s\nwant: %s", golden, b.Canonical, want)
	}
}

func hexOf(h [32]byte) string { return hex.EncodeToString(h[:]) }

func TestRenditionRootAndTopOrder(t *testing.T) {
	in := fixedInput()
	b := mustBuild(t, in)
	m := b.Manifest

	var topLeaves []merkle.Hash
	for i, r := range in.Renditions {
		leaves := []merkle.Hash{merkle.HashLeaf(r.Init.SHA256[:])}
		for _, s := range r.Segments {
			leaves = append(leaves, merkle.HashLeaf(s.SHA256[:]))
		}
		root := merkle.RootOf(leaves)
		if m.Renditions[i].MerkleRoot != hexOf(root) {
			t.Errorf("rendition %s: root %s, want %s", r.Name, m.Renditions[i].MerkleRoot, hexOf(root))
		}
		if m.Renditions[i].SegmentCount != len(r.Segments) {
			t.Errorf("rendition %s: segment_count %d", r.Name, m.Renditions[i].SegmentCount)
		}
		topLeaves = append(topLeaves, merkle.HashLeaf(root[:]))
	}
	topLeaves = append(topLeaves, merkle.HashLeaf(in.Master.SHA256[:]))
	for _, r := range in.Renditions {
		topLeaves = append(topLeaves, merkle.HashLeaf(r.Playlist.SHA256[:]))
	}
	want := merkle.RootOf(topLeaves)
	if m.TopLevel.Root != hexOf(want) || b.TopRoot != [32]byte(want) {
		t.Errorf("top root %s, want %s", m.TopLevel.Root, hexOf(want))
	}
	wantOrder := []string{"rendition:720p", "rendition:480p", "master", "playlist:720p", "playlist:480p"}
	if !reflect.DeepEqual(m.TopLevel.Order, wantOrder) {
		t.Errorf("order %v, want %v", m.TopLevel.Order, wantOrder)
	}
	if m.CreatedAt != "2026-11-12T10:30:15Z" {
		t.Errorf("created_at %q", m.CreatedAt)
	}
}

func TestTamperChangesRoots(t *testing.T) {
	base := mustBuild(t, fixedInput())
	flip := func(h *[32]byte) { h[0] ^= 1 }

	cases := map[string]func(in *Input) (rendition int){
		"init":     func(in *Input) int { flip(&in.Renditions[0].Init.SHA256); return 0 },
		"segment":  func(in *Input) int { flip(&in.Renditions[1].Segments[1].SHA256); return 1 },
		"playlist": func(in *Input) int { flip(&in.Renditions[0].Playlist.SHA256); return -1 },
		"master":   func(in *Input) int { flip(&in.Master.SHA256); return -1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := fixedInput()
			r := mutate(&in)
			got := mustBuild(t, in)
			for i := range base.Manifest.Renditions {
				changed := got.Manifest.Renditions[i].MerkleRoot != base.Manifest.Renditions[i].MerkleRoot
				if changed != (i == r) {
					t.Errorf("rendition %d root changed = %v", i, changed)
				}
			}
			if got.Manifest.TopLevel.Root == base.Manifest.TopLevel.Root {
				t.Error("top root did not change")
			}
		})
	}
}

func hasFloat(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Float32, reflect.Float64:
		return true
	case reflect.Slice, reflect.Array, reflect.Pointer:
		return hasFloat(t.Elem())
	case reflect.Map:
		return hasFloat(t.Key()) || hasFloat(t.Elem())
	case reflect.Struct:
		for i := range t.NumField() {
			if hasFloat(t.Field(i).Type) {
				return true
			}
		}
	}
	return false
}

func TestNoFloats(t *testing.T) {
	if hasFloat(reflect.TypeOf(Manifest{})) {
		t.Fatal("the manifest contains a floating-point field")
	}
}

func TestEnvelopeVerifies(t *testing.T) {
	b := mustBuild(t, fixedInput())
	seed := sha256.Sum256([]byte("test-fixture-manifest-seed"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	env, err := dsse.Sign(PayloadType, b.Canonical, dsse.SigningKey{KeyID: "sk_test", Key: priv})
	if err != nil {
		t.Fatal(err)
	}
	enc, err := env.Encode()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := dsse.Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	res, err := dsse.Verify(dec, PayloadType, map[string]ed25519.PublicKey{"sk_test": priv.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	if err := res.RequireAny(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.Payload, b.Canonical) {
		t.Error("payload differs")
	}
}

func TestNoObjectKeysOrSource(t *testing.T) {
	b := mustBuild(t, fixedInput())
	s := string(b.Canonical)
	for _, bad := range []string{"\"t/", "/hls/", "bucket", "source_key"} {
		if strings.Contains(s, bad) {
			t.Errorf("manifest contains %q", bad)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	mutations := map[string]func(in *Input){
		"no renditions":   func(in *Input) { in.Renditions = nil },
		"no segments":     func(in *Input) { in.Renditions[0].Segments = nil },
		"object key path": func(in *Input) { in.Master.Path = "t/x/a/y/hls/master.m3u8" },
		"absolute path":   func(in *Input) { in.Renditions[0].Init.Path = "/720p/init.mp4" },
		"traversal":       func(in *Input) { in.Renditions[0].Playlist.Path = "../x" },
		"duplicate name":  func(in *Input) { in.Renditions[1].Name = "720p" },
		"no source size":  func(in *Input) { in.SourceSize = 0 },
		"no time":         func(in *Input) { in.CreatedAt = time.Time{} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			in := fixedInput()
			mutate(&in)
			if _, err := Build(in); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
