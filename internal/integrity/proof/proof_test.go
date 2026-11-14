package proof

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify"
)

func obj(path, seed string) manifest.StoredObject {
	return manifest.StoredObject{Path: path, SHA256: sha256.Sum256([]byte(seed)), Size: int64(len(seed))}
}

// renditions builds `count` renditions; rendition i has i+1 segments, so trees of 2..count+1 leaves
// occur. tag keeps the two variants' hashes apart.
func renditions(count int, tag string) []manifest.RenditionInput {
	var out []manifest.RenditionInput
	for i := range count {
		name := fmt.Sprintf("r%d", i)
		r := manifest.RenditionInput{
			Name: name, Width: 100 * (i + 1), Height: 50 * (i + 1), Bandwidth: 1000,
			Init:     obj(name+"/init.mp4", tag+name+"init"),
			Playlist: obj(name+"/playlist.m3u8", tag+name+"pl"),
		}
		for j := 0; j <= i; j++ {
			r.Segments = append(r.Segments, obj(fmt.Sprintf("%s/seg-%d.m4s", name, j), fmt.Sprintf("%s%sseg%d", tag, name, j)))
		}
		out = append(out, r)
	}
	return out
}

func build(t *testing.T, count int) manifest.Manifest {
	t.Helper()
	b, err := manifest.Build(manifest.Input{
		AssetID: "ast_00000000000000000000000001", TenantID: "ten_00000000000000000000000001",
		CreatedAt: time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC), PipelineVersion: "v0",
		Encoder:    manifest.Encoder{FFmpeg: "ffmpeg", VideoCodec: "libx264", Preset: "medium", FrameRate: "25/1", SegmentSeconds: 6, KeyframeSeconds: 2, Encryption: "AES-128"},
		Renditions: renditions(count, ""), Master: obj("master.m3u8", "master"),
		SourceSHA256: sha256.Sum256([]byte("src")), SourceSize: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.Manifest
}

// paths lists every artifact path of a variant's section with its hash.
func paths(s section) map[string]string {
	out := map[string]string{}
	for _, r := range s.renditions {
		out[r.Init.Path] = r.Init.SHA256
		for _, o := range r.Segments {
			out[o.Path] = o.SHA256
		}
	}
	for _, a := range s.artifacts {
		out[a.Path] = a.SHA256
	}
	return out
}

func sum(t *testing.T, h string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return [32]byte(b)
}

// Rendition trees of 2..18 leaves (init plus 1..17 segments) and top-level trees of 3..19 leaves.
func TestEveryLeafOfEveryTreeSizeVerifies(t *testing.T) {
	for count := 1; count <= 17; count++ {
		m := build(t, count)
		s, _ := sectionOf(m, Original)
		for path, h := range paths(s) {
			p, err := Build(m, Original, path)
			if err != nil {
				t.Fatalf("count %d %s: %v", count, path, err)
			}
			if p.SHA256 != h || p.TopLevel.Root != m.TopLevel.Root || p.AssetID != m.AssetID || p.Variant != Original {
				t.Fatalf("count %d %s: proof = %+v", count, path, p)
			}
			if err := Verify(*p, sum(t, h)); err != nil {
				t.Fatalf("count %d %s: %v", count, path, err)
			}
		}
	}
}

func TestPlaylistProofsHaveOnlyTheTopLevel(t *testing.T) {
	m := build(t, 3)
	for _, path := range []string{"master.m3u8", "r1/playlist.m3u8"} {
		p, err := Build(m, Original, path)
		if err != nil {
			t.Fatal(err)
		}
		if p.LeafIndex != nil || p.TreeSize != nil || p.Rendition != "" || p.RenditionRoot != "" || p.AuditPath != nil {
			t.Errorf("%s: rendition level present: %+v", path, p)
		}
		if err := Verify(*p, sum(t, p.SHA256)); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
	// The order is the manifest's: renditions, master, then the playlists.
	p, _ := Build(m, Original, "master.m3u8")
	if p.TopLevel.LeafIndex != 3 || p.TopLevel.TreeSize != 7 {
		t.Errorf("master leaf = %d of %d, want 3 of 7", p.TopLevel.LeafIndex, p.TopLevel.TreeSize)
	}
}

func TestTamperedProofsFail(t *testing.T) {
	m := build(t, 5)
	good, err := Build(m, Original, "r3/seg-2.m4s")
	if err != nil {
		t.Fatal(err)
	}
	h := sum(t, good.SHA256)
	flip := func(s string) string {
		b := []byte(s)
		if b[0] == '0' {
			b[0] = '1'
		} else {
			b[0] = '0'
		}
		return string(b)
	}
	clone := func() Proof {
		c := *good
		c.AuditPath = append([]string(nil), good.AuditPath...)
		c.TopLevel.AuditPath = append([]string(nil), good.TopLevel.AuditPath...)
		return c
	}
	cases := map[string]func(*Proof){
		"rendition path element": func(p *Proof) { p.AuditPath[0] = flip(p.AuditPath[0]) },
		"rendition root":         func(p *Proof) { p.RenditionRoot = flip(p.RenditionRoot) },
		"top path element":       func(p *Proof) { p.TopLevel.AuditPath[0] = flip(p.TopLevel.AuditPath[0]) },
		"top root":               func(p *Proof) { p.TopLevel.Root = flip(p.TopLevel.Root) },
		"leaf index":             func(p *Proof) { i := *p.LeafIndex ^ 1; p.LeafIndex = &i },
		"top leaf index":         func(p *Proof) { p.TopLevel.LeafIndex ^= 1 },
	}
	for name, mutate := range cases {
		p := clone()
		mutate(&p)
		if err := Verify(p, h); !errors.Is(err, verify.ErrTampered) {
			t.Errorf("%s: err = %v, want tampered", name, err)
		}
	}
	// A different file, and a leaf swapped from another path.
	if err := Verify(*good, sum(t, flip(good.SHA256))); !errors.Is(err, verify.ErrTampered) {
		t.Errorf("other hash: %v", err)
	}
	other, _ := Build(m, Original, "r3/seg-1.m4s")
	swapped := *good
	swapped.SHA256 = other.SHA256
	if err := Verify(swapped, sum(t, other.SHA256)); !errors.Is(err, verify.ErrTampered) {
		t.Errorf("swapped leaf: %v", err)
	}
	// An impossible shape is malformed, not tampered.
	short := clone()
	short.AuditPath = short.AuditPath[:1]
	if err := Verify(short, h); !errors.Is(err, verify.ErrMalformed) {
		t.Errorf("short path: %v", err)
	}
	bad := clone()
	bad.TopLevel.Root = "zz"
	if err := Verify(bad, h); !errors.Is(err, verify.ErrMalformed) {
		t.Errorf("bad hex: %v", err)
	}
}

func TestUnknownPathAndVariant(t *testing.T) {
	m := build(t, 2)
	if _, err := Build(m, Original, "nope.mp4"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown path: %v", err)
	}
	if _, err := Build(m, Masked, "master.m3u8"); !errors.Is(err, ErrNoVariant) {
		t.Errorf("masked without a section: %v", err)
	}
	if _, err := Build(m, "other", "master.m3u8"); !errors.Is(err, ErrNoVariant) {
		t.Errorf("unknown variant: %v", err)
	}
	// A manifest whose recorded root was edited cannot yield proofs.
	m.TopLevel.Root = hex.EncodeToString(make([]byte, 32))
	if _, err := Build(m, Original, "master.m3u8"); !errors.Is(err, verify.ErrMalformed) {
		t.Errorf("edited root: %v", err)
	}
}

func TestMaskedSection(t *testing.T) {
	orig := build(t, 2)
	b, err := manifest.WithMasked(orig, manifest.MaskedInput{
		CreatedAt: time.Date(2026, 11, 14, 1, 0, 0, 0, time.UTC), FacesDetected: 1, Frames: 2,
		Rungs: []manifest.Rung{{Name: "r0"}, {Name: "r1"}}, Renditions: renditions(3, "m-"), Master: obj("master.m3u8", "m-master"),
	})
	if err != nil {
		t.Fatal(err)
	}
	m := b.Manifest
	ms, _ := sectionOf(m, Masked)
	for path, h := range paths(ms) {
		p, err := Build(m, Masked, path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if p.Variant != Masked || p.SHA256 != h || p.TopLevel.Root != m.Masked.TopLevel.Root {
			t.Fatalf("%s: proof = %+v", path, p)
		}
		if err := Verify(*p, sum(t, h)); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	// The same path in the two variants has different hashes and roots; a proof of one does not
	// verify the other's hash.
	po, _ := Build(m, Original, "r0/seg-0.m4s")
	pm, _ := Build(m, Masked, "r0/seg-0.m4s")
	if po.SHA256 == pm.SHA256 || po.TopLevel.Root == pm.TopLevel.Root {
		t.Fatal("variants share hashes or roots")
	}
	if err := Verify(*po, sum(t, pm.SHA256)); !errors.Is(err, verify.ErrTampered) {
		t.Errorf("cross-variant hash: %v", err)
	}
	// A path that exists only in the masked ladder is unknown in the original.
	if _, err := Build(m, Original, "r2/init.mp4"); !errors.Is(err, ErrNotFound) {
		t.Errorf("masked-only path in the original: %v", err)
	}
}
