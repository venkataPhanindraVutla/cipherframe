package manifest

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testLogo(version string) *Logo {
	return &Logo{
		SHA256: strings.Repeat("ab", 32), Version: version, Corner: "top_right", OpacityPercent: 60, WidthPercent: 15,
	}
}

// A manifest without a logo is byte for byte what it was before logos existed (TestBuildGolden holds
// the exact bytes); with one, the encoder section records it and nothing else moves.
func TestBuildWithALogo(t *testing.T) {
	plain := mustBuild(t, fixedInput())
	if bytes.Contains(plain.Canonical, []byte("logo")) {
		t.Fatal("a manifest without a logo mentions one")
	}
	in := fixedInput()
	in.Encoder.Logo = testLogo("lgo_1")
	got := mustBuild(t, in)
	if want := testLogo("lgo_1"); got.Manifest.Encoder.Logo == nil || *got.Manifest.Encoder.Logo != *want {
		t.Fatalf("encoder logo = %+v", got.Manifest.Encoder.Logo)
	}
	for _, want := range []string{`"logo":{`, `"opacity_percent":60`, `"corner":"top_right"`, `"width_percent":15`, `"version":"lgo_1"`} {
		if !bytes.Contains(got.Canonical, []byte(want)) {
			t.Errorf("canonical manifest lacks %s: %s", want, got.Canonical)
		}
	}
	// The logo is not in any tree: the media's identity is the same with and without it.
	if got.TopRoot != plain.TopRoot {
		t.Error("the logo changed the top-level root")
	}
	m := got.Manifest
	m.Encoder.Logo = nil
	if !reflect.DeepEqual(m, plain.Manifest) {
		t.Error("a member other than the logo changed")
	}
	// The caller's struct is copied, not shared.
	in.Encoder.Logo.Corner = "bottom_left"
	if got.Manifest.Encoder.Logo.Corner != "top_right" {
		t.Error("the built manifest shares the caller's logo")
	}
	// A different logo (or placement) is a different signed document.
	other := fixedInput()
	other.Encoder.Logo = testLogo("lgo_2")
	if bytes.Equal(mustBuild(t, other).Canonical, got.Canonical) {
		t.Error("two logo versions encode alike")
	}
}

func TestMaskedVariantRecordsItsLogo(t *testing.T) {
	in := fixedInput()
	in.Encoder.Logo = testLogo("lgo_1")
	orig := mustBuild(t, in)
	masked := MaskedInput{
		CreatedAt: time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC), FacesDetected: 1, Frames: 10,
		Renditions: []RenditionInput{{
			Name: "720p", Width: 1280, Height: 720, Bandwidth: 2500000,
			Init:     obj("720p/init.mp4", "mi"),
			Segments: []StoredObject{obj("720p/seg-0.m4s", "m0")},
			Playlist: obj("720p/playlist.m3u8", "mpl"),
		}},
		Master: obj("master.m3u8", "mm"), Logo: testLogo("lgo_1"),
	}
	got, err := WithMasked(orig.Manifest, masked)
	if err != nil {
		t.Fatal(err)
	}
	if got.Manifest.Masked.Logo == nil || *got.Manifest.Masked.Logo != *got.Manifest.Encoder.Logo {
		t.Fatalf("masked logo = %+v, encoder logo = %+v", got.Manifest.Masked.Logo, got.Manifest.Encoder.Logo)
	}
	// The original's members are carried over as signed.
	m := got.Manifest
	m.Masked = nil
	if !reflect.DeepEqual(m, orig.Manifest) {
		t.Error("the original variant's members changed")
	}
	// Without a logo the masked section has none either.
	masked.Logo = nil
	plain, err := WithMasked(mustBuild(t, fixedInput()).Manifest, masked)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(plain.Canonical, []byte("logo")) {
		t.Error("a masked section without a logo mentions one")
	}
}
