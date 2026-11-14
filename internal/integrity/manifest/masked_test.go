package manifest

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

func TestWithMaskedKeepsTheOriginalAndAddsASection(t *testing.T) {
	orig := mustBuild(t, fixedInput())
	in := MaskedInput{
		CreatedAt: time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC), FacesDetected: 7, Frames: 420,
		Rungs: []Rung{{Name: "720p", CRF: 23, MaxrateKbps: 3000, BufsizeKbps: 6000, AudioKbps: 128}},
		Renditions: []RenditionInput{{
			Name: "720p", Width: 1280, Height: 720, Bandwidth: 2500000,
			Init:     obj("720p/init.mp4", "masked-init"),
			Segments: []StoredObject{obj("720p/seg-0.m4s", "m0"), obj("720p/seg-1.m4s", "m1")},
			Playlist: obj("720p/playlist.m3u8", "masked-pl"),
		}},
		Master: obj("master.m3u8", "masked-master"),
	}
	got, err := WithMasked(orig.Manifest, in)
	if err != nil {
		t.Fatal(err)
	}
	m := got.Manifest
	if m.Masked == nil || m.Masked.FacesDetected != 7 || m.Masked.Frames != 420 || len(m.Masked.Renditions) != 1 {
		t.Fatalf("masked section = %+v", m.Masked)
	}
	if m.Masked.TopLevel.Root == m.TopLevel.Root {
		t.Error("the masked tree has the original's root")
	}
	if !bytes.Contains(got.Canonical, []byte(`"masked":{`)) || bytes.Equal(got.Canonical, orig.Canonical) {
		t.Error("the canonical form does not carry the masked section")
	}
	// Adding it again replaces the section instead of appending to it.
	again, err := WithMasked(got.Manifest, in)
	if err != nil || !bytes.Equal(again.Canonical, got.Canonical) {
		t.Errorf("a second WithMasked is not idempotent: %v", err)
	}
	// Everything else is as it was signed, and TopRoot is still the original variant's.
	m.Masked = nil
	if !reflect.DeepEqual(m, orig.Manifest) || got.TopRoot != orig.TopRoot {
		t.Error("the original members changed")
	}
	if _, err := WithMasked(orig.Manifest, MaskedInput{}); err == nil {
		t.Error("an empty masked input was accepted")
	}
}
