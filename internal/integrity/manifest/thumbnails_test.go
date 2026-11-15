package manifest

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
	"time"
)

func thumbs(prefix string) []Thumbnail {
	return []Thumbnail{
		{Kind: KindThumbnails, Object: obj("thumbnails.vtt", prefix+"vtt")},
		{Kind: KindPoster, Object: obj("poster.jpg", prefix+"poster")},
		{Kind: KindSprite, Object: obj("sprite.jpg", prefix+"sprite")},
	}
}

func TestBuildWithThumbnails(t *testing.T) {
	plain := mustBuild(t, fixedInput())
	if bytes.Contains(plain.Canonical, []byte("thumbnails")) {
		t.Fatal("a manifest without thumbnails mentions them")
	}
	in := fixedInput()
	in.Thumbnails = thumbs("o-")
	got := mustBuild(t, in)
	m := got.Manifest
	if len(m.Thumbnails) != 3 || m.Thumbnails[0].Kind != KindPoster || m.Thumbnails[1].Kind != KindSprite || m.Thumbnails[2].Kind != KindThumbnails {
		t.Fatalf("thumbnails = %+v", m.Thumbnails)
	}
	if m.Thumbnails[0].Path != "poster.jpg" || m.Thumbnails[0].SHA256 != hex.EncodeToString(sha256Of("o-poster")) {
		t.Errorf("poster entry = %+v", m.Thumbnails[0])
	}
	// Not in any tree: the roots are those of the same media without thumbnails.
	if got.TopRoot != plain.TopRoot || m.TopLevel.Root != plain.Manifest.TopLevel.Root {
		t.Error("thumbnails changed the top-level root")
	}
	m.Thumbnails = nil
	if !reflect.DeepEqual(m, plain.Manifest) {
		t.Error("the media members changed")
	}
	if got.Manifest.VariantThumbnails(false) == nil || got.Manifest.VariantThumbnails(true) != nil {
		t.Error("VariantThumbnails confuses the variants")
	}

	// A poster alone, a duplicate and an absolute key are refused.
	for name, bad := range map[string][]Thumbnail{
		"poster only": {{Kind: KindPoster, Object: obj("poster.jpg", "p")}},
		"duplicate":   append(thumbs("x"), Thumbnail{Kind: KindPoster, Object: obj("poster.jpg", "p")}),
		"unknown":     {{Kind: "banner", Object: obj("b.jpg", "b")}, {Kind: KindSprite, Object: obj("s.jpg", "s")}, {Kind: KindPoster, Object: obj("p.jpg", "p")}},
		"object key":  {{Kind: KindPoster, Object: obj("t/a/b/hls/poster.jpg", "p")}, {Kind: KindSprite, Object: obj("s.jpg", "s")}, {Kind: KindThumbnails, Object: obj("t.vtt", "t")}},
	} {
		in := fixedInput()
		in.Thumbnails = bad
		if _, err := Build(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The masked variant's thumbnails are its own, inside the masked section, and the original's stay
// where they were signed.
func TestMaskedThumbnailsAreSeparate(t *testing.T) {
	in := fixedInput()
	in.Thumbnails = thumbs("o-")
	orig := mustBuild(t, in)
	masked := MaskedInput{
		CreatedAt: time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC), FacesDetected: 1, Frames: 10,
		Renditions: []RenditionInput{{
			Name: "720p", Width: 1280, Height: 720, Bandwidth: 2500000,
			Init:     obj("720p/init.mp4", "mi"),
			Segments: []StoredObject{obj("720p/seg-0.m4s", "m0")},
			Playlist: obj("720p/playlist.m3u8", "mpl"),
		}},
		Master: obj("master.m3u8", "mm"), Thumbnails: thumbs("m-"),
	}
	got, err := WithMasked(orig.Manifest, masked)
	if err != nil {
		t.Fatal(err)
	}
	o, mk := got.Manifest.VariantThumbnails(false), got.Manifest.VariantThumbnails(true)
	if len(o) != 3 || len(mk) != 3 || o[0].SHA256 == mk[0].SHA256 || !reflect.DeepEqual(o, orig.Manifest.Thumbnails) {
		t.Fatalf("original %+v, masked %+v", o, mk)
	}
	// Re-signing for a subtitle change keeps both lists.
	withTrack, err := WithSubtitles(got.Manifest, []SubtitleInput{track("sub_a", "en", false)})
	if err != nil || len(withTrack.Manifest.Thumbnails) != 3 || len(withTrack.Manifest.Masked.Thumbnails) != 3 {
		t.Errorf("a subtitle change dropped thumbnails: %v", err)
	}
	// A masked variant without thumbnails has no member.
	masked.Thumbnails = nil
	none, err := WithMasked(orig.Manifest, masked)
	if err != nil || none.Manifest.VariantThumbnails(true) != nil {
		t.Errorf("masked without thumbnails: %v", err)
	}
}
