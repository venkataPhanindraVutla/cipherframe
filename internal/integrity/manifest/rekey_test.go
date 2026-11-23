package manifest

import (
	"bytes"
	"testing"
)

// rekeyedOf makes the re-keyed twin of an input: new bytes at "k1/" paths for every segment and
// playlist, the init segments and the master as they were.
func rekeyedOf(in Input) (Input, Rekeyed) {
	r := Rekeyed{Segments: map[string][]StoredObject{}, Playlists: map[string]StoredObject{}}
	out := in
	out.Renditions = nil
	for _, rend := range in.Renditions {
		n := rend
		n.Segments = nil
		for i, s := range rend.Segments {
			n.Segments = append(n.Segments, obj("k1/"+s.Path, "new-"+rend.Name+string(rune('0'+i))))
		}
		n.Playlist = obj("k1/"+rend.Playlist.Path, "new-pl-"+rend.Name)
		r.Segments[rend.Name], r.Playlists[rend.Name] = n.Segments, n.Playlist
		out.Renditions = append(out.Renditions, n)
	}
	return out, r
}

func TestWithRekeyedEqualsABuildOfTheNewObjects(t *testing.T) {
	in := fixedInput()
	orig := mustBuild(t, in)
	want, r := rekeyedOf(in)
	got, err := WithRekeyed(orig.Manifest, r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Canonical, mustBuild(t, want).Canonical) {
		t.Error("the re-keyed manifest differs from a fresh build over the new objects")
	}
	if bytes.Equal(got.Canonical, orig.Canonical) || got.TopRoot == orig.TopRoot {
		t.Error("the re-keyed manifest did not change")
	}
}

func TestWithRekeyedChecksWhatItIsGiven(t *testing.T) {
	in := fixedInput()
	orig := mustBuild(t, in)
	_, r := rekeyedOf(in)

	short := Rekeyed{Segments: map[string][]StoredObject{"720p": r.Segments["720p"][:1], "480p": r.Segments["480p"]}, Playlists: r.Playlists}
	if _, err := WithRekeyed(orig.Manifest, short, nil); err == nil {
		t.Error("a rendition with fewer segments was accepted")
	}
	if _, err := WithRekeyed(orig.Manifest, Rekeyed{}, nil); err == nil {
		t.Error("an empty replacement was accepted")
	}
	if _, err := WithRekeyed(orig.Manifest, r, &r); err == nil {
		t.Error("a masked replacement was accepted for a manifest without a masked section")
	}
}

func TestWithRekeyedCoversTheMaskedVariantToo(t *testing.T) {
	in := fixedInput()
	maskedIn := MaskedInput{
		CreatedAt: in.CreatedAt, Rungs: []Rung{{Name: "720p"}}, Master: obj("master.m3u8", "masked-master"),
		Renditions: []RenditionInput{{
			Name: "720p", Width: 1280, Height: 720, Bandwidth: 2500000, Init: obj("720p/init.mp4", "mi"),
			Segments: []StoredObject{obj("720p/seg-0.m4s", "m0")}, Playlist: obj("720p/playlist.m3u8", "mp"),
		}},
	}
	withMasked, err := WithMasked(mustBuild(t, in).Manifest, maskedIn)
	if err != nil {
		t.Fatal(err)
	}
	_, origR := rekeyedOf(in)
	maskedR := Rekeyed{
		Segments:  map[string][]StoredObject{"720p": {obj("k1/720p/seg-0.m4s", "mn")}},
		Playlists: map[string]StoredObject{"720p": obj("k1/720p/playlist.m3u8", "mpn")},
	}
	got, err := WithRekeyed(withMasked.Manifest, origR, &maskedR)
	if err != nil {
		t.Fatal(err)
	}
	if got.Manifest.Masked.TopLevel.Root == withMasked.Manifest.Masked.TopLevel.Root ||
		got.Manifest.Masked.Renditions[0].Segments[0].Path != "k1/720p/seg-0.m4s" {
		t.Error("the masked variant was not re-keyed")
	}
	if got.Manifest.Masked.FacesDetected != withMasked.Manifest.Masked.FacesDetected {
		t.Error("the masked section lost its other members")
	}
	if _, err := WithRekeyed(withMasked.Manifest, origR, nil); err == nil {
		t.Error("leaving the masked variant at the old key was accepted")
	}
}
