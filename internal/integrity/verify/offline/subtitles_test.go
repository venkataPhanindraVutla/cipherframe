package offline_test

import (
	"crypto/sha256"
	"slices"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline/offlinetest"
)

// A signed manifest with subtitle tracks verifies a track file by its path, for either variant, and
// reports a changed file as modified; a manifest without tracks verifies as before.
func TestSubtitleTracksVerify(t *testing.T) {
	f := offlinetest.New(t)
	vtt := []byte("WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nhi\n\n")
	built, err := manifest.WithSubtitles(f.Built.Manifest, []manifest.SubtitleInput{{
		ID: "sub_00000000000000000000000001", Language: "en", Origin: "upload",
		Object: manifest.StoredObject{Path: "subtitles/sub_00000000000000000000000001.vtt", SHA256: sha256.Sum256(vtt), Size: int64(len(vtt))},
	}})
	if err != nil {
		t.Fatal(err)
	}
	a := offlinetest.NewKey("sk_a", "a")
	env := offlinetest.Sign(t, built.Canonical, a)
	keys, err := offline.ParseKeySet(offlinetest.KeySetJSON([]offlinetest.Key{a}, map[string]string{"sk_a": "active"}))
	if err != nil {
		t.Fatal(err)
	}
	const path = "subtitles/sub_00000000000000000000000001.vtt"
	for _, variant := range []string{"original", "masked"} {
		if r := offline.VerifyArtifact(env, keys, path, sha256.Sum256(vtt), variant); r.Outcome != offline.Ours {
			t.Errorf("%s: %+v", variant, r)
		}
	}
	changed := sha256.Sum256(append(vtt, '!'))
	if r := offline.VerifyArtifact(env, keys, path, changed, "original"); r.Outcome != offline.Modified || r.Reason != offline.ReasonModified {
		t.Errorf("changed track: %+v", r)
	}
	if r := offline.VerifyArtifact(env, keys, "subtitles/sub_00000000000000000000000002.vtt", sha256.Sum256(vtt), "original"); r.Outcome != offline.CannotSay || r.Reason != offline.ReasonUnknownPath {
		t.Errorf("an unlisted track: %+v", r)
	}
	signed, err := offline.Open(env, keys)
	if err != nil {
		t.Fatal(err)
	}
	if got := signed.SubtitlePaths(); !slices.Equal(got, []string{path}) {
		t.Errorf("SubtitlePaths = %v", got)
	}
	if slices.Contains(signed.Paths("original"), path) {
		t.Errorf("Paths lists the track, so a download of the HLS tree would miss it: %v", signed.Paths("original"))
	}
	// The media files still verify through the same manifest.
	for _, p := range f.Files["original"] {
		if r := offline.VerifyArtifact(env, keys, p, sumOf(t, f.Original, p), "original"); r.Outcome != offline.Ours {
			t.Fatalf("%s: %+v", p, r)
		}
	}
}
