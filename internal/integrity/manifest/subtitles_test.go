package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func track(id, lang string, def bool) SubtitleInput {
	return SubtitleInput{ID: id, Language: lang, Default: def, Origin: "upload", Object: obj("subtitles/"+id+".vtt", "vtt-"+id)}
}

func TestWithSubtitlesAddsAndRemovesTheList(t *testing.T) {
	orig := mustBuild(t, fixedInput())
	got, err := WithSubtitles(orig.Manifest, []SubtitleInput{track("sub_b", "fr", false), track("sub_a", "en", true)})
	if err != nil {
		t.Fatal(err)
	}
	m := got.Manifest
	if len(m.Subtitles) != 2 || m.Subtitles[0].ID != "sub_a" || m.Subtitles[1].ID != "sub_b" || !m.Subtitles[0].Default {
		t.Fatalf("subtitles = %+v", m.Subtitles)
	}
	if m.Subtitles[0].SHA256 != hex.EncodeToString(sha256Of("vtt-sub_a")) {
		t.Errorf("hash = %s", m.Subtitles[0].SHA256)
	}
	if got.TopRoot != orig.TopRoot || m.TopLevel.Root != orig.Manifest.TopLevel.Root {
		t.Error("tracks changed the top-level root: they must not be part of the tree")
	}
	// Every other member is as it was signed.
	m.Subtitles = nil
	if !reflect.DeepEqual(m, orig.Manifest) {
		t.Error("the media members changed")
	}
	// Deterministic, and independent of the order the caller lists the tracks in.
	again, _ := WithSubtitles(orig.Manifest, []SubtitleInput{track("sub_a", "en", true), track("sub_b", "fr", false)})
	if !bytes.Equal(again.Canonical, got.Canonical) {
		t.Error("the encoding depends on the input order")
	}
	// Removing the last track gives back exactly the manifest without tracks.
	none, err := WithSubtitles(got.Manifest, nil)
	if err != nil || !bytes.Equal(none.Canonical, orig.Canonical) {
		t.Errorf("no tracks is not the original encoding: %v", err)
	}
}

// A manifest with no tracks does not mention them, so what was signed before tracks existed is
// unchanged, and a reader that does not know the member ignores it when it is there.
func TestSubtitlesAreBackwardsCompatible(t *testing.T) {
	orig := mustBuild(t, fixedInput())
	if bytes.Contains(orig.Canonical, []byte("subtitles")) {
		t.Error("a manifest without tracks mentions subtitles")
	}
	got, err := WithSubtitles(orig.Manifest, []SubtitleInput{track("sub_a", "en", false)})
	if err != nil {
		t.Fatal(err)
	}
	// An older reader's view of the manifest: the same struct without the new member.
	var old struct {
		Schema     string      `json:"schema"`
		Renditions []Rendition `json:"renditions"`
		Artifacts  []Artifact  `json:"artifacts"`
		TopLevel   TopLevel    `json:"top_level"`
	}
	if err := json.Unmarshal(got.Canonical, &old); err != nil {
		t.Fatal(err)
	}
	if old.Schema != Schema || old.TopLevel.Root != orig.Manifest.TopLevel.Root || len(old.Renditions) != 2 {
		t.Errorf("an older reader misreads the manifest: %+v", old)
	}
	// No label or file name: the member list is closed.
	if bytes.Contains(got.Canonical, []byte(`"label"`)) {
		t.Error("the manifest records a label")
	}
}

func TestWithSubtitlesRejects(t *testing.T) {
	orig := mustBuild(t, fixedInput())
	for name, tracks := range map[string][]SubtitleInput{
		"duplicate id":    {track("sub_a", "en", false), track("sub_a", "fr", false)},
		"two defaults":    {track("sub_a", "en", true), track("sub_b", "fr", true)},
		"no language":     {track("sub_a", "", false)},
		"no id":           {track("", "en", false)},
		"object key path": {{ID: "sub_a", Language: "en", Object: obj("t/x/a/y/subtitles/sub_a.vtt", "x")}},
		"traversal":       {{ID: "sub_a", Language: "en", Object: obj("../x.vtt", "x")}},
	} {
		if _, err := WithSubtitles(orig.Manifest, tracks); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	bad := orig.Manifest
	bad.TopLevel.Root = "zz"
	if _, err := WithSubtitles(bad, nil); err == nil || !strings.Contains(err.Error(), "root") {
		t.Errorf("a malformed root: %v", err)
	}
}

func sha256Of(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}
