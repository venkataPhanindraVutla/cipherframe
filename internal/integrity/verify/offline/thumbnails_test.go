package offline_test

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/jcs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline/offlinetest"
)

// A thumbnail object is verified by its path under the variant that owns it, appears in that
// variant's Paths, and is never found under the other variant.
func TestThumbnailsVerifyPerVariant(t *testing.T) {
	f := offlinetest.New(t)
	art := func(kind, path, content string) manifest.Artifact {
		sum := sha256.Sum256([]byte(content))
		return manifest.Artifact{Kind: kind, Path: path, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(content))}
	}
	m := f.Built.Manifest
	m.Thumbnails = []manifest.Artifact{art(manifest.KindPoster, "poster.jpg", "original poster")}
	if m.Masked == nil {
		t.Skip("the fixture has no masked variant")
	}
	masked := *m.Masked
	masked.Thumbnails = []manifest.Artifact{art(manifest.KindPoster, "poster.jpg", "masked poster")}
	m.Masked = &masked
	canonical, err := jcs.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	k := offlinetest.NewKey("sk_a", "a")
	env := offlinetest.Sign(t, canonical, k)
	keys, err := offline.ParseKeySet(offlinetest.KeySetJSON([]offlinetest.Key{k}, map[string]string{"sk_a": "active"}))
	if err != nil {
		t.Fatal(err)
	}
	orig, mask := sha256.Sum256([]byte("original poster")), sha256.Sum256([]byte("masked poster"))
	if r := offline.VerifyArtifact(env, keys, "poster.jpg", orig, "original"); r.Outcome != offline.Ours {
		t.Errorf("original poster: %+v", r)
	}
	if r := offline.VerifyArtifact(env, keys, "poster.jpg", mask, "masked"); r.Outcome != offline.Ours {
		t.Errorf("masked poster: %+v", r)
	}
	// The original's image never passes as the masked variant's.
	if r := offline.VerifyArtifact(env, keys, "poster.jpg", orig, "masked"); r.Outcome != offline.Modified {
		t.Errorf("the original poster verified as the masked one: %+v", r)
	}
	signed, err := offline.Open(env, keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"original", "masked"} {
		if !slices.Contains(signed.Paths(v), "poster.jpg") {
			t.Errorf("%s Paths lacks the poster: %v", v, signed.Paths(v))
		}
	}
}
