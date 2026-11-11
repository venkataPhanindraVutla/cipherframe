package keys_test

import (
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

type builtKey struct {
	name   string
	bucket keys.Bucket
	key    string
}

func allKeys(t *testing.T, tn id.TenantID, a id.AssetID) []builtKey {
	t.Helper()
	r, err := keys.ParseRendition("720p")
	if err != nil {
		t.Fatal(err)
	}
	return []builtKey{
		{"NewSource", keys.Source, keys.NewSource(tn, a)},
		{"Master", keys.Delivery, keys.Master(tn, a)},
		{"Playlist", keys.Delivery, keys.Playlist(tn, a, r)},
		{"InitSegment", keys.Delivery, keys.InitSegment(tn, a, r)},
		{"Segment0", keys.Delivery, keys.Segment(tn, a, r, 0)},
		{"Segment9999", keys.Delivery, keys.Segment(tn, a, r, 9999)},
		{"Poster", keys.Delivery, keys.Poster(tn, a)},
	}
}

func TestEveryKeyIsCoveredByAnAssetPrefix(t *testing.T) {
	tn, a := id.New[id.TenantKind](), id.New[id.AssetKind]()
	prefixes := keys.AssetPrefixes(tn, a)
	for _, k := range allKeys(t, tn, a) {
		covered := false
		for _, p := range prefixes {
			if p.Bucket == k.bucket && strings.HasPrefix(k.key, p.Prefix) {
				covered = true
			}
		}
		if !covered {
			t.Errorf("%s: key is not under any prefix of its bucket %q", k.name, k.bucket)
		}
	}
}

func TestKeysContainOnlyTypedIDsAndFixedNames(t *testing.T) {
	tn, a := id.New[id.TenantKind](), id.New[id.AssetKind]()
	for _, k := range allKeys(t, tn, a) {
		if !strings.HasPrefix(k.key, "t/"+tn.String()+"/a/"+a.String()+"/") {
			t.Errorf("%s: unexpected layout %q", k.name, k.key)
		}
		if strings.Contains(k.key, "//") || strings.Contains(k.key, "..") || strings.HasPrefix(k.key, "/") {
			t.Errorf("%s: malformed key %q", k.name, k.key)
		}
	}
}

func TestAssetPrefixesAreDistinctPerAsset(t *testing.T) {
	tn := id.New[id.TenantKind]()
	a, b := id.New[id.AssetKind](), id.New[id.AssetKind]()
	prefixes := keys.AssetPrefixes(tn, a)
	if len(prefixes) != 2 {
		t.Fatal("want one prefix per bucket")
	}
	for _, pa := range prefixes {
		for _, kb := range allKeys(t, tn, b) {
			if kb.bucket == pa.Bucket && strings.HasPrefix(kb.key, pa.Prefix) {
				t.Errorf("key of another asset falls under prefix %q", pa.Prefix)
			}
		}
	}
}

func TestNewSourceHasARandomComponent(t *testing.T) {
	tn, a := id.New[id.TenantKind](), id.New[id.AssetKind]()
	prefix := "t/" + tn.String() + "/a/" + a.String() + "/source/"
	seen := map[string]bool{}
	for range 50 {
		k := keys.NewSource(tn, a)
		if !strings.HasPrefix(k, prefix) {
			t.Fatalf("key %q is not under %q", k, prefix)
		}
		rnd := strings.TrimPrefix(k, prefix)
		if len(rnd) != 2*keys.SourceRandomBytes || strings.Trim(rnd, "0123456789abcdef") != "" {
			t.Fatalf("random component %q is not %d hex characters", rnd, 2*keys.SourceRandomBytes)
		}
		if seen[k] {
			t.Fatalf("key %q repeated", k)
		}
		seen[k] = true
	}
}

func TestParseRendition(t *testing.T) {
	for _, ok := range []string{"720p", "a", "audio_128", "0123456789abcdef"} {
		if _, err := keys.ParseRendition(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "../x", "A", "a/b", "a b", "0123456789abcdefg", "é"} {
		if _, err := keys.ParseRendition(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestZeroIDsPanic(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	keys.NewSource(id.TenantID{}, id.New[id.AssetKind]())
}

func TestHLSPrefixCoversEveryHLSKeyAndNothingElse(t *testing.T) {
	tn, a := id.New[id.TenantKind](), id.New[id.AssetKind]()
	for _, k := range allKeys(t, tn, a) {
		under := strings.HasPrefix(k.key, keys.HLSPrefix(tn, a))
		isHLS := k.bucket == keys.Delivery && k.name != "Poster"
		if under != isHLS {
			t.Errorf("%s: under HLSPrefix = %v, want %v", k.name, under, isHLS)
		}
	}
}
