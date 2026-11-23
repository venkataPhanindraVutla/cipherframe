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
		{"Poster", keys.Delivery, keys.VariantPoster(tn, a, keys.Original)},
		{"Sprite", keys.Delivery, keys.VariantSprite(tn, a, keys.Original)},
		{"Thumbnails", keys.Delivery, keys.VariantThumbnails(tn, a, keys.Original)},
		{"MaskedPoster", keys.Delivery, keys.VariantPoster(tn, a, keys.Masked)},
		{"MaskedSprite", keys.Delivery, keys.VariantSprite(tn, a, keys.Masked)},
		{"MaskedThumbnails", keys.Delivery, keys.VariantThumbnails(tn, a, keys.Masked)},
		{"Subtitle", keys.Delivery, keys.Subtitle(tn, a, id.New[id.SubtitleKind]())},
		{"MaskedMaster", keys.Delivery, keys.VariantMaster(tn, a, keys.Masked)},
		{"MaskedPlaylist", keys.Delivery, keys.VariantPlaylist(tn, a, keys.Masked, r)},
		{"MaskedInitSegment", keys.Delivery, keys.VariantInitSegment(tn, a, keys.Masked, r)},
		{"MaskedSegment7", keys.Delivery, keys.VariantSegment(tn, a, keys.Masked, r, 7)},
		{"PlaylistGen2", keys.Delivery, keys.VariantPlaylistGen(tn, a, keys.Original, r, 2)},
		{"SegmentGen2", keys.Delivery, keys.VariantSegmentGen(tn, a, keys.Original, r, 3, 2)},
		{"MaskedSegmentGen1", keys.Delivery, keys.VariantSegmentGen(tn, a, keys.Masked, r, 3, 1)},
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
		isHLS := k.bucket == keys.Delivery && k.name != "Subtitle" && !strings.HasPrefix(k.name, "Masked")
		if under != isHLS {
			t.Errorf("%s: under HLSPrefix = %v, want %v", k.name, under, isHLS)
		}
	}
}

func TestVariantLayout(t *testing.T) {
	tn, a := id.New[id.TenantKind](), id.New[id.AssetKind]()
	root := "t/" + tn.String() + "/a/" + a.String() + "/"
	r, _ := keys.ParseRendition("720p")
	if got, want := keys.Master(tn, a), root+"hls/master.m3u8"; got != want {
		t.Errorf("original master moved: %q, want %q", got, want)
	}
	if got, want := keys.VariantMaster(tn, a, keys.Masked), root+"masked/hls/master.m3u8"; got != want {
		t.Errorf("masked master = %q, want %q", got, want)
	}
	if got, want := keys.VariantSegment(tn, a, keys.Masked, r, 3), root+"masked/hls/720p/seg-3.m4s"; got != want {
		t.Errorf("masked segment = %q, want %q", got, want)
	}
	if strings.HasPrefix(keys.VariantHLSPrefix(tn, a, keys.Masked), keys.VariantHLSPrefix(tn, a, keys.Original)) ||
		strings.HasPrefix(keys.VariantHLSPrefix(tn, a, keys.Original), keys.VariantHLSPrefix(tn, a, keys.Masked)) {
		t.Error("variant prefixes overlap")
	}
	if keys.Variant("other").Valid() || !keys.Masked.Valid() || !keys.Original.Valid() {
		t.Error("Variant.Valid is wrong")
	}
}

func TestBrandLogoKeysAreTheTenantsAndOutsideEveryAssetPrefix(t *testing.T) {
	tn, a := id.New[id.TenantKind](), id.New[id.AssetKind]()
	v := id.New[id.LogoVersionKind]()
	key := keys.BrandLogo(tn, v)
	if want := "t/" + tn.String() + "/branding/logo/" + v.String() + ".png"; key != want {
		t.Fatalf("key = %q, want %q", key, want)
	}
	if !strings.HasPrefix(key, keys.BrandLogoPrefix(tn)) {
		t.Error("the key is not under the branding prefix")
	}
	for _, p := range keys.AssetPrefixes(tn, a) {
		if strings.HasPrefix(key, p.Prefix) {
			t.Errorf("a logo key falls under the asset prefix %q", p.Prefix)
		}
	}
	other := id.New[id.TenantKind]()
	if strings.HasPrefix(keys.BrandLogo(other, v), keys.BrandLogoPrefix(tn)) {
		t.Error("two tenants share a branding prefix")
	}
}

func TestSplitGeneration(t *testing.T) {
	tn, a := id.New[id.TenantKind](), id.New[id.AssetKind]()
	r, _ := keys.ParseRendition("720p")
	prefix := keys.VariantHLSPrefix(tn, a, keys.Original)
	for gen := range 4 {
		rel := strings.TrimPrefix(keys.VariantSegmentGen(tn, a, keys.Original, r, 5, gen), prefix)
		g, rest := keys.SplitGeneration(rel)
		if g != gen || rest != "720p/seg-5.m4s" {
			t.Errorf("generation %d: got (%d, %q) from %q", gen, g, rest, rel)
		}
	}
	for _, rel := range []string{"master.m3u8", "k0/720p/seg-0.m4s", "k01/720p/x", "kx/720p/x", "k/720p/x", "k1", "720p/seg-0.m4s"} {
		if g, rest := keys.SplitGeneration(rel); g != 0 || rest != rel {
			t.Errorf("%q: got (%d, %q), want generation 0 and the same path", rel, g, rest)
		}
	}
}

func TestWithGeneration(t *testing.T) {
	for _, c := range []struct {
		rel  string
		gen  int
		want string
	}{
		{"720p/seg-0.m4s", 1, "k1/720p/seg-0.m4s"},
		{"k1/720p/seg-0.m4s", 2, "k2/720p/seg-0.m4s"},
		{"k2/720p/playlist.m3u8", 0, "720p/playlist.m3u8"},
		{"720p/playlist.m3u8", 0, "720p/playlist.m3u8"},
	} {
		if got := keys.WithGeneration(c.rel, c.gen); got != c.want {
			t.Errorf("WithGeneration(%q, %d) = %q, want %q", c.rel, c.gen, got, c.want)
		}
	}
}
