package purge

import (
	"slices"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

func newIDs() (id.TenantID, id.AssetID) { return id.New[id.TenantKind](), id.New[id.AssetKind]() }

// TestPurgeCoversEveryKeyTheSystemWrites enumerates keys.AssetPrefixes and every key builder of
// package keys: each key must lie under a prefix of its own bucket, so the purge's enumeration
// reaches it, and must classify as a registered kind (invariant I6).
func TestPurgeCoversEveryKeyTheSystemWrites(t *testing.T) {
	tenant, asset := newIDs()
	r720, err := keys.ParseRendition("720p")
	if err != nil {
		t.Fatal(err)
	}
	src := keys.NewSource(tenant, asset)
	type written struct {
		bucket keys.Bucket
		key    string
		kind   Kind
		vari   string
	}
	all := []written{
		{keys.Source, src, KindSource, ""},
		{keys.Source, src + ".info", KindTusInfo, ""},
		{keys.Source, src + ".part", KindTusPart, ""},
		{keys.Delivery, keys.Poster(tenant, asset), KindPoster, ""},
	}
	for _, v := range []keys.Variant{keys.Original, keys.Masked} {
		all = append(all,
			written{keys.Delivery, keys.VariantMaster(tenant, asset, v), KindMaster, v.String()},
			written{keys.Delivery, keys.VariantPlaylist(tenant, asset, v, r720), KindPlaylist, v.String()},
			written{keys.Delivery, keys.VariantInitSegment(tenant, asset, v, r720), KindInit, v.String()},
			written{keys.Delivery, keys.VariantSegment(tenant, asset, v, r720, 0), KindSegment, v.String()},
			written{keys.Delivery, keys.VariantSegment(tenant, asset, v, r720, 123), KindSegment, v.String()},
		)
	}
	all = append(all,
		written{keys.Delivery, keys.Master(tenant, asset), KindMaster, "original"},
		written{keys.Delivery, keys.Playlist(tenant, asset, r720), KindPlaylist, "original"},
		written{keys.Delivery, keys.InitSegment(tenant, asset, r720), KindInit, "original"},
		written{keys.Delivery, keys.Segment(tenant, asset, r720, 7), KindSegment, "original"},
	)
	prefixes := keys.AssetPrefixes(tenant, asset)
	registered := map[Kind]bool{}
	for _, e := range Registry() {
		registered[e.Kind] = true
	}
	for _, w := range all {
		covered := slices.ContainsFunc(prefixes, func(p keys.Prefix) bool {
			return p.Bucket == w.bucket && strings.HasPrefix(w.key, p.Prefix)
		})
		if !covered {
			t.Errorf("%s key %q is under no prefix of keys.AssetPrefixes", w.bucket, w.key)
		}
		got := Classify(tenant, asset, w.bucket, w.key)
		if got.Kind != w.kind || got.Variant != w.vari || got.Bucket != w.bucket {
			t.Errorf("Classify(%q) = %+v, want kind %s variant %q", w.key, got, w.kind, w.vari)
		}
		if !registered[got.Kind] {
			t.Errorf("kind %s is not in the registry", got.Kind)
		}
	}
}

func TestRegistryHoldsEveryArtifactKind(t *testing.T) {
	have := map[db.ArtifactKind]bool{}
	for _, e := range Registry() {
		if e.Artifact != "" {
			have[e.Artifact] = true
		}
	}
	for _, k := range db.ArtifactKinds() {
		if !have[k] {
			t.Errorf("asset_artifacts kind %q is not registered with the purge", k)
		}
		if !k.Valid() {
			t.Errorf("db.ArtifactKinds lists an invalid kind %q", k)
		}
	}
}

func TestClassifyUnknownObjects(t *testing.T) {
	tenant, asset := newIDs()
	other := id.New[id.AssetKind]()
	if c := Classify(tenant, asset, keys.Delivery, keys.DeliveryPrefix(tenant, asset)+"hls/720p/odd.bin"); c.Kind != KindOther || c.Variant != "original" {
		t.Errorf("unknown HLS object: %+v", c)
	}
	if c := Classify(tenant, asset, keys.Delivery, keys.DeliveryPrefix(tenant, asset)+"thumbs/1.jpg"); c.Kind != KindOther {
		t.Errorf("unknown delivery object: %+v", c)
	}
	if c := Classify(tenant, asset, keys.Source, keys.SourcePrefix(tenant, other)+"abc"); c.Kind != KindOther {
		t.Errorf("another asset's object: %+v", c)
	}
}
