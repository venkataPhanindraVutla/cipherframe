// Package purge is verified deletion (M6, ADR 0040): the registry of every kind of object the
// system stores for an asset, the asset.delete job that removes them and destroys the content keys,
// and the signed deletion record it leaves behind.
//
// Deletion never trusts the database alone. It enumerates storage under every prefix of
// keys.AssetPrefixes, so an object an attempt uploaded but never registered is removed too, and it
// classifies what it finds with Classify so the deletion record can say how many objects of each
// kind and variant were removed (invariant I6).
package purge

import (
	"strings"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// Kind names a kind of stored object, as it appears in a deletion record.
type Kind string

// The kinds. Every key the system can write under an asset's prefixes classifies as one of these
// except Other, which only an object nothing in this codebase writes can be.
const (
	// KindSource is the uploaded original in the source bucket.
	KindSource Kind = "source"
	// KindTusInfo and KindTusPart are tusd's bookkeeping objects beside the source (".info" holds
	// the upload's metadata, ".part" an incomplete trailing part).
	KindTusInfo Kind = "tus_info"
	KindTusPart Kind = "tus_part"
	// The HLS objects of one variant.
	KindMaster   Kind = "master"
	KindPlaylist Kind = "playlist"
	KindInit     Kind = "init"
	KindSegment  Kind = "segment"
	// KindPoster is the poster image (not written yet; registered so M7 cannot forget it).
	KindPoster Kind = "poster"
	// KindOther is anything else under an asset prefix. It is deleted like the rest and counted
	// separately, so an unexpected object shows up in the record instead of vanishing.
	KindOther Kind = "other"
)

// Entry is one registered kind.
type Entry struct {
	Kind   Kind
	Bucket keys.Bucket
	// PerVariant says whether the kind exists once per variant (HLS objects) or not.
	PerVariant bool
	// Artifact is the asset_artifacts.kind that registers the kind, or "" when the registry table
	// does not hold it (the source side objects).
	Artifact db.ArtifactKind
}

// Registry lists every kind the purge knows. A new kind of stored object is added here (and to
// Classify), or the registry test fails.
func Registry() []Entry {
	return []Entry{
		{Kind: KindSource, Bucket: keys.Source},
		{Kind: KindTusInfo, Bucket: keys.Source},
		{Kind: KindTusPart, Bucket: keys.Source},
		{Kind: KindMaster, Bucket: keys.Delivery, PerVariant: true, Artifact: db.ArtifactMaster},
		{Kind: KindPlaylist, Bucket: keys.Delivery, PerVariant: true, Artifact: db.ArtifactPlaylist},
		{Kind: KindInit, Bucket: keys.Delivery, PerVariant: true, Artifact: db.ArtifactInit},
		{Kind: KindSegment, Bucket: keys.Delivery, PerVariant: true, Artifact: db.ArtifactSegment},
		{Kind: KindPoster, Bucket: keys.Delivery, Artifact: db.ArtifactPoster},
	}
}

// Class is what Classify makes of one object key.
type Class struct {
	Bucket keys.Bucket
	Kind   Kind
	// Variant is "original" or "masked" for an HLS object and empty for anything else.
	Variant string
}

// Classify says which registered kind (and variant) the object at key is. key must lie under one
// of the asset's prefixes in the bucket; anything unrecognised is KindOther.
func Classify(tenant id.TenantID, asset id.AssetID, bucket keys.Bucket, key string) Class {
	c := Class{Bucket: bucket, Kind: KindOther}
	switch bucket {
	case keys.Source:
		if !strings.HasPrefix(key, keys.SourcePrefix(tenant, asset)) {
			return c
		}
		switch {
		case strings.HasSuffix(key, ".info"):
			c.Kind = KindTusInfo
		case strings.HasSuffix(key, ".part"):
			c.Kind = KindTusPart
		default:
			c.Kind = KindSource
		}
	case keys.Delivery:
		rest, ok := strings.CutPrefix(key, keys.DeliveryPrefix(tenant, asset))
		if !ok {
			return c
		}
		if rest == "poster.jpg" {
			c.Kind = KindPoster
			return c
		}
		for _, v := range []keys.Variant{keys.Original, keys.Masked} {
			hls, ok := strings.CutPrefix(key, keys.VariantHLSPrefix(tenant, asset, v))
			if !ok {
				continue
			}
			c.Variant = v.String()
			c.Kind = hlsKind(hls)
			return c
		}
	}
	return c
}

// hlsKind classifies a path relative to a variant's HLS prefix.
func hlsKind(rel string) Kind {
	if rel == "master.m3u8" {
		return KindMaster
	}
	rendition, name, ok := strings.Cut(rel, "/")
	if !ok || rendition == "" || strings.Contains(name, "/") {
		return KindOther
	}
	switch {
	case name == "playlist.m3u8":
		return KindPlaylist
	case name == "init.mp4":
		return KindInit
	case strings.HasPrefix(name, "seg-") && strings.HasSuffix(name, ".m4s"):
		return KindSegment
	}
	return KindOther
}
