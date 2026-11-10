// Package keys is the only place Cipherframe builds object-storage keys and the
// prefixes deletion enumerates (ADR 0014).
//
// Keys are made of typed IDs and fixed names only. User-supplied names (file names, titles, labels)
// never appear in a key. Deletion prefixes come from AssetPrefixes in this same file, so the keys
// written and the prefixes enumerated cannot drift apart; the package tests check that every key a
// builder returns falls under one of its asset's prefixes in the right bucket.
//
// The builders panic on a zero ID. A zero ID can only come from a programming error (IDs read from
// the database or parsed from input are never zero), and building "t//a//" would produce a key that
// no prefix of a real asset covers.
package keys

import (
	"errors"
	"strconv"

	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// Bucket names the role of a bucket. It is the role, not the configured bucket name.
type Bucket string

// The two buckets (ADR 0014, docs/architecture.md).
const (
	Source   Bucket = "source"
	Delivery Bucket = "delivery"
)

// Prefix is a key prefix inside one bucket.
type Prefix struct {
	Bucket Bucket
	Prefix string
}

// Rendition names an output rendition such as "720p". It is system-chosen, never user input.
type Rendition struct{ name string }

// ErrRendition is returned by ParseRendition for a rejected name.
var ErrRendition = errors.New("keys: rendition name must be 1 to 16 characters from [a-z0-9_]")

// ParseRendition accepts 1 to 16 characters from [a-z0-9_].
func ParseRendition(s string) (Rendition, error) {
	if len(s) == 0 || len(s) > 16 {
		return Rendition{}, ErrRendition
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return Rendition{}, ErrRendition
		}
	}
	return Rendition{name: s}, nil
}

// String returns the rendition name.
func (r Rendition) String() string { return r.name }

func assetRoot(t id.TenantID, a id.AssetID) string {
	if t.IsZero() || a.IsZero() {
		panic("keys: zero tenant or asset ID")
	}
	return "t/" + t.String() + "/a/" + a.String() + "/"
}

// SourceOriginal is the key of the uploaded original in the source bucket.
func SourceOriginal(t id.TenantID, a id.AssetID) string {
	return SourcePrefix(t, a) + "original"
}

// SourcePrefix is the prefix of everything stored for the asset in the source bucket.
func SourcePrefix(t id.TenantID, a id.AssetID) string {
	return assetRoot(t, a) + "source/"
}

// DeliveryPrefix is the prefix of everything stored for the asset in the delivery bucket.
func DeliveryPrefix(t id.TenantID, a id.AssetID) string {
	return assetRoot(t, a)
}

func renditionName(r Rendition) string {
	if r.name == "" {
		panic("keys: zero rendition")
	}
	return r.name
}

// Master is the key of the master playlist in the delivery bucket.
func Master(t id.TenantID, a id.AssetID) string {
	return DeliveryPrefix(t, a) + "hls/master.m3u8"
}

// Playlist is the key of a rendition's media playlist in the delivery bucket.
func Playlist(t id.TenantID, a id.AssetID, r Rendition) string {
	return DeliveryPrefix(t, a) + "hls/" + renditionName(r) + "/playlist.m3u8"
}

// InitSegment is the key of a rendition's initialization segment in the delivery bucket.
func InitSegment(t id.TenantID, a id.AssetID, r Rendition) string {
	return DeliveryPrefix(t, a) + "hls/" + renditionName(r) + "/init.mp4"
}

// Segment is the key of media segment n (n >= 0) of a rendition in the delivery bucket.
func Segment(t id.TenantID, a id.AssetID, r Rendition, n int) string {
	if n < 0 {
		panic("keys: negative segment number")
	}
	return DeliveryPrefix(t, a) + "hls/" + renditionName(r) + "/seg-" + strconv.Itoa(n) + ".m4s"
}

// Poster is the key of the poster image in the delivery bucket.
func Poster(t id.TenantID, a id.AssetID) string {
	return DeliveryPrefix(t, a) + "poster.jpg"
}

// AssetPrefixes returns every (bucket, prefix) pair that deleting the asset must enumerate. Anything
// the system stores for the asset lies under one of them.
func AssetPrefixes(t id.TenantID, a id.AssetID) []Prefix {
	return []Prefix{
		{Bucket: Source, Prefix: SourcePrefix(t, a)},
		{Bucket: Delivery, Prefix: DeliveryPrefix(t, a)},
	}
}
