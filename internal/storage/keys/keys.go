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
	"crypto/rand"
	"encoding/hex"
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

// SourceRandomBytes is the length of the random component of a source key.
const SourceRandomBytes = 16

// NewSource returns a fresh key for the uploaded original in the source bucket. It ends in a
// random component (128 bits, hex), so the key cannot be derived from the tenant and asset IDs.
// It is stored on the asset row and must never be returned to a client or logged. Every key it
// returns lies under SourcePrefix, so deletion by prefix covers it.
func NewSource(t id.TenantID, a id.AssetID) string {
	var b [SourceRandomBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("keys: no randomness available") // crypto/rand does not fail on supported platforms
	}
	return SourcePrefix(t, a) + hex.EncodeToString(b[:])
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

// Variant names a rendering of an asset: the uploaded video as it is, or a version with faces masked
// (ADR 0036). Each variant has its own HLS tree and its own content key.
type Variant string

// The variants. Original is where HLS has always lived, so existing data does not move.
const (
	Original Variant = "original"
	Masked   Variant = "masked"
)

// Valid reports whether v is a known variant.
func (v Variant) Valid() bool { return v == Original || v == Masked }

func (v Variant) String() string { return string(v) }

// VariantHLSPrefix is the prefix of every HLS object of one variant of the asset in the delivery
// bucket: the master playlist and each rendition's playlist, init segment and media segments. The
// original variant is under "hls/", the masked one under "masked/hls/", so neither prefix contains
// the other. It panics on an unknown variant.
func VariantHLSPrefix(t id.TenantID, a id.AssetID, v Variant) string {
	switch v {
	case Original:
		return DeliveryPrefix(t, a) + "hls/"
	case Masked:
		return DeliveryPrefix(t, a) + "masked/hls/"
	}
	panic("keys: unknown variant")
}

// HLSPrefix is VariantHLSPrefix of the original variant. A retried processing job enumerates it to
// remove the previous attempt's output.
func HLSPrefix(t id.TenantID, a id.AssetID) string { return VariantHLSPrefix(t, a, Original) }

// VariantMaster is the key of a variant's master playlist in the delivery bucket.
func VariantMaster(t id.TenantID, a id.AssetID, v Variant) string {
	return VariantHLSPrefix(t, a, v) + "master.m3u8"
}

// VariantPlaylist is the key of a variant's rendition media playlist in the delivery bucket.
func VariantPlaylist(t id.TenantID, a id.AssetID, v Variant, r Rendition) string {
	return VariantHLSPrefix(t, a, v) + renditionName(r) + "/playlist.m3u8"
}

// VariantInitSegment is the key of a variant's rendition initialization segment.
func VariantInitSegment(t id.TenantID, a id.AssetID, v Variant, r Rendition) string {
	return VariantHLSPrefix(t, a, v) + renditionName(r) + "/init.mp4"
}

// VariantSegment is the key of media segment n (n >= 0) of a variant's rendition.
func VariantSegment(t id.TenantID, a id.AssetID, v Variant, r Rendition, n int) string {
	if n < 0 {
		panic("keys: negative segment number")
	}
	return VariantHLSPrefix(t, a, v) + renditionName(r) + "/seg-" + strconv.Itoa(n) + ".m4s"
}

// Master is the key of the original variant's master playlist.
func Master(t id.TenantID, a id.AssetID) string { return VariantMaster(t, a, Original) }

// Playlist is the key of the original variant's rendition media playlist.
func Playlist(t id.TenantID, a id.AssetID, r Rendition) string {
	return VariantPlaylist(t, a, Original, r)
}

// InitSegment is the key of the original variant's rendition initialization segment.
func InitSegment(t id.TenantID, a id.AssetID, r Rendition) string {
	return VariantInitSegment(t, a, Original, r)
}

// Segment is the key of media segment n (n >= 0) of the original variant's rendition.
func Segment(t id.TenantID, a id.AssetID, r Rendition, n int) string {
	return VariantSegment(t, a, Original, r, n)
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
