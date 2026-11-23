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
	"strings"

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

// VariantGenPrefix is the prefix of the encrypted objects (media segments and media playlists) of
// one key generation of a variant (ADR 0068). Generation 0 is the variant's HLS prefix itself, where
// every asset starts; generation n > 0, made by the n-th re-key, is "k<n>/" under it. It panics on an
// unknown variant or a negative generation.
func VariantGenPrefix(t id.TenantID, a id.AssetID, v Variant, gen int) string {
	if gen < 0 {
		panic("keys: negative generation")
	}
	if gen == 0 {
		return VariantHLSPrefix(t, a, v)
	}
	return VariantHLSPrefix(t, a, v) + "k" + strconv.Itoa(gen) + "/"
}

// SplitGeneration splits a path relative to a variant's HLS prefix into its key generation and the
// path inside that generation: "k2/720p/seg-0.m4s" is (2, "720p/seg-0.m4s"), anything else
// generation 0. Only a "k" followed by a positive number without leading zeros counts, so it
// cannot be confused with a rendition name (renditions are named like "720p").
func SplitGeneration(rel string) (gen int, rest string) {
	dir, tail, ok := strings.Cut(rel, "/")
	if !ok || len(dir) < 2 || dir[0] != 'k' || dir[1] == '0' {
		return 0, rel
	}
	n, err := strconv.Atoi(dir[1:])
	if err != nil || n < 1 || dir[1:] != strconv.Itoa(n) {
		return 0, rel
	}
	return n, tail
}

// WithGeneration moves a path relative to a variant's HLS prefix to key generation gen: the same
// path inside "k<gen>/", or the bare path for generation 0.
func WithGeneration(rel string, gen int) string {
	_, rest := SplitGeneration(rel)
	if gen == 0 {
		return rest
	}
	return "k" + strconv.Itoa(gen) + "/" + rest
}

// VariantMaster is the key of a variant's master playlist in the delivery bucket.
func VariantMaster(t id.TenantID, a id.AssetID, v Variant) string {
	return VariantHLSPrefix(t, a, v) + "master.m3u8"
}

// VariantPlaylist is the key of a variant's rendition media playlist in the delivery bucket.
func VariantPlaylist(t id.TenantID, a id.AssetID, v Variant, r Rendition) string {
	return VariantPlaylistGen(t, a, v, r, 0)
}

// VariantPlaylistGen is VariantPlaylist for one key generation (ADR 0068). Its media segments are
// VariantSegmentGen of the same generation; the init segment and the master playlist are shared by
// every generation.
func VariantPlaylistGen(t id.TenantID, a id.AssetID, v Variant, r Rendition, gen int) string {
	return VariantGenPrefix(t, a, v, gen) + renditionName(r) + "/playlist.m3u8"
}

// VariantInitSegment is the key of a variant's rendition initialization segment.
func VariantInitSegment(t id.TenantID, a id.AssetID, v Variant, r Rendition) string {
	return VariantHLSPrefix(t, a, v) + renditionName(r) + "/init.mp4"
}

// VariantSegment is the key of media segment n (n >= 0) of a variant's rendition.
func VariantSegment(t id.TenantID, a id.AssetID, v Variant, r Rendition, n int) string {
	return VariantSegmentGen(t, a, v, r, n, 0)
}

// VariantSegmentGen is VariantSegment for one key generation (ADR 0068).
func VariantSegmentGen(t id.TenantID, a id.AssetID, v Variant, r Rendition, n, gen int) string {
	if n < 0 {
		panic("keys: negative segment number")
	}
	return VariantGenPrefix(t, a, v, gen) + renditionName(r) + "/seg-" + strconv.Itoa(n) + ".m4s"
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

// VariantPoster, VariantSprite and VariantThumbnails are the keys of a variant's poster image, sprite
// sheet and WebVTT thumbnail track (ADR 0046). They sit directly under the variant's HLS prefix, so
// a masked variant's images can never share a key with the original's, and the prefix scan that
// removes a variant's output removes them too.
func VariantPoster(t id.TenantID, a id.AssetID, v Variant) string {
	return VariantHLSPrefix(t, a, v) + "poster.jpg"
}

// VariantSprite is the key of a variant's sprite sheet.
func VariantSprite(t id.TenantID, a id.AssetID, v Variant) string {
	return VariantHLSPrefix(t, a, v) + "sprite.jpg"
}

// VariantThumbnails is the key of a variant's WebVTT thumbnail track.
func VariantThumbnails(t id.TenantID, a id.AssetID, v Variant) string {
	return VariantHLSPrefix(t, a, v) + "thumbnails.vtt"
}

// Subtitle is the key of one subtitle track (WebVTT) in the delivery bucket (ADR 0044). The track ID
// is system-made; the language and label are never part of a key. Tracks are shared by every
// variant, so the key sits beside the HLS trees, not in one.
func Subtitle(t id.TenantID, a id.AssetID, track id.SubtitleID) string {
	if track.IsZero() {
		panic("keys: zero subtitle ID")
	}
	return DeliveryPrefix(t, a) + "subtitles/" + track.String() + ".vtt"
}

// BrandLogoPrefix is the prefix of every version of the tenant's brand logo in the delivery bucket
// (ADR 0049). It is the tenant's, not an asset's: it lies outside every AssetPrefixes entry, so
// deleting an asset never reaches a logo.
func BrandLogoPrefix(t id.TenantID) string {
	if t.IsZero() {
		panic("keys: zero tenant ID")
	}
	return "t/" + t.String() + "/branding/logo/"
}

// BrandLogo is the key of one immutable version of the tenant's brand logo, a PNG that Cipherframe
// itself encoded. The version ID is system-made; the name the tenant uploaded never reaches a key.
func BrandLogo(t id.TenantID, v id.LogoVersionID) string {
	if v.IsZero() {
		panic("keys: zero logo version ID")
	}
	return BrandLogoPrefix(t) + v.String() + ".png"
}

// AssetPrefixes returns every (bucket, prefix) pair that deleting the asset must enumerate. Anything
// the system stores for the asset lies under one of them.
func AssetPrefixes(t id.TenantID, a id.AssetID) []Prefix {
	return []Prefix{
		{Bucket: Source, Prefix: SourcePrefix(t, a)},
		{Bucket: Delivery, Prefix: DeliveryPrefix(t, a)},
	}
}
