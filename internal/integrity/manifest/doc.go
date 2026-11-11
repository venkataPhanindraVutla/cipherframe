// Package manifest builds the signed integrity manifest of an asset (ADR 0033, M5-1).
//
// A manifest records, for one asset, the SHA-256 and size of every object the pipeline stored in
// the delivery bucket, the Merkle root of each rendition and a top-level root over the renditions
// and the playlists. It is serialised in canonical form (RFC 8785, package jcs) and signed as a
// DSSE envelope (package dsse) by the caller.
//
// The package is pure: it does no I/O and holds no key. Build takes values the pipeline already
// has and returns the manifest, its canonical bytes and the top-level root.
//
// Format rules:
//
//   - Field names are lower_snake_case and no value is a floating-point number: bandwidth and
//     sizes are integers and the frame rate is a rational string such as "30000/1001".
//   - Hashes are lowercase hex. Times are RFC 3339 in UTC with second precision.
//   - Paths are relative to the asset's HLS prefix, the same convention as the variant URIs of the
//     master playlist. The manifest never holds a bucket name or an object key, and it never refers
//     to the source object; the source appears only by the hash and size recorded at ingest.
//
// Trees (RFC 9162 hashing, package merkle). A rendition's leaves are its init segment and then its
// media segments in playlist order; each leaf's data is the artifact's 32-byte SHA-256. The
// top-level leaves are, in this fixed order, each rendition root in ladder order, the master
// playlist's SHA-256, then each media playlist's SHA-256 in ladder order. The manifest records the
// labels of those leaves in top_level.order.
package manifest
