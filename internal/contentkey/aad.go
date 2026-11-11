// Package contentkey creates, reads and destroys the per-asset content keys (M2-1, invariant I7).
// A content key is a random AES-128 key (the HLS segment cipher). It is stored only as an
// envelope: wrapped by a key-encryption key held by a key provider (package kms), with associated
// data that binds the wrapped bytes to their asset, their key slot and the KEK that made them.
//
// A plaintext key lives only inside a ContentKey, which redacts every printed form, and is never
// logged, stored or placed in an error.
package contentkey

import (
	"encoding/binary"

	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// EnvelopeVersion is the current envelope format. It is stored with every row and is the first byte
// of the associated data, so a change of scheme cannot be confused with an old one.
const EnvelopeVersion = 1

// Binding is everything the associated data of a wrapped content key commits to (ADR 0020).
type Binding struct {
	EnvelopeVersion int
	AssetID         id.AssetID
	ContentKeyID    id.ContentKeyID
	Provider        string
	KEKKeyID        string
	KEKVersion      string
}

// AAD returns the canonical associated data for b: the envelope version as one byte, then each of
// the asset id, content key id, provider, KEK key id and KEK version as a 4-byte big-endian length
// followed by its bytes. The length prefixes make the encoding unambiguous, so no two different
// bindings produce the same bytes. The ids use their text form, which is canonical.
//
// An envelope version outside 1..255 is not representable and yields nil; callers treat a nil
// result as a failure.
func AAD(b Binding) []byte {
	if b.EnvelopeVersion < 1 || b.EnvelopeVersion > 255 {
		return nil
	}
	fields := []string{b.AssetID.String(), b.ContentKeyID.String(), b.Provider, b.KEKKeyID, b.KEKVersion}
	n := 1
	for _, f := range fields {
		n += 4 + len(f)
	}
	out := make([]byte, 0, n)
	out = append(out, byte(b.EnvelopeVersion)) //nolint:gosec // range checked above
	for _, f := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f))) //nolint:gosec // field lengths are tiny
		out = append(out, f...)
	}
	return out
}
