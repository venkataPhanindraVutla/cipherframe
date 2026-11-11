package signing

import (
	"encoding/binary"
	"errors"

	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
)

// envelopeVersion is the stored envelope format. It is the first byte of the envelope and of the
// associated data, so a change of scheme cannot be confused with an old one.
const envelopeVersion = 1

// aadPurpose is the first field of the associated data. It separates a wrapped signing seed from
// every other wrapped value (content keys, callback secrets): the same bytes cannot be replayed
// as another kind of key, even by a table swap.
const aadPurpose = "signing-key"

// ErrEnvelope is returned for a stored envelope that cannot be read or does not authenticate.
var ErrEnvelope = errors.New("signing: the signing key envelope is unusable")

// binding is everything the associated data of a wrapped seed commits to.
type binding struct {
	keyID      string
	algorithm  string
	provider   string
	kekKeyID   string
	kekVersion string
}

// aad returns the canonical associated data: the envelope version as one byte, then the purpose
// ("signing-key"), key id, algorithm, provider, KEK id and KEK version, each as a 4-byte
// big-endian length followed by its bytes. Length prefixes make the encoding unambiguous.
func aad(b binding) []byte {
	fields := []string{aadPurpose, b.keyID, b.algorithm, b.provider, b.kekKeyID, b.kekVersion}
	out := []byte{envelopeVersion}
	for _, f := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f))) //nolint:gosec // field lengths are tiny
		out = append(out, f...)
	}
	return out
}

// encodeEnvelope serialises w: the envelope version, then provider, KEK id, KEK version and
// ciphertext, each length-prefixed.
func encodeEnvelope(w kms.Wrapped) []byte {
	out := []byte{envelopeVersion}
	for _, f := range [][]byte{[]byte(w.Provider), []byte(w.KeyID), []byte(w.Version), w.Ciphertext} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f))) //nolint:gosec // bounded by the provider
		out = append(out, f...)
	}
	return out
}

func decodeEnvelope(b []byte) (kms.Wrapped, error) {
	if len(b) < 1 || b[0] != envelopeVersion {
		return kms.Wrapped{}, ErrEnvelope
	}
	rest := b[1:]
	var parts [4][]byte
	for i := range parts {
		if len(rest) < 4 {
			return kms.Wrapped{}, ErrEnvelope
		}
		n := binary.BigEndian.Uint32(rest)
		rest = rest[4:]
		if uint64(n) > uint64(len(rest)) {
			return kms.Wrapped{}, ErrEnvelope
		}
		parts[i], rest = rest[:n], rest[n:]
	}
	if len(rest) != 0 || len(parts[0]) == 0 || len(parts[3]) == 0 {
		return kms.Wrapped{}, ErrEnvelope
	}
	return kms.Wrapped{
		Provider: string(parts[0]), KeyID: string(parts[1]), Version: string(parts[2]),
		Ciphertext: append([]byte(nil), parts[3]...),
	}, nil
}
