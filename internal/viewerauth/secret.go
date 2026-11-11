package viewerauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"

	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
)

// SecretBytes is the length of a callback secret: 32 random bytes.
const SecretBytes = 32

// SecretPrefix starts the text form of a callback secret, as Standard Webhooks writes it.
const SecretPrefix = "whsec_"

// envelopeVersion is the format of a stored secret envelope. It is the first byte of the envelope
// and of the associated data, so a change of scheme cannot be confused with an old one.
const envelopeVersion = 1

// secretPurpose binds a wrapped secret to its use: the same bytes cannot be replayed as another
// kind of wrapped value, even by a table swap.
const secretPurpose = "playback.callback_secret"

// ErrEnvelope is returned for a stored envelope that cannot be read or does not authenticate.
var ErrEnvelope = errors.New("viewerauth: the callback secret envelope is unusable")

// GenerateSecret returns a new random callback secret.
func GenerateSecret() ([]byte, error) {
	b := make([]byte, SecretBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, errors.New("viewerauth: no randomness available")
	}
	return b, nil
}

// FormatSecret returns the text form of a secret, "whsec_" followed by its standard base64: the
// string a tenant stores and a Standard Webhooks library takes.
func FormatSecret(secret []byte) string {
	return SecretPrefix + base64.StdEncoding.EncodeToString(secret)
}

// SecretBox wraps and unwraps callback secrets with the key provider (ADR 0019, 0020).
type SecretBox struct{ reg *kms.Registry }

// NewSecretBox returns a SecretBox over the provider registry.
func NewSecretBox(reg *kms.Registry) *SecretBox { return &SecretBox{reg: reg} }

// secretAAD is the associated data of a wrapped secret: the envelope version as one byte, then the
// purpose, tenant ID, secret version, provider, KEK id and KEK version, each as a 4-byte
// big-endian length followed by its bytes. Length prefixes make the encoding unambiguous.
func secretAAD(tenant id.TenantID, version int, provider, kekID, kekVersion string) []byte {
	fields := []string{secretPurpose, tenant.String(), strconv.Itoa(version), provider, kekID, kekVersion}
	out := []byte{envelopeVersion}
	for _, f := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f))) //nolint:gosec // field lengths are tiny
		out = append(out, f...)
	}
	return out
}

// Seal wraps secret for the tenant and secret version under the current KEK and returns the
// envelope to store: the envelope version, then the provider, KEK id, KEK version and ciphertext,
// each length-prefixed. The associated data binds the wrapped bytes to the tenant, the purpose and
// the version, so an envelope copied to another tenant, or to another version's column, does not
// open.
func (b *SecretBox) Seal(ctx context.Context, tenant id.TenantID, version int, secret []byte) ([]byte, error) {
	if tenant.IsZero() || version < 1 || len(secret) != SecretBytes {
		return nil, errors.New("viewerauth: invalid secret to seal")
	}
	p := b.reg.Current()
	// The associated data names the KEK version, so it is computed from Current and the result is
	// checked against it: a wrap that came back under another version is retried once.
	for range 2 {
		ref, err := p.Current(ctx)
		if err != nil {
			return nil, err
		}
		w, err := p.Wrap(ctx, secret, secretAAD(tenant, version, p.Name(), ref.KeyID, ref.Version))
		if err != nil {
			return nil, err
		}
		if w.Provider == p.Name() && w.Ref() == ref && len(w.Ciphertext) > 0 {
			return encodeEnvelope(w), nil
		}
	}
	return nil, kms.New(kms.Other, p.Name(), "wrap", "provider wrapped under an unexpected KEK version")
}

// Open unwraps an envelope made by Seal for the same tenant and version. The caller clears the
// result when finished. Any failure (an outage, a missing provider, a damaged or swapped envelope)
// is an error and never a secret.
func (b *SecretBox) Open(ctx context.Context, tenant id.TenantID, version int, envelope []byte) ([]byte, error) {
	w, err := decodeEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	plain, err := b.reg.Unwrap(ctx, w, secretAAD(tenant, version, w.Provider, w.KeyID, w.Version))
	if err != nil {
		return nil, err
	}
	if len(plain) != SecretBytes {
		clear(plain)
		return nil, ErrEnvelope
	}
	return plain, nil
}

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
	return kms.Wrapped{Provider: string(parts[0]), KeyID: string(parts[1]), Version: string(parts[2]), Ciphertext: append([]byte(nil), parts[3]...)}, nil
}
