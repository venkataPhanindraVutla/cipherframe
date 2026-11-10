// Package auth implements API-key authentication and key management (ADR 0009, 0016): the key
// format, hashing with a versioned pepper, request verification, the principal carried in the
// request context, and the tenant-scoped operations that create, rotate and revoke keys.
//
// Nothing in this package logs or returns a full key, a secret, a hash or a pepper. The full key
// exists as a Key value only between generation and the single response that shows it; Key prints
// as redacted in every formatting verb.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

// Key format: cf_<prefix>_<secret>.
const (
	keyTag = "cf_"
	// PrefixLen is the length of the public prefix, in characters of the Crockford alphabet.
	PrefixLen = 12
	// SecretBytes is the length of the random secret before encoding.
	SecretBytes = 32
	// secretTextLen is the base64url length of SecretBytes without padding.
	secretTextLen = 43
	// KeyLen is the exact length of a full key.
	KeyLen = len(keyTag) + PrefixLen + 1 + secretTextLen

	// prefixAlphabet is lowercase Crockford base32. Its 32 symbols make a masked random byte a
	// uniform choice.
	prefixAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"
)

// ErrKeyFormat is returned by ParseKey. It never contains the rejected input.
var ErrKeyFormat = errors.New("auth: malformed API key")

// Key is a full API key, or its parsed parts. The secret half is only reachable through Reveal
// and Hash. Every printable form is redacted.
type Key struct {
	prefix string
	secret [SecretBytes]byte
}

// Prefix returns the public prefix. It is safe to log and to show.
func (k Key) Prefix() string { return k.prefix }

// Reveal returns the full key text, cf_<prefix>_<secret>. Call it only to hand the key to its
// owner once (the create, rotate or bootstrap response).
func (k Key) Reveal() string {
	return keyTag + k.prefix + "_" + base64.RawURLEncoding.EncodeToString(k.secret[:])
}

// Hash returns HMAC-SHA256(pepper, secret) over the 32 secret bytes.
func (k Key) Hash(pepper []byte) []byte { return hashSecret(pepper, k.secret[:]) }

// String implements fmt.Stringer; it never shows the secret.
func (k Key) String() string { return keyTag + k.prefix + "_[redacted]" }

// GoString implements fmt.GoStringer.
func (k Key) GoString() string { return k.String() }

// LogValue implements slog.LogValuer.
func (k Key) LogValue() slog.Value { return slog.StringValue(k.String()) }

// MarshalText implements encoding.TextMarshaler, so a Key put in a JSON body by mistake is
// redacted.
func (k Key) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// Format implements fmt.Formatter and covers every verb.
func (k Key) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }

func hashSecret(pepper, secret []byte) []byte {
	m := hmac.New(sha256.New, pepper)
	m.Write(secret)
	return m.Sum(nil)
}

// NewKey generates a key with a fresh random prefix and secret.
func NewKey() (Key, error) { return newKey(rand.Reader) }

// WithNewSecret returns a key with the same prefix as k and a fresh secret. Rotation uses it: the
// prefix is the key's public identity and does not change.
func WithNewSecret(prefix string) (Key, error) {
	if !validPrefix(prefix) {
		return Key{}, ErrKeyFormat
	}
	k := Key{prefix: prefix}
	if _, err := io.ReadFull(rand.Reader, k.secret[:]); err != nil {
		return Key{}, fmt.Errorf("auth: read random: %w", err)
	}
	return k, nil
}

func newKey(r io.Reader) (Key, error) {
	var b [PrefixLen]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return Key{}, fmt.Errorf("auth: read random: %w", err)
	}
	for i := range b {
		b[i] = prefixAlphabet[b[i]&31]
	}
	k := Key{prefix: string(b[:])}
	if _, err := io.ReadFull(r, k.secret[:]); err != nil {
		return Key{}, fmt.Errorf("auth: read random: %w", err)
	}
	return k, nil
}

func validPrefix(p string) bool {
	if len(p) != PrefixLen {
		return false
	}
	for i := range len(p) {
		if !isPrefixChar(p[i]) {
			return false
		}
	}
	return true
}

func isPrefixChar(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' && c != 'i' && c != 'l' && c != 'o' && c != 'u'
}

// ParseKey parses a full key strictly: exact length, the cf_ tag, a 12-character Crockford
// prefix, an underscore, and a canonical 43-character base64url secret (no padding, no
// whitespace, no trailing bits). Parsing is by position, because the secret alphabet contains
// underscores.
func ParseKey(s string) (Key, error) {
	if len(s) != KeyLen || s[:len(keyTag)] != keyTag || s[len(keyTag)+PrefixLen] != '_' {
		return Key{}, ErrKeyFormat
	}
	prefix := s[len(keyTag) : len(keyTag)+PrefixLen]
	if !validPrefix(prefix) {
		return Key{}, ErrKeyFormat
	}
	k := Key{prefix: prefix}
	n, err := base64.RawURLEncoding.Strict().Decode(k.secret[:], []byte(s[len(keyTag)+PrefixLen+1:]))
	if err != nil || n != SecretBytes {
		return Key{}, ErrKeyFormat
	}
	return k, nil
}
