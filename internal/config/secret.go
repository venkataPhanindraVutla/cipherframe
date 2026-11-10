// Package config loads and validates Cipherframe's configuration from the
// environment (ADR 0013). Secrets are held in types that never print their value.
package config

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
)

// Redacted is what every printable form of a secret shows.
const Redacted = "[redacted]"

// Secret wraps a sensitive string. The only way to read it is Reveal; every
// other form (fmt verbs, JSON, text, slog) yields "[redacted]". The zero value
// is the empty secret.
//
// The value is held inside a closure. When fmt prints a struct whose field of
// type Secret is unexported, it cannot call Secret's formatter and falls back to
// reflection; a function value then prints as an address and cannot be
// dereferenced, so the value never appears. Compare secrets with Equal.
type Secret struct {
	get func() string
}

// NewSecret wraps v.
func NewSecret(v string) Secret { return Secret{get: func() string { return v }} }

// Reveal returns the secret value. Call it only at the point of use.
func (s Secret) Reveal() string {
	if s.get == nil {
		return ""
	}
	return s.get()
}

// IsEmpty reports whether the secret is the empty string.
func (s Secret) IsEmpty() bool { return s.Reveal() == "" }

// Equal reports whether two secrets hold the same value, in constant time.
func (s Secret) Equal(o Secret) bool {
	return subtle.ConstantTimeCompare([]byte(s.Reveal()), []byte(o.Reveal())) == 1
}

// String implements fmt.Stringer.
func (Secret) String() string { return Redacted }

// GoString implements fmt.GoStringer.
func (Secret) GoString() string { return Redacted }

// Format implements fmt.Formatter and covers every verb, including %x and %#v.
func (Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(Redacted)) }

// MarshalJSON implements json.Marshaler.
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// MarshalText implements encoding.TextMarshaler.
func (Secret) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }
