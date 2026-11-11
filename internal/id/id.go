// Package id implements Cipherframe's typed identifiers (ADR 0011).
//
// Object IDs are UUIDv7 values written as <prefix>_<26 chars of lowercase Crockford base32>.
// The type parameter makes a client ID impossible to pass where an asset ID is expected.
// Object IDs are not secret and reveal their creation time to the millisecond. Session IDs
// (see SessionID) are capabilities and are a separate, random type.
package id

import (
	"errors"
	"fmt"
	"uuid"
)

// Kind is implemented by the zero-size marker types below. It is sealed: only this package can
// declare kinds, so every prefix is registered in one place.
type Kind interface {
	prefix() string
}

type (
	// TenantKind marks tenant IDs.
	TenantKind struct{}
	// ClientKind marks client IDs.
	ClientKind struct{}
	// APIKeyKind marks API key IDs.
	APIKeyKind struct{}
	// AssetKind marks asset IDs.
	AssetKind struct{}
	// ContentKeyKind marks content key IDs.
	ContentKeyKind struct{}
	// SigningKeyKind marks integrity signing key IDs (ADR 0033). They are published in the key
	// set, so they are not secret.
	SigningKeyKind struct{}
)

func (TenantKind) prefix() string     { return "ten" }
func (ClientKind) prefix() string     { return "cli" }
func (APIKeyKind) prefix() string     { return "key" }
func (AssetKind) prefix() string      { return "ast" }
func (ContentKeyKind) prefix() string { return "cky" }
func (SigningKeyKind) prefix() string { return "sk" }

// Aliases for the concrete ID types.
type (
	TenantID = ID[TenantKind]
	ClientID = ID[ClientKind]
	APIKeyID = ID[APIKeyKind]
	AssetID  = ID[AssetKind]
	// ContentKeyID identifies a content key row. It is not secret.
	ContentKeyID = ID[ContentKeyKind]
	// SigningKeyID identifies an integrity signing key. It is the `keyid` of a signature.
	SigningKeyID = ID[SigningKeyKind]
)

const uuidTextLen = 26

// ID is a typed identifier. The zero value is the "no ID" value; it cannot be marshalled.
type ID[K Kind] struct {
	u uuid.UUID
}

// Errors returned by Parse and the text methods. They never contain the rejected input.
var (
	ErrZero   = errors.New("id: zero ID")
	ErrFormat = errors.New("id: malformed")
)

func prefixOf[K Kind]() string {
	var k K
	return k.prefix()
}

// New returns a new ID backed by a UUIDv7.
func New[K Kind]() ID[K] {
	return ID[K]{u: uuid.NewV7()}
}

// FromUUID wraps an existing UUID (for example one read from the database).
func FromUUID[K Kind](u uuid.UUID) ID[K] {
	return ID[K]{u: u}
}

// Parse reads the text form strictly: exact prefix for K, underscore, exactly 26 lowercase
// alphabet characters, canonical encoding, and not the nil UUID. Errors name at most the
// expected prefix, never the input.
func Parse[K Kind](s string) (ID[K], error) {
	p := prefixOf[K]()
	if len(s) != len(p)+1+uuidTextLen || s[:len(p)] != p || s[len(p)] != '_' {
		return ID[K]{}, fmt.Errorf("%w: want %s_ followed by %d characters", ErrFormat, p, uuidTextLen)
	}
	var u uuid.UUID
	if err := decode(u[:], s[len(p)+1:]); err != nil {
		return ID[K]{}, fmt.Errorf("%w: invalid %s_ identifier body", ErrFormat, p)
	}
	if u == uuid.Nil() {
		return ID[K]{}, fmt.Errorf("%w: nil identifier", ErrFormat)
	}
	return ID[K]{u: u}, nil
}

// String returns the text form, or "" for the zero ID.
func (i ID[K]) String() string {
	if i.IsZero() {
		return ""
	}
	return prefixOf[K]() + "_" + encode(i.u[:])
}

// UUID returns the underlying UUID.
func (i ID[K]) UUID() uuid.UUID { return i.u }

// IsZero reports whether i is the zero value.
func (i ID[K]) IsZero() bool { return i.u == uuid.Nil() }

// MarshalText implements encoding.TextMarshaler. Marshalling the zero ID is an error.
func (i ID[K]) MarshalText() ([]byte, error) {
	if i.IsZero() {
		return nil, ErrZero
	}
	return []byte(i.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler using Parse. On error i is unchanged.
func (i *ID[K]) UnmarshalText(b []byte) error {
	v, err := Parse[K](string(b))
	if err != nil {
		return err
	}
	*i = v
	return nil
}
