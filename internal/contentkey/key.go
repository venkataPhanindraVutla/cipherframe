package contentkey

import (
	"fmt"
	"log/slog"

	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// KeyBytes is the length of a content key: AES-128, as HLS requires.
const KeyBytes = 16

// Redacted is what every printable form of a ContentKey shows.
const Redacted = "[redacted]"

// ContentKey is a plaintext content key with its identifiers. The only way to read the key is
// Bytes; every other form (fmt verbs, JSON, text, slog) yields "[redacted]".
//
// The key is held inside closures, as config.Secret does. When fmt prints a struct containing a
// ContentKey by an unexported field it cannot call the formatter and falls back to reflection; a
// function value then prints as an address, so the key never appears. Call Zero when finished.
type ContentKey struct {
	id      id.ContentKeyID
	assetID id.AssetID
	get     func() []byte
	zero    func()
}

func newContentKey(keyID id.ContentKeyID, assetID id.AssetID, key []byte) ContentKey {
	buf := make([]byte, len(key))
	copy(buf, key)
	return ContentKey{
		id:      keyID,
		assetID: assetID,
		get: func() []byte {
			out := make([]byte, len(buf))
			copy(out, buf)
			return out
		},
		zero: func() { clear(buf) },
	}
}

// Bytes returns a copy of the key. Call it only at the point of use and do not retain the result.
// The zero ContentKey returns nil; after Zero the result is all zero bytes.
func (k ContentKey) Bytes() []byte {
	if k.get == nil {
		return nil
	}
	return k.get()
}

// ID returns the content key's identifier. It is not secret.
func (k ContentKey) ID() id.ContentKeyID { return k.id }

// AssetID returns the asset the key belongs to.
func (k ContentKey) AssetID() id.AssetID { return k.assetID }

// IsZero reports whether k holds no key.
func (k ContentKey) IsZero() bool { return k.get == nil }

// Zero overwrites the key bytes held by k and by every copy of k. It is best effort: copies the
// caller already took with Bytes are the caller's to clear.
func (k ContentKey) Zero() {
	if k.zero != nil {
		k.zero()
	}
}

// String implements fmt.Stringer.
func (ContentKey) String() string { return Redacted }

// GoString implements fmt.GoStringer.
func (ContentKey) GoString() string { return Redacted }

// Format implements fmt.Formatter and covers every verb, including %x and %#v.
func (ContentKey) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(Redacted)) }

// MarshalJSON implements json.Marshaler.
func (ContentKey) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// MarshalText implements encoding.TextMarshaler.
func (ContentKey) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// MarshalBinary implements encoding.BinaryMarshaler, so gob and similar encoders cannot reach the
// key either.
func (ContentKey) MarshalBinary() ([]byte, error) { return []byte(Redacted), nil }

// LogValue implements slog.LogValuer.
func (ContentKey) LogValue() slog.Value { return slog.StringValue(Redacted) }
