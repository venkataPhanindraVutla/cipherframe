// Package uploads holds what the api and edge listeners share about asset uploads (ADR 0025,
// 0026): upload tokens, size and part rules, the asset service the API calls (create, commit,
// abort), the multipart part receiver and the tus data store the edge mounts.
//
// Nothing here returns or logs an object key of the source bucket, an object-store upload ID, an
// upload token after its issuing response, or a presigned URL.
package uploads

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

// Token format: "cfu_" followed by the unpadded base64url form of 32 random bytes (256 bits).
const (
	tokenTag = "cfu_"
	// TokenBytes is the entropy of a token.
	TokenBytes = 32
	// tokenTextLen is the length of the base64url text of TokenBytes.
	tokenTextLen = 43
	// TokenLen is the exact length of a token.
	TokenLen = len(tokenTag) + tokenTextLen
)

// ErrTokenFormat is returned by HashToken for a malformed token. It never contains the input.
var ErrTokenFormat = errors.New("uploads: malformed upload token")

// Token is a freshly issued upload token. It exists in plain form only between issuing and the
// single response that returns it; the database holds its hash. Every printable form is redacted.
type Token struct {
	raw [TokenBytes]byte
}

// NewToken returns a new random token.
func NewToken() (Token, error) {
	var t Token
	if _, err := io.ReadFull(rand.Reader, t.raw[:]); err != nil {
		return Token{}, fmt.Errorf("uploads: random token: %w", err)
	}
	return t, nil
}

// Reveal returns the token text. Call it only to put the token in its issuing response.
func (t Token) Reveal() string { return tokenTag + base64.RawURLEncoding.EncodeToString(t.raw[:]) }

// Hash returns the value stored in the database: SHA-256 of the token text. The token is 256
// random bits, so a plain fast hash leaves nothing to brute-force.
func (t Token) Hash() []byte { return sum(t.Reveal()) }

// String implements fmt.Stringer; it never shows the token.
func (Token) String() string { return tokenTag + "[redacted]" }

// GoString implements fmt.GoStringer.
func (t Token) GoString() string { return t.String() }

// LogValue implements slog.LogValuer.
func (t Token) LogValue() slog.Value { return slog.StringValue(t.String()) }

// MarshalText implements encoding.TextMarshaler, so a Token put in a JSON body by mistake is
// redacted.
func (t Token) MarshalText() ([]byte, error) { return []byte(t.String()), nil }

// Format implements fmt.Formatter and covers every verb.
func (t Token) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, t.String()) }

func sum(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// HashToken validates the format of a presented token and returns the hash to look up. A token
// that is not exactly "cfu_" plus 43 base64url characters of canonical encoding is rejected without
// touching the database.
func HashToken(presented string) ([]byte, error) {
	if len(presented) != TokenLen || presented[:len(tokenTag)] != tokenTag {
		return nil, ErrTokenFormat
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(presented[len(tokenTag):])
	if err != nil || len(raw) != TokenBytes {
		return nil, ErrTokenFormat
	}
	return sum(presented), nil
}
