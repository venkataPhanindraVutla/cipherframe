// Package token signs and verifies playback tokens (ADR 0028).
//
// A token is four dot-separated parts:
//
//		v1.<payload>.<kid>.<mac>
//
//	  - payload is compact JSON, base64url without padding. The fields are short:
//	    s (session ID), a (asset ID), n (tenant ID), m (scope bitmask), i (issued-at, unix seconds)
//	    and e (expiry, unix seconds). Unknown fields are rejected.
//	  - kid is the key ID: the decimal version of the signing key, written as plain text. Decimal
//	    digits are already URL-safe and never contain a dot, so it is not base64-encoded.
//	  - mac is HMAC-SHA256 over the exact text "v1." + payload + "." + kid, base64url without
//	    padding. The MAC covers the text as sent, so the payload is not decoded or parsed until the
//	    MAC has been verified.
//
// Scopes are a bitmask (manifest 1, key 2, segment 4) so the set stays small and has one canonical
// encoding. A token may carry any non-empty combination.
//
// The tenant is in the claims so that edge can serve a segment without a database round trip: it
// builds the object key from the tenant and asset in the (MAC-protected) claims, and finds the
// tenant's settings in its own small cache. The client never names the asset or the tenant.
//
// Verification is stateless: it checks the MAC, the key ID, expiry, scope and asset, with no
// database round trip. That is enough for playlists and segments at the edge. The key endpoint
// must additionally check that the session row is still active, so that revoking a session takes
// effect at once; that check lives with the key endpoint, not here.
//
// Expiry is checked with zero clock skew: a token is invalid at its expiry instant. Tokens are
// issued by the server and refreshed by heartbeat well before they expire, so no tolerance is
// needed, and adding one would only lengthen every token's life. Issued-at is carried for
// diagnostics and is not checked, so a verifier whose clock is slightly behind the signer's does
// not reject fresh tokens.
//
// Every verification failure returns ErrInvalid, so a caller (and an attacker) cannot tell which
// check failed. Neither errors nor logs ever include the token. Keys must be at least MinKeyBytes
// long, and a token is rejected before any decoding if it is longer than MaxTokenLen.
package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

const (
	// Version is the token format version and the first part of every token.
	Version = "v1"
	// MaxTokenLen is the longest token Verify will look at, in bytes.
	MaxTokenLen = 1024
	// MinKeyBytes is the shortest signing key NewKeyring accepts.
	MinKeyBytes = 32
	// maxIDLen bounds the session and asset IDs Sign accepts.
	maxIDLen = 128
)

// Scope is a set of things a token allows.
type Scope uint8

// Scope bits.
const (
	ScopeManifest Scope = 1 << iota
	ScopeKey
	ScopeSegment

	allScopes = ScopeManifest | ScopeKey | ScopeSegment
)

// Has reports whether s contains every scope in need.
func (s Scope) Has(need Scope) bool { return s&need == need }

// valid reports whether s is a non-empty set of known scopes.
func (s Scope) valid() bool { return s != 0 && s&^allScopes == 0 }

// String lists the scope names, for example "manifest|segment".
func (s Scope) String() string {
	var n []string
	if s&ScopeManifest != 0 {
		n = append(n, "manifest")
	}
	if s&ScopeKey != 0 {
		n = append(n, "key")
	}
	if s&ScopeSegment != 0 {
		n = append(n, "segment")
	}
	if len(n) == 0 {
		return "none"
	}
	return strings.Join(n, "|")
}

// ErrInvalid is returned by Verify for every failure. It reveals nothing about the cause.
var ErrInvalid = errs.New(errs.Unauthenticated, "invalid playback token")

// Claims is what a token asserts. Times have one-second resolution.
type Claims struct {
	SessionID string
	AssetID   string
	TenantID  string
	Scopes    Scope
	// Variant is the variant the session is bound to ("original" or "masked", ADR 0036). Empty is
	// read as original, so a token signed before variants existed stays valid.
	Variant  string
	IssuedAt time.Time
	Expiry   time.Time
}

// payload is the wire form of Claims.
type payload struct {
	Session string `json:"s"`
	Asset   string `json:"a"`
	Tenant  string `json:"n"`
	Scopes  uint8  `json:"m"`
	Variant string `json:"v,omitempty"`
	Issued  int64  `json:"i"`
	Expires int64  `json:"e"`
}

// Keyring holds the versioned signing keys and the version new tokens use (ADR 0016's shape).
// Older keys keep verifying until they are removed from configuration.
type Keyring struct {
	keys    map[int][]byte
	current int
}

// NewKeyring copies keys and checks them: at least one, each at least MinKeyBytes, versions
// positive, and current present. Errors name versions, never key bytes.
func NewKeyring(keys map[int][]byte, current int) (*Keyring, error) {
	if len(keys) == 0 {
		return nil, errors.New("token: no signing keys")
	}
	k := &Keyring{keys: make(map[int][]byte, len(keys)), current: current}
	for v, key := range keys {
		if v < 1 {
			return nil, fmt.Errorf("token: key version %d is not positive", v)
		}
		if len(key) < MinKeyBytes {
			return nil, fmt.Errorf("token: key version %d is shorter than %d bytes", v, MinKeyBytes)
		}
		k.keys[v] = slices.Clone(key)
	}
	if _, ok := k.keys[current]; !ok {
		return nil, fmt.Errorf("token: current key version %d is not in the key set", current)
	}
	return k, nil
}

// String shows versions only.
func (k *Keyring) String() string {
	if k == nil {
		return "token.Keyring(nil)"
	}
	return fmt.Sprintf("token.Keyring(versions=%d current=%d keys=[redacted])", len(k.keys), k.current)
}

// GoString implements fmt.GoStringer.
func (k *Keyring) GoString() string { return k.String() }

// Format implements fmt.Formatter so no verb can reach the key bytes.
func (k *Keyring) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }

// LogValue implements slog.LogValuer.
func (k *Keyring) LogValue() slog.Value { return slog.StringValue(k.String()) }

func mac(key []byte, signed string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(signed))
	return h.Sum(nil)
}

var enc = base64.RawURLEncoding.Strict()

// Sign returns a token for c, signed with the current key. It returns an error for claims that
// could never verify (empty IDs, no scope, expiry not after issue). Errors never contain claims.
func (k *Keyring) Sign(c Claims) (string, error) {
	switch {
	case c.SessionID == "" || len(c.SessionID) > maxIDLen:
		return "", errors.New("token: invalid session ID")
	case c.AssetID == "" || len(c.AssetID) > maxIDLen:
		return "", errors.New("token: invalid asset ID")
	case c.TenantID == "" || len(c.TenantID) > maxIDLen:
		return "", errors.New("token: invalid tenant ID")
	case !c.Scopes.valid():
		return "", errors.New("token: invalid scope")
	case c.IssuedAt.Unix() < 1 || c.Expiry.Unix() <= c.IssuedAt.Unix():
		return "", errors.New("token: expiry must be after issue time")
	}
	body, err := json.Marshal(payload{
		Session: c.SessionID, Asset: c.AssetID, Tenant: c.TenantID, Scopes: uint8(c.Scopes), Variant: c.Variant,
		Issued: c.IssuedAt.Unix(), Expires: c.Expiry.Unix(),
	})
	if err != nil {
		return "", errors.New("token: encode payload")
	}
	kid := strconv.Itoa(k.current)
	signed := Version + "." + enc.EncodeToString(body) + "." + kid
	tok := signed + "." + enc.EncodeToString(mac(k.keys[k.current], signed))
	if len(tok) > MaxTokenLen {
		return "", errors.New("token: token too long")
	}
	return tok, nil
}

// Verify checks tok and returns its claims. now is the verification time; need is the scope the
// request requires (every bit must be present, and it must not be empty); assetID is the asset the
// request is for. Any failure returns ErrInvalid.
func (k *Keyring) Verify(tok string, now time.Time, need Scope, assetID string) (Claims, error) {
	c, ok := k.verify(tok, now, need, &assetID)
	if !ok {
		return Claims{}, ErrInvalid
	}
	return c, nil
}

// Open is Verify for a caller that does not know the asset yet, such as edge, whose request names
// only the session: it checks everything Verify checks except the asset, which the caller then
// takes from the returned claims (never from the client). Any failure returns ErrInvalid.
func (k *Keyring) Open(tok string, now time.Time, need Scope) (Claims, error) {
	c, ok := k.verify(tok, now, need, nil)
	if !ok {
		return Claims{}, ErrInvalid
	}
	return c, nil
}

func (k *Keyring) verify(tok string, now time.Time, need Scope, assetID *string) (Claims, bool) {
	if k == nil || len(tok) > MaxTokenLen || !need.valid() {
		return Claims{}, false
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 4 || parts[0] != Version {
		return Claims{}, false
	}
	kid, ok := parseKID(parts[2])
	if !ok {
		return Claims{}, false
	}
	key, ok := k.keys[kid]
	if !ok {
		return Claims{}, false
	}
	got, err := enc.DecodeString(parts[3])
	if err != nil {
		return Claims{}, false
	}
	// MAC first: nothing unauthenticated is parsed.
	if !hmac.Equal(got, mac(key, parts[0]+"."+parts[1]+"."+parts[2])) {
		return Claims{}, false
	}
	raw, err := enc.DecodeString(parts[1])
	if err != nil {
		return Claims{}, false
	}
	var p payload
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Claims{}, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) { // nothing may follow the object
		return Claims{}, false
	}
	sc := Scope(p.Scopes)
	switch {
	case p.Session == "" || p.Asset == "" || p.Tenant == "" || !sc.valid() || p.Expires <= p.Issued:
		return Claims{}, false
	case now.Unix() >= p.Expires:
		return Claims{}, false
	case !sc.Has(need):
		return Claims{}, false
	case assetID != nil && !hmac.Equal([]byte(p.Asset), []byte(*assetID)):
		return Claims{}, false
	}
	return Claims{
		SessionID: p.Session, AssetID: p.Asset, TenantID: p.Tenant, Scopes: sc, Variant: p.Variant,
		IssuedAt: time.Unix(p.Issued, 0).UTC(), Expiry: time.Unix(p.Expires, 0).UTC(),
	}, true
}

// parseKID parses a canonical positive decimal key ID (no sign, no leading zero).
func parseKID(s string) (int, bool) {
	if s == "" || len(s) > 9 || s[0] == '0' {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}
