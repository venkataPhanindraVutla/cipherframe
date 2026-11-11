// Package viewerauth holds the logic that lets a viewer's browser start a playback session without
// the embedding application's API key (ADR 0029, 0031): verifying a JWT against uploaded keys or a
// JWKS, calling a tenant's signed authorization callback, and wrapping the callback secret with
// the key provider.
//
// Everything here fails closed. A denial carries a reason from a closed set and never the token,
// the ticket, a secret, a URL or a response body. This package does not log.
package viewerauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// The JWT algorithms Cipherframe accepts (ADR 0029). "none" and every HMAC algorithm are always
// refused: the allowlist is passed to the parser, so they never get as far as a key.
const (
	AlgEdDSA = "EdDSA"
	AlgES256 = "ES256"
	AlgRS256 = "RS256"
)

// Key size bounds. An RSA verification key below 2048 bits is too weak; above 8192 bits a verify
// costs more than a public endpoint should spend on an unauthenticated request.
const (
	minRSABits = 2048
	maxRSABits = 8192
)

// MaxJWKSKeys is how many keys of a JWKS document are considered. The rest are ignored.
const MaxJWKSKeys = 50

// Algorithms is the JWT signature algorithm allowlist.
var Algorithms = []jose.SignatureAlgorithm{jose.EdDSA, jose.ES256, jose.RS256}

// PublicKey is a verification key together with the one algorithm it may be used with.
type PublicKey struct {
	Kid string
	Alg string
	Key crypto.PublicKey
	// JWK is the canonical JSON of the public JWK (kid, alg and use "sig" included), as stored.
	JWK []byte
}

// ErrKey is returned for a JWK that cannot be used. Its message is safe to show to the caller: it
// says what is wrong with the key without quoting any of it.
type ErrKey struct{ Msg string }

func (e *ErrKey) Error() string { return e.Msg }

func keyErr(format string, a ...any) error { return &ErrKey{Msg: fmt.Sprintf(format, a...)} }

// algForKey returns the only algorithm a key may be used with, or an error for a key type or curve
// Cipherframe does not accept.
func algForKey(k crypto.PublicKey) (string, error) {
	switch pk := k.(type) {
	case ed25519.PublicKey:
		return AlgEdDSA, nil
	case *ecdsa.PublicKey:
		if pk.Curve != elliptic.P256() {
			return "", keyErr("the EC curve is not supported: use P-256 (ES256)")
		}
		return AlgES256, nil
	case *rsa.PublicKey:
		bits := pk.N.BitLen()
		if bits < minRSABits {
			return "", keyErr("the RSA key is too short: at least 2048 bits are required")
		}
		if bits > maxRSABits {
			return "", keyErr("the RSA key is too long: at most 8192 bits are accepted")
		}
		return AlgRS256, nil
	}
	return "", keyErr("the key type is not supported: use OKP (Ed25519), EC (P-256) or RSA")
}

// parseJWK parses one JWK and checks it. declaredAlg is what the caller says the key is for ("" to
// take the key's `alg` member, and, failing that, the only algorithm its type allows). A private
// key is refused wherever it comes from.
func parseJWK(raw []byte, declaredAlg string) (PublicKey, error) {
	var k jose.JSONWebKey
	if err := k.UnmarshalJSON(raw); err != nil {
		// go-jose's messages can quote parts of the input; give a fixed one.
		return PublicKey{}, keyErr("the JWK is malformed or has an unsupported key type")
	}
	if !k.Valid() {
		return PublicKey{}, keyErr("the JWK is not valid")
	}
	if !k.IsPublic() {
		return PublicKey{}, keyErr("the JWK holds private key material: upload the public key only")
	}
	if k.Use != "" && k.Use != "sig" {
		return PublicKey{}, keyErr(`the JWK "use" must be "sig"`)
	}
	want, err := algForKey(k.Key)
	if err != nil {
		return PublicKey{}, err
	}
	alg := declaredAlg
	if alg == "" {
		alg = k.Algorithm
	}
	switch alg {
	case "":
		alg = want
	case AlgEdDSA, AlgES256, AlgRS256:
		if alg != want {
			return PublicKey{}, keyErr("the algorithm does not match the key type")
		}
	default:
		return PublicKey{}, keyErr("the algorithm must be EdDSA, ES256 or RS256")
	}
	if k.Algorithm != "" && k.Algorithm != alg {
		return PublicKey{}, keyErr("the JWK alg member does not match the algorithm")
	}
	// Canonical form: only the public key, its kid, its algorithm and its use.
	canon := jose.JSONWebKey{Key: k.Key, KeyID: k.KeyID, Algorithm: alg, Use: "sig"}
	b, err := canon.MarshalJSON()
	if err != nil {
		return PublicKey{}, keyErr("the JWK cannot be encoded")
	}
	return PublicKey{Kid: k.KeyID, Alg: alg, Key: k.Key, JWK: b}, nil
}

// ParseUploadedJWK checks a public JWK uploaded for kid. The body must name its algorithm (the
// `alg` member), which must be EdDSA, ES256 or RS256 and match the key. A `kid` member, if
// present, must equal kid. A private key, an RSA key below 2048 bits, an unknown key type or curve
// and a symmetric key are all refused.
func ParseUploadedJWK(kid string, raw []byte) (PublicKey, error) {
	var probe struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return PublicKey{}, keyErr("the JWK is malformed")
	}
	if probe.Alg == "" {
		return PublicKey{}, keyErr(`the JWK must name its algorithm in "alg"`)
	}
	if probe.Kid != "" && probe.Kid != kid {
		return PublicKey{}, keyErr(`the JWK "kid" does not match the kid in the path`)
	}
	pk, err := parseJWK(raw, probe.Alg)
	if err != nil {
		return PublicKey{}, err
	}
	// Re-encode with the path's kid.
	canon := jose.JSONWebKey{Key: pk.Key, KeyID: kid, Algorithm: pk.Alg, Use: "sig"}
	b, err := canon.MarshalJSON()
	if err != nil {
		return PublicKey{}, keyErr("the JWK cannot be encoded")
	}
	pk.Kid, pk.JWK = kid, b
	return pk, nil
}

// ParseStoredJWK reads a key from the form ParseUploadedJWK stored (its kid and algorithm are in
// the JSON). The result is checked again, so a damaged row is an error and never a key.
func ParseStoredJWK(kid, alg string, raw []byte) (PublicKey, error) {
	pk, err := parseJWK(raw, alg)
	if err != nil {
		return PublicKey{}, err
	}
	pk.Kid = kid
	return pk, nil
}

// ParseJWKS reads a JWKS document. Unusable keys (an unsupported type, a short RSA key, a private
// key, a key without a kid, a key meant for encryption) are skipped, not fatal: a real JWKS often
// lists keys Cipherframe does not use. At most MaxJWKSKeys entries are looked at. A document
// without a usable key is an error.
func ParseJWKS(doc []byte) (map[string]PublicKey, error) {
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(doc, &set); err != nil {
		return nil, errors.New("viewerauth: the JWKS document is malformed")
	}
	out := map[string]PublicKey{}
	dup := map[string]bool{}
	for i, raw := range set.Keys {
		if i >= MaxJWKSKeys {
			break
		}
		pk, err := parseJWK(raw, "")
		if err != nil || pk.Kid == "" {
			continue
		}
		if dup[pk.Kid] { // a repeated kid is ambiguous: use none of them
			continue
		}
		if _, seen := out[pk.Kid]; seen {
			dup[pk.Kid] = true
			delete(out, pk.Kid)
			continue
		}
		out[pk.Kid] = pk
	}
	if len(out) == 0 {
		return nil, errors.New("viewerauth: the JWKS document has no usable key")
	}
	return out, nil
}
