// Package dsse implements the DSSE v1 signing envelope
// (https://github.com/secure-systems-lab/dsse, envelope.md and protocol.md) with Ed25519.
//
// An envelope is the JSON object
//
//	{"payloadType": "...", "payload": "<base64>", "signatures": [{"keyid": "...", "sig": "<base64>"}]}
//
// and every signature is over PAE(payloadType, payload), the pre-authentication encoding
//
//	"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
//
// where SP is 0x20 and LEN is the byte length in ASCII decimal without leading zeros. Because the
// type is part of the signed bytes, a signature made for one payload type never verifies under
// another.
//
// Encoding: the spec allows standard or URL-safe base64 for payload and sig, and requires
// consumers to accept both. [Decode] accepts either alphabet, padded and canonical (no stray
// trailing bits, no line breaks); [Envelope.Encode] always writes standard padded base64. The spec
// makes keyid optional; this package requires it on signatures it creates and counts a signature
// without one as untrusted when verifying.
//
// Decoding is strict: size caps, no duplicate or unknown members (member names match exactly,
// unlike encoding/json), and no null or wrong-typed values. Verification never needs a secret: it
// takes only public keys. Errors wrap the verify package sentinels: structural problems are
// verify.ErrMalformed, a signature by a trusted key that does not match is verify.ErrTampered, and
// signatures only by unknown keys are verify.ErrUntrustedKey.
package dsse

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/jcs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify"
)

// Limits applied by Decode and Verify.
const (
	// MaxEnvelopeBytes is the largest encoded envelope Decode accepts.
	MaxEnvelopeBytes = 8 << 20
	// MaxSignatures is the largest number of signatures an envelope may carry.
	MaxSignatures = 16
	// MaxKeyIDBytes is the largest keyid.
	MaxKeyIDBytes = 256
	// MaxPayloadTypeBytes is the largest payloadType.
	MaxPayloadTypeBytes = 256
)

// Envelope is a decoded DSSE envelope: Payload and each Sig hold raw bytes, not base64.
type Envelope struct {
	PayloadType string
	Payload     []byte
	Signatures  []Signature
}

// Signature is one signature in an envelope.
type Signature struct {
	KeyID string
	Sig   []byte
}

// PAE returns the DSSE v1 pre-authentication encoding of the payload type and payload.
func PAE(payloadType string, payload []byte) []byte {
	out := make([]byte, 0, 6+4+len(payloadType)+len(payload)+40)
	out = append(out, "DSSEv1 "...)
	out = strconv.AppendInt(out, int64(len(payloadType)), 10)
	out = append(out, ' ')
	out = append(out, payloadType...)
	out = append(out, ' ')
	out = strconv.AppendInt(out, int64(len(payload)), 10)
	out = append(out, ' ')
	return append(out, payload...)
}

// SigningKey is a key that signs envelopes. Key may be an ed25519.PrivateKey or any other
// crypto.Signer (a KMS client, for example) whose Public method returns an ed25519.PublicKey.
type SigningKey struct {
	KeyID string
	Key   crypto.Signer
}

// Sign returns an envelope carrying payload and one signature per signer. Each signature is
// checked against the signer's own public key before it is returned, so a misbehaving signer
// cannot produce an envelope that does not verify.
func Sign(payloadType string, payload []byte, signers ...SigningKey) (*Envelope, error) {
	if err := checkType(payloadType); err != nil {
		return nil, err
	}
	if len(signers) == 0 {
		return nil, errors.New("dsse: no signers")
	}
	if len(signers) > MaxSignatures {
		return nil, fmt.Errorf("dsse: %d signers exceeds the limit of %d", len(signers), MaxSignatures)
	}
	pae := PAE(payloadType, payload)
	env := &Envelope{PayloadType: payloadType, Payload: append([]byte(nil), payload...)}
	seen := map[string]bool{}
	for _, s := range signers {
		if s.KeyID == "" || len(s.KeyID) > MaxKeyIDBytes {
			return nil, errors.New("dsse: signer keyid must be 1..256 bytes")
		}
		if seen[s.KeyID] {
			return nil, fmt.Errorf("dsse: duplicate signer keyid %q", s.KeyID)
		}
		seen[s.KeyID] = true
		if s.Key == nil {
			return nil, fmt.Errorf("dsse: signer %q has no key", s.KeyID)
		}
		pub, ok := s.Key.Public().(ed25519.PublicKey)
		if !ok || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("dsse: signer %q is not an Ed25519 key", s.KeyID)
		}
		sig, err := s.Key.Sign(rand.Reader, pae, crypto.Hash(0))
		if err != nil {
			return nil, fmt.Errorf("dsse: signer %q: %w", s.KeyID, err)
		}
		if !ed25519.Verify(pub, pae, sig) {
			return nil, fmt.Errorf("dsse: signer %q produced a signature that does not verify", s.KeyID)
		}
		env.Signatures = append(env.Signatures, Signature{KeyID: s.KeyID, Sig: sig})
	}
	return env, nil
}

func checkType(t string) error {
	if t == "" || len(t) > MaxPayloadTypeBytes {
		return fmt.Errorf("%w: dsse: payloadType must be 1..%d bytes", verify.ErrMalformed, MaxPayloadTypeBytes)
	}
	return nil
}

// Encode returns the JSON encoding of the envelope with standard padded base64 and members in
// the order payloadType, payload, signatures.
func (e *Envelope) Encode() ([]byte, error) {
	type sig struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}
	out := struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []sig  `json:"signatures"`
	}{e.PayloadType, base64.StdEncoding.EncodeToString(e.Payload), make([]sig, 0, len(e.Signatures))}
	for _, s := range e.Signatures {
		out.Signatures = append(out.Signatures, sig{s.KeyID, base64.StdEncoding.EncodeToString(s.Sig)})
	}
	return json.Marshal(out)
}

// Decode parses and strictly validates an encoded envelope.
func Decode(data []byte) (*Envelope, error) {
	if len(data) > MaxEnvelopeBytes {
		return nil, malformed("envelope larger than %d bytes", MaxEnvelopeBytes)
	}
	// jcs rejects invalid UTF-8, duplicate member names (after unescaping), bad JSON and
	// excessive nesting; the canonical form is then decoded with exact member-name checks.
	canon, err := jcs.Canonicalize(data)
	if err != nil {
		return nil, fmt.Errorf("dsse: %w", err)
	}
	top, err := object(canon, "envelope", "payloadType", "payload", "signatures")
	if err != nil {
		return nil, err
	}
	var env Envelope
	if env.PayloadType, err = str(top["payloadType"], "payloadType"); err != nil {
		return nil, err
	}
	if err = checkType(env.PayloadType); err != nil {
		return nil, err
	}
	payload, err := str(top["payload"], "payload")
	if err != nil {
		return nil, err
	}
	if env.Payload, err = b64(payload); err != nil {
		return nil, malformed("payload: %v", err)
	}
	var sigs []json.RawMessage
	if raw := top["signatures"]; len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &sigs) != nil {
		return nil, malformed("signatures must be an array")
	}
	if len(sigs) > MaxSignatures {
		return nil, malformed("%d signatures exceeds the limit of %d", len(sigs), MaxSignatures)
	}
	for _, raw := range sigs {
		m, err := object(raw, "signature", "keyid", "sig")
		if err != nil {
			return nil, err
		}
		var s Signature
		if _, ok := m["keyid"]; ok {
			if s.KeyID, err = str(m["keyid"], "keyid"); err != nil {
				return nil, err
			}
			if len(s.KeyID) > MaxKeyIDBytes {
				return nil, malformed("keyid longer than %d bytes", MaxKeyIDBytes)
			}
		}
		sigStr, err := str(m["sig"], "sig")
		if err != nil {
			return nil, err
		}
		if s.Sig, err = b64(sigStr); err != nil {
			return nil, malformed("sig: %v", err)
		}
		env.Signatures = append(env.Signatures, s)
	}
	return &env, nil
}

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: dsse: "+format, append([]any{verify.ErrMalformed}, args...)...)
}

// object decodes raw as a JSON object whose member names are exactly among allowed, and which
// contains every required name other than "keyid".
func object(raw []byte, what string, allowed ...string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &m) != nil {
		return nil, malformed("%s must be an object", what)
	}
	for k := range m {
		found := false
		for _, a := range allowed {
			found = found || k == a
		}
		if !found {
			return nil, malformed("%s has unknown member %q", what, k)
		}
	}
	for _, a := range allowed {
		if _, ok := m[a]; !ok && a != "keyid" {
			return nil, malformed("%s is missing member %q", what, a)
		}
	}
	return m, nil
}

func str(raw json.RawMessage, name string) (string, error) {
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", malformed("%s must be a string", name)
	}
	return s, nil
}

// b64 decodes padded base64 in either the standard or the URL-safe alphabet, rejecting
// non-canonical encodings and any line break.
func b64(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("line break in base64")
	}
	if b, err := base64.StdEncoding.Strict().DecodeString(s); err == nil {
		return b, nil
	}
	b, err := base64.URLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, errors.New("invalid base64")
	}
	return b, nil
}

// Result reports which signatures of an envelope verified.
type Result struct {
	// Payload is the envelope's payload. It is authentic only if RequireAny returns nil.
	Payload []byte
	// Verified lists the keyids whose signature verified under a trusted key.
	Verified []string
	// Failed lists keyids that are trusted but whose signature did not verify.
	Failed []string
	// Unknown lists keyids (possibly empty) that are not among the trusted keys.
	Unknown []string
}

// RequireAny is the policy "at least one trusted key verified". It returns nil when Verified is
// not empty. Otherwise it returns an error wrapping verify.ErrTampered if a trusted key's
// signature failed, or verify.ErrUntrustedKey if no signature came from a trusted key.
func (r *Result) RequireAny() error {
	switch {
	case len(r.Verified) > 0:
		return nil
	case len(r.Failed) > 0:
		return fmt.Errorf("%w: signature by trusted key %q does not verify", verify.ErrTampered, r.Failed[0])
	default:
		return fmt.Errorf("%w: no signature from a trusted key", verify.ErrUntrustedKey)
	}
}

// Verify checks every signature of env against keys (keyid to public key). It returns an error
// wrapping verify.ErrMalformed if the envelope is structurally invalid (nil, a payload type other
// than expectedPayloadType, no signatures, too many, or duplicate keyids); otherwise it reports
// each signature's outcome in the Result and leaves the policy to the caller (see
// [Result.RequireAny]). A key in keys that is not a valid Ed25519 public key is a caller error and
// is returned unclassified.
func Verify(env *Envelope, expectedPayloadType string, keys map[string]ed25519.PublicKey) (*Result, error) {
	if env == nil {
		return nil, malformed("nil envelope")
	}
	if env.PayloadType != expectedPayloadType {
		return nil, malformed("payload type %q, want %q", env.PayloadType, expectedPayloadType)
	}
	if len(env.Signatures) == 0 {
		return nil, malformed("envelope has no signatures")
	}
	if len(env.Signatures) > MaxSignatures {
		return nil, malformed("%d signatures exceeds the limit of %d", len(env.Signatures), MaxSignatures)
	}
	seen := map[string]bool{}
	for _, s := range env.Signatures {
		if seen[s.KeyID] {
			return nil, malformed("duplicate keyid %q", s.KeyID)
		}
		seen[s.KeyID] = true
	}
	pae := PAE(env.PayloadType, env.Payload)
	res := &Result{Payload: env.Payload}
	for _, s := range env.Signatures {
		pub, ok := keys[s.KeyID]
		if !ok || s.KeyID == "" {
			res.Unknown = append(res.Unknown, s.KeyID)
			continue
		}
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("dsse: trusted key %q is not a valid Ed25519 public key", s.KeyID)
		}
		if len(s.Sig) == ed25519.SignatureSize && ed25519.Verify(pub, pae, s.Sig) {
			res.Verified = append(res.Verified, s.KeyID)
		} else {
			res.Failed = append(res.Failed, s.KeyID)
		}
	}
	return res, nil
}
