// Package offline verifies a signed Cipherframe manifest, and files against it, with public keys
// only (ADR 0039, M5-4). It imports no server, database or storage code.
//
// It lives beside package verify, not in it, because package proof imports verify.
//
// Every check ends in one of three public outcomes: [Ours], [Modified] or [CannotSay]. The
// signature is always checked first. [Modified] is reported only when a trusted key's valid
// signature covers a manifest that records a different hash for the path. A signature that does
// not verify, an unknown key, a malformed document, an unknown path or any error is [CannotSay]
// with the precise [Reason]; never [Modified].
package offline

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/dsse"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/proof"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify"
)

// MaxKeySetBytes is the largest key set ParseKeySet accepts.
const MaxKeySetBytes = 1 << 20

// Public is the outcome shown to a person.
type Public int

// The public outcomes.
const (
	CannotSay Public = iota
	Ours
	Modified
)

// String returns "ours", "modified" or "cannot say".
func (p Public) String() string {
	switch p {
	case Ours:
		return "ours"
	case Modified:
		return "modified"
	}
	return "cannot say"
}

// Reason is the precise internal reason behind a Public outcome.
type Reason string

// The reasons.
const (
	ReasonVerified         Reason = "verified"          // Ours
	ReasonModified         Reason = "modified"          // Modified: the hash differs from the signed one
	ReasonTamperedEnvelope Reason = "tampered-envelope" // a trusted key's signature does not verify
	ReasonUntrustedKey     Reason = "untrusted-key"
	ReasonMalformed        Reason = "malformed"
	ReasonUnknownPath      Reason = "unknown-path"
	ReasonNoVariant        Reason = "no-variant"
	ReasonCannotSay        Reason = "cannot-say"
)

// Result is the verdict for one file.
type Result struct {
	Outcome Public
	Reason  Reason
	Detail  string
}

func cannot(reason Reason, err error) Result {
	return Result{CannotSay, reason, err.Error()}
}

// KeySet maps keyid to a trusted Ed25519 public key.
type KeySet map[string]ed25519.PublicKey

// ParseKeySet parses the published key set JSON (/.well-known/cipherframe-keys.json). Keys with
// status active or retired are trusted: a retired key still verifies what it signed. A key with
// another status or algorithm is ignored, so it is never trusted by accident.
func ParseKeySet(data []byte) (KeySet, error) {
	if len(data) > MaxKeySetBytes {
		return nil, fmt.Errorf("%w: key set larger than %d bytes", verify.ErrMalformed, MaxKeySetBytes)
	}
	var doc struct {
		Keys []struct {
			KeyID     string `json:"keyid"`
			Alg       string `json:"alg"`
			PublicKey string `json:"public_key"`
			Status    string `json:"status"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || doc.Keys == nil {
		return nil, fmt.Errorf("%w: not a key set document", verify.ErrMalformed)
	}
	ks := KeySet{}
	for _, k := range doc.Keys {
		if k.KeyID == "" {
			return nil, fmt.Errorf("%w: a key has no keyid", verify.ErrMalformed)
		}
		if _, dup := ks[k.KeyID]; dup {
			return nil, fmt.Errorf("%w: duplicate keyid %q", verify.ErrMalformed, k.KeyID)
		}
		if k.Alg != "ed25519" || (k.Status != "active" && k.Status != "retired") {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: key %q is not a base64 32-byte Ed25519 public key", verify.ErrMalformed, k.KeyID)
		}
		ks[k.KeyID] = ed25519.PublicKey(raw)
	}
	return ks, nil
}

// Signed is a manifest whose DSSE signature verified under a trusted key.
type Signed struct {
	Manifest manifest.Manifest
}

// Open decodes the envelope, verifies its signature against keys and decodes the manifest. The
// error wraps verify.ErrTampered (a trusted key's signature does not verify), ErrUntrustedKey or
// ErrMalformed where it can; use [FromError] for a Result.
func Open(envelope []byte, keys KeySet) (*Signed, error) {
	env, err := dsse.Decode(envelope)
	if err != nil {
		return nil, err
	}
	res, err := dsse.Verify(env, manifest.PayloadType, keys)
	if err != nil {
		return nil, err
	}
	if err := res.RequireAny(); err != nil {
		return nil, err
	}
	var m manifest.Manifest
	if err := json.Unmarshal(res.Payload, &m); err != nil || m.Schema != manifest.Schema {
		return nil, fmt.Errorf("%w: the payload is not a %s manifest", verify.ErrMalformed, manifest.Schema)
	}
	return &Signed{m}, nil
}

// FromError turns an error from Open (or any loading step) into a CannotSay Result. A bad
// signature is reported as tampered-envelope: it says the envelope was altered, not the file.
func FromError(err error) Result {
	switch verify.Classify(err) {
	case verify.Tampered:
		return cannot(ReasonTamperedEnvelope, err)
	case verify.UntrustedKey:
		return cannot(ReasonUntrustedKey, err)
	case verify.Malformed:
		return cannot(ReasonMalformed, err)
	}
	return cannot(ReasonCannotSay, err)
}

// Paths lists every artifact path the manifest records for the variant, sorted.
func (s *Signed) Paths(variant string) []string {
	rends, arts := s.Manifest.Renditions, s.Manifest.Artifacts
	if variant == proof.Masked {
		if s.Manifest.Masked == nil {
			return nil
		}
		rends, arts = s.Manifest.Masked.Renditions, s.Manifest.Masked.Artifacts
	}
	var out []string
	for _, r := range rends {
		out = append(out, r.Init.Path)
		for _, o := range r.Segments {
			out = append(out, o.Path)
		}
	}
	for _, a := range arts {
		out = append(out, a.Path)
	}
	sort.Strings(out)
	return out
}

// Artifact checks the file at path (relative to the variant's HLS prefix) with SHA-256 sum.
func (s *Signed) Artifact(path string, sum [sha256.Size]byte, variant string) Result {
	want, err := proof.Build(s.Manifest, variant, path)
	switch {
	case errors.Is(err, proof.ErrNotFound):
		return cannot(ReasonUnknownPath, err)
	case errors.Is(err, proof.ErrNoVariant):
		return cannot(ReasonNoVariant, err)
	case err != nil:
		return FromError(err)
	}
	return compare(want.SHA256, sum)
}

// Proof checks sum against an inclusion proof: the proof must agree with the signed manifest, and
// its audit paths must lead from the file hash up to the signed rendition and top-level roots.
func (s *Signed) Proof(p proof.Proof, sum [sha256.Size]byte) Result {
	want, err := proof.Build(s.Manifest, p.Variant, p.Path)
	switch {
	case errors.Is(err, proof.ErrNotFound):
		return cannot(ReasonUnknownPath, err)
	case errors.Is(err, proof.ErrNoVariant):
		return cannot(ReasonNoVariant, err)
	case err != nil:
		return FromError(err)
	}
	if p.SHA256 != want.SHA256 || p.Rendition != want.Rendition || p.RenditionRoot != want.RenditionRoot ||
		p.TopLevel.Root != want.TopLevel.Root {
		return cannot(ReasonMalformed, errors.New("the proof does not belong to this manifest"))
	}
	if r := compare(want.SHA256, sum); r.Outcome != Ours {
		return r
	}
	if err := proof.Verify(p, sum); err != nil {
		return FromError(err) // a bad audit path is a bad proof, not a modified file
	}
	return Result{Ours, ReasonVerified, "the hash is under the signed top-level root"}
}

func compare(wantHex string, sum [sha256.Size]byte) Result {
	if got := hex.EncodeToString(sum[:]); got != wantHex {
		return Result{Modified, ReasonModified, fmt.Sprintf("sha256 %s, the signed manifest records %s", got, wantHex)}
	}
	return Result{Ours, ReasonVerified, "the hash matches the signed manifest"}
}

// VerifyArtifact verifies the envelope's signature, then the file's hash against the manifest.
func VerifyArtifact(envelope []byte, keys KeySet, path string, sum [sha256.Size]byte, variant string) Result {
	s, err := Open(envelope, keys)
	if err != nil {
		return FromError(err)
	}
	return s.Artifact(path, sum, variant)
}

// VerifyProof verifies the envelope's signature, then the file's hash against the proof and the
// manifest.
func VerifyProof(envelope []byte, keys KeySet, p proof.Proof, sum [sha256.Size]byte) Result {
	s, err := Open(envelope, keys)
	if err != nil {
		return FromError(err)
	}
	return s.Proof(p, sum)
}

// HashReader returns the SHA-256 of r, read as a stream.
func HashReader(r io.Reader) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return sum, err
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}
