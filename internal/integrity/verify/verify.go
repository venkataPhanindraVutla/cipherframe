// Package verify defines the error taxonomy shared by every Cipherframe integrity verifier.
//
// A verifier ends in exactly one of five outcomes (see [Outcome]):
//
//   - [Verified]: every check passed.
//   - [Tampered]: a cryptographic mismatch was proven (a hash, Merkle path or signature that
//     does not match). Only errors wrapping [ErrTampered] produce it.
//   - [UntrustedKey]: the document is well formed but no signature came from a key the caller
//     trusts. Only errors wrapping [ErrUntrustedKey] produce it.
//   - [Malformed]: the input is not a valid document of the expected shape. Only errors wrapping
//     [ErrMalformed] produce it.
//   - [CannotSay]: anything else. Network, permission, timeout, storage and unknown errors land
//     here and are never reported as tampered or missing (pitfall 2): not being able to check
//     is different from having checked and found a mismatch.
//
// Library code returns errors that wrap one of the sentinels where it has proof. Everything it
// cannot classify is returned unwrapped, or explicitly via [Unknown]; [Classify] maps it to
// CannotSay. If an error chain contains both [ErrCannotSay] and another sentinel, CannotSay wins:
// the safe direction is never to claim proof that was not obtained.
package verify

import (
	"errors"
	"fmt"
)

// Sentinel errors. Wrap them with fmt.Errorf("...: %w", ErrX) to add detail.
var (
	// ErrTampered means a cryptographic mismatch was proven.
	ErrTampered = errors.New("integrity: tampered")
	// ErrUntrustedKey means no signature came from a trusted key.
	ErrUntrustedKey = errors.New("integrity: untrusted key")
	// ErrMalformed means the input is not a valid document of the expected shape.
	ErrMalformed = errors.New("integrity: malformed")
	// ErrCannotSay means the verifier could not reach a verdict.
	ErrCannotSay = errors.New("integrity: cannot say")
)

// Outcome is the final verdict of a verification.
type Outcome int

// The possible outcomes.
const (
	Verified Outcome = iota
	Tampered
	UntrustedKey
	Malformed
	CannotSay
)

// String returns a short stable name for the outcome.
func (o Outcome) String() string {
	switch o {
	case Verified:
		return "verified"
	case Tampered:
		return "tampered"
	case UntrustedKey:
		return "untrusted-key"
	case Malformed:
		return "malformed"
	default:
		return "cannot-say"
	}
}

// Classify maps an error to an Outcome. nil is Verified; an error is Tampered, UntrustedKey or
// Malformed only if it wraps the matching sentinel (and not ErrCannotSay); everything else,
// including I/O and context errors, is CannotSay.
func Classify(err error) Outcome {
	switch {
	case err == nil:
		return Verified
	case errors.Is(err, ErrCannotSay):
		return CannotSay
	case errors.Is(err, ErrTampered):
		return Tampered
	case errors.Is(err, ErrUntrustedKey):
		return UntrustedKey
	case errors.Is(err, ErrMalformed):
		return Malformed
	default:
		return CannotSay
	}
}

// Unknown wraps err (for example an I/O error met while fetching a segment) so that it is
// classified as CannotSay whatever it wraps. It returns nil for a nil err.
func Unknown(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrCannotSay, err)
}
