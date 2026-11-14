package offline

import (
	"fmt"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/deletion"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/dsse"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify"
)

// SignedDeletion is a deletion record whose DSSE signature verified under a trusted key.
type SignedDeletion struct {
	Record deletion.Record
}

// OpenDeletion decodes the envelope, verifies its signature against keys (the payload type must be
// deletion.PayloadType, so a manifest envelope is refused) and decodes the record. The error wraps
// verify.ErrTampered, ErrUntrustedKey or ErrMalformed where it can; use [FromError] for a Result.
//
// A verified record proves what Cipherframe says it deleted and that it destroyed the content
// keys. It cannot prove that nobody kept a copy (docs/integrity.md).
func OpenDeletion(envelope []byte, keys KeySet) (*SignedDeletion, error) {
	env, err := dsse.Decode(envelope)
	if err != nil {
		return nil, err
	}
	res, err := dsse.Verify(env, deletion.PayloadType, keys)
	if err != nil {
		return nil, err
	}
	if err := res.RequireAny(); err != nil {
		return nil, err
	}
	rec, err := deletion.Parse(res.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", verify.ErrMalformed, err)
	}
	return &SignedDeletion{Record: rec}, nil
}

// VerifyDeletion is OpenDeletion with the outcome of a person-facing check: Ours with the record
// when the signature verified, otherwise CannotSay with the precise reason. A deletion record has
// no "modified" outcome: there is no file to compare, only a signature to check.
func VerifyDeletion(envelope []byte, keys KeySet) (Result, *SignedDeletion) {
	s, err := OpenDeletion(envelope, keys)
	if err != nil {
		return FromError(err), nil
	}
	return Result{Ours, ReasonVerified, "the deletion record is signed by a trusted key"}, s
}
