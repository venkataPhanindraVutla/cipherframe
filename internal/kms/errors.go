package kms

import (
	"context"
	"errors"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

// Kind classifies a key-management failure.
type Kind int

// The kinds. Other is the zero value: anything not positively recognised is Other, never
// Invalid, so an unknown failure is not reported as tampering (invariant I8 and I11).
const (
	// Other is any failure that is not one of the kinds below.
	Other Kind = iota
	// Unavailable means the provider timed out or could not be reached. Retryable.
	Unavailable
	// Denied means the provider refused the credentials or the operation. It is an operator
	// misconfiguration, not the caller's fault.
	Denied
	// Invalid means authentication of a wrapped key failed: tampered ciphertext, wrong
	// associated data, malformed envelope, or a request the provider rejects as malformed.
	Invalid
	// NotConfigured means the provider or key version named by a wrapped key is not available in
	// this process.
	NotConfigured
)

// String returns the kind's name.
func (k Kind) String() string {
	switch k {
	case Other:
		return "other"
	case Unavailable:
		return "unavailable"
	case Denied:
		return "denied"
	case Invalid:
		return "invalid"
	case NotConfigured:
		return "not_configured"
	default:
		return "unknown"
	}
}

// Sentinels for errors.Is, one per kind: errors.Is(err, kms.ErrUnavailable).
var (
	ErrOther         = &Error{Kind: Other}
	ErrUnavailable   = &Error{Kind: Unavailable}
	ErrDenied        = &Error{Kind: Denied}
	ErrInvalid       = &Error{Kind: Invalid}
	ErrNotConfigured = &Error{Kind: NotConfigured}
)

// Error is the error type of this package. It names the kind, the provider and the operation. It
// never holds plaintext, key material, ciphertext, associated data or a provider's own error text,
// because those can contain secrets; only a context error is kept as a cause.
type Error struct {
	Kind Kind
	// Provider is the provider name, for example "local". Empty for a sentinel.
	Provider string
	// Op is the operation: "current", "wrap", "unwrap" or "lookup". Empty for a sentinel.
	Op string
	// Detail is a fixed, safe sentence that adds context. It may be empty.
	Detail string

	cause error // only context errors, which are safe to expose
}

// New builds an Error. detail must be a fixed sentence without values.
func New(kind Kind, provider, op, detail string) *Error {
	return &Error{Kind: kind, Provider: provider, Op: op, Detail: detail}
}

// FromContext classifies a context failure as Unavailable (a deadline or a cancelled request means
// the provider could not answer), keeping the context error as the cause. It returns nil when ctx
// is still live.
func FromContext(ctx context.Context, provider, op string) *Error {
	err := ctx.Err()
	if err == nil {
		return nil
	}
	e := New(Unavailable, provider, op, "request deadline passed or was cancelled")
	e.cause = err
	return e
}

// Error returns kind, provider, operation and detail only.
func (e *Error) Error() string {
	s := "kms"
	if e.Provider != "" {
		s += " " + e.Provider
	}
	if e.Op != "" {
		s += " " + e.Op
	}
	s += ": " + e.Kind.String()
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

// Unwrap returns the context error for a deadline or cancellation, and nil otherwise.
func (e *Error) Unwrap() error { return e.cause }

// Is makes errors.Is(err, ErrUnavailable) and the other sentinels match by kind.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok || t.Op != "" || t.Provider != "" || t.Detail != "" {
		return false
	}
	return t.Kind == e.Kind
}

// KindOf returns the kind of err, or Other when err is not (and does not wrap) a kms Error.
// KindOf(nil) is Other; check for nil first.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return Other
}

// IsIntegrityFailure reports whether err means a wrapped key failed authentication. Callers log
// it as an integrity failure (identifiers only, never values).
func IsIntegrityFailure(err error) bool { return KindOf(err) == Invalid && err != nil }

// ToAppError maps a key-management failure to an internal/errs error for the API layer. The kms
// error is kept as the cause (it holds no key material) and is never part of the client-facing
// detail.
//
//	Unavailable   -> dependency_unavailable (retryable)
//	Denied        -> internal_error (the operator's provider credentials are wrong)
//	Invalid       -> internal_error (the stored key failed authentication)
//	NotConfigured -> internal_error
//	Other         -> internal_error
//
// A nil err gives nil. An error that is not a kms Error is Other.
func ToAppError(err error) error {
	if err == nil {
		return nil
	}
	var already *errs.Error
	if errors.As(err, &already) {
		return err
	}
	if KindOf(err) == Unavailable {
		return errs.Wrap(errs.DependencyUnavailable, "key service unavailable", err)
	}
	return errs.Wrap(errs.InternalError, "internal error", err)
}
