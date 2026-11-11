package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"syscall"

	"github.com/aws/smithy-go"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// Kind classifies a storage failure.
type Kind int

// The kinds. Other is the zero value: anything not positively recognised is Other, never NotFound.
const (
	// Other is any failure that is not one of the kinds below.
	Other Kind = iota
	// NotFound means the object (or multipart upload) does not exist.
	NotFound
	// PermissionDenied means the storage credentials were refused. It is an operator
	// misconfiguration, not the caller's fault.
	PermissionDenied
	// Timeout means a deadline passed or the network timed out.
	Timeout
	// Unavailable means the store could not be reached or reported a server-side failure.
	Unavailable
	// Invalid means the request itself was rejected as malformed.
	Invalid
)

// String returns the kind's name.
func (k Kind) String() string {
	switch k {
	case Other:
		return "other"
	case NotFound:
		return "not_found"
	case PermissionDenied:
		return "permission_denied"
	case Timeout:
		return "timeout"
	case Unavailable:
		return "unavailable"
	case Invalid:
		return "invalid"
	default:
		return "unknown"
	}
}

// Sentinels for errors.Is, one per kind: errors.Is(err, storage.ErrNotFound).
var (
	ErrOther            = &Error{Kind: Other}
	ErrNotFound         = &Error{Kind: NotFound}
	ErrPermissionDenied = &Error{Kind: PermissionDenied}
	ErrTimeout          = &Error{Kind: Timeout}
	ErrUnavailable      = &Error{Kind: Unavailable}
	ErrInvalid          = &Error{Kind: Invalid}
)

// Error is the error type of this package. It names the kind, the operation and the bucket role. It
// never holds an object key, a URL or a credential, and the underlying SDK error is dropped
// because its text can include them; only the S3 error code and the HTTP status survive.
type Error struct {
	Kind Kind
	// Op is the operation: "put", "get", "head", "list", "delete_batch", "presign_get", ...
	Op string
	// Role is the bucket role, source or delivery. It is empty for a sentinel.
	Role keys.Bucket
	// Code is the S3 error code, for example "NoSuchKey". It may be empty.
	Code string
	// HTTPStatus is the HTTP status of the response, or 0.
	HTTPStatus int
	// Detail is a fixed, safe sentence that adds context. It may be empty.
	Detail string

	cause error // only context errors, which are safe to expose
}

// Error returns kind, operation, role, code and status. It never includes a key or URL.
func (e *Error) Error() string {
	s := "storage"
	if e.Op != "" {
		s += " " + e.Op
	}
	if e.Role != "" {
		s += " (" + string(e.Role) + ")"
	}
	s += ": " + e.Kind.String()
	if e.Code != "" {
		s += ", code " + e.Code
	}
	if e.HTTPStatus != 0 {
		s += fmt.Sprintf(", http %d", e.HTTPStatus)
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

// Unwrap returns the context error for a deadline or cancellation, and nil otherwise.
func (e *Error) Unwrap() error { return e.cause }

// Is makes errors.Is(err, ErrNotFound) and the other sentinels match by kind.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok || t.Op != "" || t.Role != "" || t.Code != "" || t.HTTPStatus != 0 || t.Detail != "" {
		return false
	}
	return t.Kind == e.Kind
}

// KindOf returns the kind of err, or Other when err is not (and does not wrap) a storage Error.
// KindOf(nil) is Other; check for nil first.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return Other
}

// invalid builds an Error for a request rejected before it was sent.
func invalid(op string, role keys.Bucket, detail string) *Error {
	return &Error{Kind: Invalid, Op: op, Role: role, Detail: detail}
}

// wrapErr turns an SDK error into an Error. An Error passes through unchanged.
func wrapErr(op string, role keys.Bucket, err error) error {
	if err == nil {
		return nil
	}
	var already *Error
	if errors.As(err, &already) {
		return err
	}
	k, code, status := classify(err)
	e := &Error{Kind: k, Op: op, Role: role, Code: code, HTTPStatus: status}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		e.cause = context.DeadlineExceeded
	case errors.Is(err, context.Canceled):
		e.cause = context.Canceled
	}
	return e
}

var safeCode = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// codeKinds maps S3 error codes. A code listed as Other is recognised but deliberately not
// mapped to a more specific kind (a missing bucket is a configuration problem, not a missing object).
var codeKinds = map[string]Kind{
	"NoSuchKey":    NotFound,
	"NotFound":     NotFound,
	"NoSuchUpload": NotFound,
	"NoSuchBucket": Other,

	"AccessDenied":                  PermissionDenied,
	"Forbidden":                     PermissionDenied,
	"InvalidAccessKeyId":            PermissionDenied,
	"SignatureDoesNotMatch":         PermissionDenied,
	"ExpiredToken":                  PermissionDenied,
	"InvalidToken":                  PermissionDenied,
	"AllAccessDisabled":             PermissionDenied,
	"AccountProblem":                PermissionDenied,
	"RequestTimeTooSkewed":          PermissionDenied,
	"AuthorizationHeaderMalformed":  PermissionDenied,
	"InvalidSecurity":               PermissionDenied,
	"AccessControlListNotSupported": PermissionDenied,

	"RequestTimeout":          Timeout,
	"RequestTimeoutException": Timeout,

	"ServiceUnavailable":       Unavailable,
	"SlowDown":                 Unavailable,
	"InternalError":            Unavailable,
	"ThrottlingException":      Unavailable,
	"Throttling":               Unavailable,
	"RequestLimitExceeded":     Unavailable,
	"TooManyRequestsException": Unavailable,
	"OperationAborted":         Unavailable,

	"InvalidArgument":           Invalid,
	"InvalidRequest":            Invalid,
	"InvalidPart":               Invalid,
	"InvalidPartOrder":          Invalid,
	"EntityTooSmall":            Invalid,
	"EntityTooLarge":            Invalid,
	"MalformedXML":              Invalid,
	"InvalidRange":              Invalid,
	"InvalidDigest":             Invalid,
	"BadDigest":                 Invalid,
	"KeyTooLongError":           Invalid,
	"MissingContentLength":      Invalid,
	"InvalidBucketName":         Invalid,
	"XAmzContentSHA256Mismatch": Invalid,
	"IncompleteBody":            Invalid,
	"MalformedPOSTRequest":      Invalid,
	"InvalidURI":                Invalid,
	"InvalidLocationConstraint": Invalid,
	"UnexpectedContent":         Invalid,
	"MissingRequestBodyError":   Invalid,
	"InvalidObjectState":        Other,
	"BucketAlreadyOwnedByYou":   Other,
	"NoSuchBucketPolicy":        Other,
}

// classify maps an SDK or network error to a kind, an S3 error code and an HTTP status.
// Order matters: deadlines first, then the S3 error code, then the HTTP status, then the network.
func classify(err error) (kind Kind, code string, status int) {
	var sc interface{ HTTPStatusCode() int }
	if errors.As(err, &sc) {
		status = sc.HTTPStatusCode()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Timeout, "", status
	}
	if errors.Is(err, context.Canceled) {
		return Other, "", status
	}

	var api smithy.APIError
	if errors.As(err, &api) {
		c := api.ErrorCode()
		if safeCode.MatchString(c) {
			code = c
		}
		if k, ok := codeKinds[c]; ok {
			return k, code, status
		}
	}
	if status != 0 {
		return kindFromStatus(status), code, status
	}

	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return Timeout, code, status
	}
	var opErr *net.OpError
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &opErr), errors.As(err, &dnsErr),
		errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.ECONNRESET),
		errors.Is(err, syscall.EPIPE), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return Unavailable, code, status
	}
	return Other, code, status
}

func kindFromStatus(status int) Kind {
	switch {
	case status == 404:
		return NotFound
	case status == 401 || status == 403:
		return PermissionDenied
	case status == 408:
		return Timeout
	case status == 429 || status >= 500:
		return Unavailable
	case status == 400 || status == 411 || status == 413 || status == 416:
		return Invalid
	default:
		return Other
	}
}

// ToAppError maps a storage failure to an internal/errs error for the API layer. The storage error
// is kept as the cause (it holds no key or URL) and is never part of the client-facing detail.
//
//	NotFound         -> not_found
//	PermissionDenied -> internal_error (the operator's storage credentials are wrong)
//	Timeout          -> timeout
//	Unavailable      -> dependency_unavailable
//	Invalid          -> invalid_request
//	Other            -> internal_error
//
// A nil err gives nil. An error that is not a storage Error is Other.
func ToAppError(err error) error {
	if err == nil {
		return nil
	}
	switch KindOf(err) {
	case NotFound:
		return errs.Wrap(errs.NotFound, "resource not found", err)
	case Timeout:
		return errs.Wrap(errs.Timeout, "storage timed out", err)
	case Unavailable:
		return errs.Wrap(errs.DependencyUnavailable, "storage unavailable", err)
	case Invalid:
		return errs.Wrap(errs.InvalidRequest, "invalid storage request", err)
	case PermissionDenied, Other:
		return errs.Wrap(errs.InternalError, "internal error", err)
	default:
		return errs.Wrap(errs.InternalError, "internal error", err)
	}
}

// Sanitize turns an error from the raw S3 client (which the tus data store uses) into an Error
// that is safe to log and to wrap: kind, operation, role, S3 code and status only. op names the
// operation, for example "tus_write_chunk".
func Sanitize(op string, role keys.Bucket, err error) error { return wrapErr(op, role, err) }
