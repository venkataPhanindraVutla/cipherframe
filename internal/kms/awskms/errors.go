//go:build !nokms_aws

package awskms

import (
	"context"
	"errors"
	"io"
	"net"
	"regexp"
	"strconv"
	"syscall"

	"github.com/aws/smithy-go"

	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
)

var safeCode = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// codeKinds maps AWS KMS error codes (and the generic credential and throttling codes) to kinds.
// A code that is absent is decided by HTTP status and transport, and otherwise is kms.Other.
var codeKinds = map[string]kms.Kind{
	// The key is not usable: disabled, pending deletion or import, or absent.
	"KMSInvalidStateException": kms.NotConfigured,
	"DisabledException":        kms.NotConfigured,
	"NotFoundException":        kms.NotConfigured,

	// The caller is not allowed, or its credentials are not accepted.
	"AccessDeniedException":       kms.Denied,
	"AccessDenied":                kms.Denied,
	"UnrecognizedClientException": kms.Denied,
	"InvalidClientTokenId":        kms.Denied,
	"InvalidSignatureException":   kms.Denied,
	"SignatureDoesNotMatch":       kms.Denied,
	"ExpiredTokenException":       kms.Denied,
	"ExpiredToken":                kms.Denied,
	"MissingAuthenticationToken":  kms.Denied,

	// Authentication of the wrapped key failed, or the request is malformed.
	"InvalidCiphertextException": kms.Invalid,
	"IncorrectKeyException":      kms.Invalid,
	"ValidationException":        kms.Invalid,

	// Retryable service conditions.
	"ThrottlingException":         kms.Unavailable,
	"Throttling":                  kms.Unavailable,
	"LimitExceededException":      kms.Unavailable,
	"RequestLimitExceeded":        kms.Unavailable,
	"TooManyRequestsException":    kms.Unavailable,
	"DependencyTimeoutException":  kms.Unavailable,
	"KMSInternalException":        kms.Unavailable,
	"KeyUnavailableException":     kms.Unavailable,
	"ServiceUnavailable":          kms.Unavailable,
	"ServiceUnavailableException": kms.Unavailable,
	"InternalFailure":             kms.Unavailable,
	"RequestTimeout":              kms.Unavailable,
	"RequestTimeoutException":     kms.Unavailable,
}

// fail turns an SDK error into a kms.Error. The SDK error text is dropped, because it can carry key
// ARNs, account ids and request details; only the AWS error code and the HTTP status survive, in a
// fixed sentence. ctx is the call's context: if it is done, the failure is a context failure.
func fail(ctx context.Context, op string, err error) error {
	if ce := kms.FromContext(ctx, Name, op); ce != nil {
		return ce
	}
	kind, code, status := classify(err)
	return kms.New(kind, Name, op, detail(code, status))
}

func detail(code string, status int) string {
	s := ""
	if code != "" {
		s = "aws error code " + code
	}
	if status != 0 {
		if s != "" {
			s += ", "
		}
		s += "http " + strconv.Itoa(status)
	}
	return s
}

// classify maps an SDK or network error to a kind, an AWS error code and an HTTP status.
// Order matters: deadlines first, then the AWS error code, then the HTTP status, then the network.
func classify(err error) (kind kms.Kind, code string, status int) {
	var sc interface{ HTTPStatusCode() int }
	if errors.As(err, &sc) {
		status = sc.HTTPStatusCode()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return kms.Unavailable, "", status
	}
	if errors.Is(err, context.Canceled) {
		return kms.Unavailable, "", status
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
		return kms.Unavailable, code, status
	}
	var opErr *net.OpError
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &opErr), errors.As(err, &dnsErr),
		errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.ECONNRESET),
		errors.Is(err, syscall.EPIPE), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return kms.Unavailable, code, status
	}
	return kms.Other, code, status
}

func kindFromStatus(status int) kms.Kind {
	switch {
	case status == 408, status == 429, status >= 500:
		return kms.Unavailable
	case status == 401, status == 403:
		return kms.Denied
	default:
		return kms.Other
	}
}
