package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"testing"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// apiErr builds an error shaped like the SDK's: operation error > response error (status) > API error (code).
func apiErr(status int, code string) error {
	var inner error = &smithy.GenericAPIError{Code: code, Message: "secret-key-name should not leak"}
	if status != 0 {
		inner = &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
				Err:      inner,
			},
			RequestID: "req",
		}
	}
	return &smithy.OperationError{ServiceID: "S3", OperationName: "GetObject", Err: inner}
}

func statusOnly(status int) error {
	return &smithy.OperationError{
		ServiceID: "S3", OperationName: "GetObject",
		Err: &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
				Err:      errors.New("plain body"),
			},
		},
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassify(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: &net.OpError{Op: "connect", Err: syscall.ECONNREFUSED}}
	tests := []struct {
		name string
		err  error
		want Kind
	}{
		{"NoSuchKey 404", apiErr(404, "NoSuchKey"), NotFound},
		{"HEAD NotFound", apiErr(404, "NotFound"), NotFound},
		{"NoSuchUpload", apiErr(404, "NoSuchUpload"), NotFound},
		{"unknown code with 404", apiErr(404, "Whatever"), NotFound},
		{"404 without API error", statusOnly(404), NotFound},
		{"NoSuchBucket is not a missing object", apiErr(404, "NoSuchBucket"), Other},
		{"AccessDenied", apiErr(403, "AccessDenied"), PermissionDenied},
		{"bad signature", apiErr(403, "SignatureDoesNotMatch"), PermissionDenied},
		{"403 unknown code", apiErr(403, "Odd"), PermissionDenied},
		{"401", statusOnly(401), PermissionDenied},
		{"deadline", context.DeadlineExceeded, Timeout},
		{"wrapped deadline", fmt.Errorf("op: %w", context.DeadlineExceeded), Timeout},
		{"net timeout", &net.OpError{Op: "read", Err: timeoutErr{}}, Timeout},
		{"RequestTimeout code", apiErr(400, "RequestTimeout"), Timeout},
		{"408", statusOnly(408), Timeout},
		{"connection refused", refused, Unavailable},
		{"connection reset", fmt.Errorf("x: %w", syscall.ECONNRESET), Unavailable},
		{"dns", &net.DNSError{Err: "no such host", Name: "h"}, Unavailable},
		{"500", statusOnly(500), Unavailable},
		{"503 ServiceUnavailable", apiErr(503, "ServiceUnavailable"), Unavailable},
		{"SlowDown", apiErr(503, "SlowDown"), Unavailable},
		{"502", statusOnly(502), Unavailable},
		{"429", statusOnly(429), Unavailable},
		{"InvalidArgument", apiErr(400, "InvalidArgument"), Invalid},
		{"InvalidRange 416", apiErr(416, "InvalidRange"), Invalid},
		{"EntityTooSmall", apiErr(400, "EntityTooSmall"), Invalid},
		{"409 conflict", apiErr(409, "BucketNotEmpty"), Other},
		{"unrecognised plain error", errors.New("boom"), Other},
		{"unrecognised plain error mentioning not found", errors.New("not found"), Other},
		{"canceled", context.Canceled, Other},
		{"unknown API error without status", &smithy.GenericAPIError{Code: "Strange"}, Other},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := wrapErr("get", keys.Source, tc.err)
			if KindOf(got) != tc.want {
				t.Fatalf("kind = %v, want %v (%v)", KindOf(got), tc.want, got)
			}
			if !errors.Is(got, sentinelFor(tc.want)) {
				t.Fatalf("errors.Is does not match the %v sentinel", tc.want)
			}
			for _, k := range []Kind{Other, NotFound, PermissionDenied, Timeout, Unavailable, Invalid} {
				if k != tc.want && errors.Is(got, sentinelFor(k)) {
					t.Fatalf("also matches the %v sentinel", k)
				}
			}
		})
	}
}

func sentinelFor(k Kind) error {
	switch k {
	case NotFound:
		return ErrNotFound
	case PermissionDenied:
		return ErrPermissionDenied
	case Timeout:
		return ErrTimeout
	case Unavailable:
		return ErrUnavailable
	case Invalid:
		return ErrInvalid
	default:
		return ErrOther
	}
}

func TestErrorTextHasNoSDKTextOrKey(t *testing.T) {
	cause := fmt.Errorf("Get \"https://host/bucket/t/ten_x/a/ast_y/source/original?X-Amz-Signature=abc\": %w", io.ErrUnexpectedEOF)
	e := wrapErr("get", keys.Source, cause)
	s := e.Error()
	for _, bad := range []string{"ten_x", "original", "X-Amz", "https://", "bucket/"} {
		if strings.Contains(s, bad) {
			t.Errorf("error text %q contains %q", s, bad)
		}
	}
	if !strings.Contains(s, "get") || !strings.Contains(s, "source") {
		t.Errorf("error text %q lacks operation or role", s)
	}
	e2 := wrapErr("head", keys.Source, apiErr(404, "NoSuchKey"))
	if strings.Contains(e2.Error(), "secret-key-name") {
		t.Errorf("S3 message leaked: %q", e2)
	}
	if !strings.Contains(e2.Error(), "NoSuchKey") {
		t.Errorf("S3 code missing: %q", e2)
	}
}

func TestDeadlineKeepsContextCause(t *testing.T) {
	e := wrapErr("get", keys.Source, fmt.Errorf("request canceled: %w", context.DeadlineExceeded))
	if !errors.Is(e, context.DeadlineExceeded) || !errors.Is(e, ErrTimeout) {
		t.Fatalf("want both deadline and timeout sentinel, got %v", e)
	}
}

func TestWrapErrPassesStorageErrorsThrough(t *testing.T) {
	orig := &Error{Kind: Invalid, Op: "put"}
	if got := wrapErr("get", keys.Source, fmt.Errorf("x: %w", orig)); KindOf(got) != Invalid {
		t.Fatalf("kind changed: %v", got)
	}
	if wrapErr("get", keys.Source, nil) != nil {
		t.Fatal("nil must stay nil")
	}
}

func TestToAppError(t *testing.T) {
	tests := []struct {
		kind Kind
		want errs.Code
	}{
		{NotFound, errs.NotFound},
		{PermissionDenied, errs.InternalError},
		{Timeout, errs.Timeout},
		{Unavailable, errs.DependencyUnavailable},
		{Invalid, errs.InvalidRequest},
		{Other, errs.InternalError},
	}
	for _, tc := range tests {
		t.Run(tc.kind.String(), func(t *testing.T) {
			err := ToAppError(&Error{Kind: tc.kind, Op: "get", Role: keys.Source})
			var ae *errs.Error
			if !errors.As(err, &ae) {
				t.Fatalf("not an errs.Error: %T", err)
			}
			if ae.Code != tc.want {
				t.Fatalf("code = %s, want %s", ae.Code, tc.want)
			}
			if strings.Contains(ae.Detail, "storage get") || strings.Contains(ae.Detail, "(source)") {
				t.Errorf("detail leaks internals: %q", ae.Detail)
			}
		})
	}
	if ToAppError(nil) != nil {
		t.Fatal("nil must stay nil")
	}
	var ae *errs.Error
	if !errors.As(ToAppError(errors.New("unrelated")), &ae) || ae.Code != errs.InternalError {
		t.Fatal("a foreign error must become internal_error")
	}
}
