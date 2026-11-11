package errs

import "fmt"

// Error is an error with a registered Code and a safe, client-facing Detail.
//
// Detail is returned to API callers verbatim. It must never contain secrets, tokens, signed URLs,
// source object keys, key material or internal error text. Put anything internal in the cause,
// which is logged but never sent to clients.
type Error struct {
	Code   Code
	Detail string
	// Fields lists the invalid request fields of an invalid_request error. Like Detail, it is sent
	// to clients, so it holds field names and fixed messages only, never submitted values.
	Fields []FieldError
	cause  error
}

// FieldError says what is wrong with one request field.
type FieldError struct {
	// Field is the JSON name of the field, with an index for list items: "allowed_origins[2]".
	Field string `json:"field"`
	// Message is a fixed, human-readable reason. It never quotes the submitted value.
	Message string `json:"message"`
}

// Invalid returns an invalid_request error that carries one entry per invalid field.
func Invalid(detail string, fields []FieldError) *Error {
	return &Error{Code: InvalidRequest, Detail: detail, Fields: fields}
}

// New returns an Error with no cause.
func New(code Code, detail string) *Error {
	return &Error{Code: code, Detail: detail}
}

// Wrap returns an Error that wraps cause. The cause is reachable through errors.Is, errors.As
// and Unwrap, but is not part of Error() or of any response.
func Wrap(code Code, detail string, cause error) *Error {
	return &Error{Code: code, Detail: detail, cause: cause}
}

// Error returns the code and detail only, never the cause text.
func (e *Error) Error() string {
	if e.Detail == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Detail)
}

// Unwrap returns the cause, if any.
func (e *Error) Unwrap() error { return e.cause }
