// Package reqid creates request IDs and carries them in a context (ADR 0012).
package reqid

import (
	"context"
	"uuid"
)

type ctxKey struct{}

// New returns a new request ID: a UUIDv7 in its standard string form.
func New() string { return uuid.NewV7().String() }

// WithContext returns a context carrying id.
func WithContext(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the request ID stored by WithContext. ok is false if none is set or it
// is empty.
func FromContext(ctx context.Context) (id string, ok bool) {
	id, ok = ctx.Value(ctxKey{}).(string)
	return id, ok && id != ""
}

// Sanitize reports whether s is an acceptable incoming request ID and returns it in canonical
// lowercase form. Only the 36-character hyphenated UUID form is accepted (any version), so a
// caller cannot inject arbitrary text into logs or response headers.
func Sanitize(s string) (string, bool) {
	if len(s) != 36 {
		return "", false
	}
	u, err := uuid.Parse(s)
	if err != nil {
		return "", false
	}
	return u.String(), true
}
