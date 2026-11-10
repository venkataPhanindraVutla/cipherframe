// Package errs is Cipherframe's error model (ADR 0012): a closed registry of error codes, an
// error type that carries a safe client-facing detail, and RFC 9457 problem responses.
package errs

import "sort"

// Code is a stable, lower_snake_case error identifier. Codes are a closed set: only the constants
// below, which must also appear in registry.
type Code string

// Registered codes. Adding one is a compatible change; renaming or removing one is breaking.
const (
	InvalidRequest        Code = "invalid_request"
	Unauthenticated       Code = "unauthenticated"
	Forbidden             Code = "forbidden"
	NotFound              Code = "not_found"
	Conflict              Code = "conflict"
	PayloadTooLarge       Code = "payload_too_large"
	RateLimited           Code = "rate_limited"
	InternalError         Code = "internal_error"
	DependencyUnavailable Code = "dependency_unavailable"
	Timeout               Code = "timeout"
)

// Info describes a registered code.
type Info struct {
	Status    int    // HTTP status
	Title     string // short, stable, human-readable summary
	Retryable bool   // whether repeating the same request may succeed
}

var registry = map[Code]Info{
	InvalidRequest:        {Status: 400, Title: "Invalid request"},
	Unauthenticated:       {Status: 401, Title: "Authentication required"},
	Forbidden:             {Status: 403, Title: "Forbidden"},
	NotFound:              {Status: 404, Title: "Not found"},
	Conflict:              {Status: 409, Title: "Conflict"},
	PayloadTooLarge:       {Status: 413, Title: "Payload too large"},
	RateLimited:           {Status: 429, Title: "Too many requests", Retryable: true},
	InternalError:         {Status: 500, Title: "Internal error"},
	DependencyUnavailable: {Status: 503, Title: "Dependency unavailable", Retryable: true},
	Timeout:               {Status: 504, Title: "Timeout", Retryable: true},
}

// Lookup returns the registry entry for c.
func Lookup(c Code) (Info, bool) {
	i, ok := registry[c]
	return i, ok
}

// Codes returns every registered code, sorted. Use it to publish the enum in the OpenAPI spec.
func Codes() []Code {
	out := make([]Code, 0, len(registry))
	for c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
