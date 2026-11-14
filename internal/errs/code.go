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
	MethodNotAllowed      Code = "method_not_allowed"
	Conflict              Code = "conflict"
	PayloadTooLarge       Code = "payload_too_large"
	RateLimited           Code = "rate_limited"
	InternalError         Code = "internal_error"
	DependencyUnavailable Code = "dependency_unavailable"
	Timeout               Code = "timeout"
	// AssetNotReady is a 409 for an operation that needs a ready asset (for example starting a
	// playback session) when the asset is not ready yet, or has failed.
	AssetNotReady Code = "asset_not_ready"
	// SessionLimit is a 409 for a viewer that already has the tenant's maximum number of active
	// playback sessions (ADR 0028). Existing sessions are left alone.
	SessionLimit Code = "session_limit"
	// VariantUnavailable is a 409 for a playback session that asks for a variant the asset does
	// not have: "masked" on an asset created without mask_faces (ADR 0036).
	VariantUnavailable Code = "variant_unavailable"
	// VariantNotReady is a 409 for a session that asks for the masked variant before it is ready
	// (pending or failed). It never falls back to the original (ADR 0036).
	VariantNotReady Code = "variant_not_ready"
	// ArtifactNotFound is a 404 for a proof request whose path is not an artifact of the asset's
	// signed manifest (ADR 0039).
	ArtifactNotFound Code = "artifact_not_found"
	// NotAnchored is a 404 for a timestamp request on a manifest that has no RFC 3161 token (ADR 0041).
	NotAnchored Code = "not_anchored"
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
	MethodNotAllowed:      {Status: 405, Title: "Method not allowed"},
	Conflict:              {Status: 409, Title: "Conflict"},
	PayloadTooLarge:       {Status: 413, Title: "Payload too large"},
	RateLimited:           {Status: 429, Title: "Too many requests", Retryable: true},
	InternalError:         {Status: 500, Title: "Internal error"},
	DependencyUnavailable: {Status: 503, Title: "Dependency unavailable", Retryable: true},
	Timeout:               {Status: 504, Title: "Timeout", Retryable: true},
	AssetNotReady:         {Status: 409, Title: "Asset not ready"},
	SessionLimit:          {Status: 409, Title: "Session limit reached"},
	VariantUnavailable:    {Status: 409, Title: "Variant unavailable"},
	VariantNotReady:       {Status: 409, Title: "Variant not ready"},
	ArtifactNotFound:      {Status: 404, Title: "Artifact not found"},
	NotAnchored:           {Status: 404, Title: "Not anchored"},
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
