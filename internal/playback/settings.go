package playback

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

// MaxAllowedOrigins is the most origins a tenant can list.
const MaxAllowedOrigins = 20

// ValidateSettings checks every setting against the ranges of ADR 0028 and returns one entry per
// problem (nil when valid). The playback_settings CHECK constraints enforce the same rules; this
// is the first line, so clients get field-level messages. Messages never quote submitted values.
func ValidateSettings(s db.PlaybackSettings) []errs.FieldError {
	var out []errs.FieldError
	bad := func(field, msg string) { out = append(out, errs.FieldError{Field: field, Message: msg}) }
	rng := func(field string, v, lo, hi int) {
		if v < lo || v > hi {
			bad(field, fmt.Sprintf("must be between %d and %d", lo, hi))
		}
	}
	rng("token_ttl_seconds", s.TokenTTLSeconds, 60, 3600)
	rng("heartbeat_interval_seconds", s.HeartbeatIntervalSeconds, 10, 600)
	rng("idle_timeout_seconds", s.IdleTimeoutSeconds, 30, 3600)
	rng("session_max_seconds", s.SessionMaxSeconds, 300, 86400)
	rng("max_sessions_per_viewer", s.MaxSessionsPerViewer, 0, 100)
	rng("key_fetches_per_token", s.KeyFetchesPerToken, 1, 1000)
	rng("key_requests_per_minute", s.KeyRequestsPerMinute, 1, 600)
	// The relations only make sense when both sides are in range.
	inRange := func(v, lo, hi int) bool { return v >= lo && v <= hi }
	hbOK := inRange(s.HeartbeatIntervalSeconds, 10, 600)
	if hbOK && inRange(s.TokenTTLSeconds, 60, 3600) && s.HeartbeatIntervalSeconds >= s.TokenTTLSeconds {
		bad("heartbeat_interval_seconds", "must be less than token_ttl_seconds")
	}
	if hbOK && inRange(s.IdleTimeoutSeconds, 30, 3600) && s.HeartbeatIntervalSeconds >= s.IdleTimeoutSeconds {
		bad("heartbeat_interval_seconds", "must be less than idle_timeout_seconds")
	}
	if len(s.AllowedOrigins) > MaxAllowedOrigins {
		bad("allowed_origins", fmt.Sprintf("must list at most %d origins", MaxAllowedOrigins))
	}
	seen := map[string]bool{}
	for i, o := range s.AllowedOrigins {
		field := "allowed_origins[" + strconv.Itoa(i) + "]"
		if msg := checkOrigin(o); msg != "" {
			bad(field, msg)
		} else if seen[o] {
			bad(field, "must not repeat another entry")
		}
		seen[o] = true
	}
	return out
}

const originHint = "must be an exact origin such as https://example.com or https://example.com:8443"

// checkOrigin returns why o is not an acceptable origin, or "". An origin is exactly
// scheme://host[:port], as a browser writes it in the Origin header: https (or http for
// localhost only), a lower-case DNS or IPv4 host, an explicit port only when it is not the scheme's
// default, no wildcard, user information, path, query or fragment.
func checkOrigin(o string) string {
	if strings.Contains(o, "*") {
		return "must not contain a wildcard"
	}
	u, err := url.Parse(o)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return originHint
	}
	host := u.Hostname()
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && host == "localhost":
	case u.Scheme == "http":
		return "must use https (http is allowed for localhost only)"
	default:
		return originHint
	}
	if !validHost(host) {
		return originHint
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
			return originHint
		}
		if (u.Scheme == "https" && n == 443) || (u.Scheme == "http" && n == 80) {
			return "must omit the default port, as browsers do in the Origin header"
		}
	}
	// Rebuilding the origin from its parts and comparing catches every other form: a path, a
	// trailing slash, a query, a fragment, user information, an empty port, upper-case letters.
	canon := u.Scheme + "://" + host
	if p := u.Port(); p != "" {
		canon += ":" + p
	}
	if canon != o {
		return originHint
	}
	return ""
}

// validHost accepts lower-case DNS names (letters, digits, hyphens, dots, no empty or
// hyphen-edged labels, at most 253 characters), which includes dotted IPv4 addresses.
func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}
