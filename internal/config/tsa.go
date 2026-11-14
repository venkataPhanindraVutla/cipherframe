package config

import (
	"net/url"
	"regexp"
	"time"
)

// RFC 3161 anchoring variables (ADR 0041). Anchoring is off unless CIPHERFRAME_TSA_URL is set.
const (
	EnvTSAURL       = "CIPHERFRAME_TSA_URL"
	EnvTSATimeout   = "CIPHERFRAME_TSA_TIMEOUT"
	EnvTSAPolicyOID = "CIPHERFRAME_TSA_POLICY_OID"
)

const (
	defaultTSATimeout = 10 * time.Second
	tsaTimeoutCeiling = 2 * time.Minute
)

var oidRE = regexp.MustCompile(`^[0-2](\.(0|[1-9][0-9]*))+$`)

// TSA configures the optional RFC 3161 time-stamping authority. The zero URL means anchoring is off.
type TSA struct {
	// URL is the authority's endpoint: https, or http in development for a local authority.
	URL string
	// Timeout bounds one request to the authority.
	Timeout time.Duration
	// PolicyOID, when set, is asked for as the token's policy (dotted decimal).
	PolicyOID string
}

// Enabled reports whether anchoring is configured.
func (t TSA) Enabled() bool { return t.URL != "" }

func (l *loader) tsa(prod bool) TSA {
	t := TSA{Timeout: l.positiveDuration(EnvTSATimeout, defaultTSATimeout, tsaTimeoutCeiling)}
	if v := l.plain(EnvTSAURL, ""); v != "" {
		u, err := url.Parse(v)
		switch {
		case err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "":
			l.errf("%s must be an absolute URL without credentials", EnvTSAURL)
		case u.Scheme != "https" && (u.Scheme != "http" || prod):
			l.errf("%s must be an https URL (http is allowed only in development)", EnvTSAURL)
		default:
			t.URL = v
		}
	}
	if v := l.plain(EnvTSAPolicyOID, ""); v != "" {
		if !oidRE.MatchString(v) {
			l.errf("%s must be a dotted-decimal object identifier, for example 1.2.3.4", EnvTSAPolicyOID)
		} else {
			t.PolicyOID = v
		}
	}
	return t
}
