package config

import (
	"net/url"
	"regexp"
)

// CDN variables (ADR 0062). CDN delivery is off unless CIPHERFRAME_CDN_PROVIDER is set.
const (
	EnvCDNProvider = "CIPHERFRAME_CDN_PROVIDER"
	EnvCDNBaseURL  = "CIPHERFRAME_CDN_BASE_URL"
	// EnvCDNKeyID is the CloudFront public key ID or the Cloud CDN signing key name.
	EnvCDNKeyID = "CIPHERFRAME_CDN_KEY_ID"
	// EnvCDNSigningKeyFile is the path of the signing key. There is deliberately no variable that
	// takes the key itself.
	EnvCDNSigningKeyFile = "CIPHERFRAME_CDN_SIGNING_KEY_FILE"
	// envCDNSigningKeyLiteral is never read: it exists to refuse a literal key with a clear message.
	envCDNSigningKeyLiteral = "CIPHERFRAME_CDN_SIGNING_KEY"

	EnvCDNCloudFrontDistributionID = "CIPHERFRAME_CDN_CLOUDFRONT_DISTRIBUTION_ID"
	EnvCDNCloudCDNProject          = "CIPHERFRAME_CDN_CLOUDCDN_PROJECT"
	EnvCDNCloudCDNURLMap           = "CIPHERFRAME_CDN_CLOUDCDN_URL_MAP"
)

// The CDN providers.
const (
	CDNCloudFront = "cloudfront"
	CDNCloudCDN   = "cloudcdn"
)

var (
	cdnKeyIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	// A CloudFront distribution ID, such as E2EXAMPLE1ABCD.
	cdnDistributionRE = regexp.MustCompile(`^[A-Z0-9]{8,32}$`)
	// A GCP project ID or URL map name: lower-case letters, digits and hyphens.
	cdnGCPNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

// CDN configures the optional CDN of the cdn delivery strategy. The zero Provider means no CDN.
// The signing key is read from SigningKeyFile by the edge role only, which signs (SigningKeyFile is
// empty on the other roles); the api role needs only to know that a CDN is configured, and the
// worker role needs the purge settings.
type CDN struct {
	Provider string
	// BaseURL is the CDN's origin as browsers reach it, https://host (https only; http is allowed
	// in development), with no path.
	BaseURL string
	// KeyID is the CloudFront public key ID, or the Cloud CDN signing key name.
	KeyID          string
	SigningKeyFile string
	// CloudFrontDistributionID is the distribution to invalidate (provider cloudfront).
	CloudFrontDistributionID string
	// CloudCDNProject and CloudCDNURLMap name the URL map to invalidate (provider cloudcdn).
	CloudCDNProject string
	CloudCDNURLMap  string
}

// Enabled reports whether a CDN is configured.
func (c CDN) Enabled() bool { return c.Provider != "" }

func (l *loader) cdn(prod bool) CDN {
	var c CDN
	c.Provider = l.plain(EnvCDNProvider, "")
	if _, literal := l.look(envCDNSigningKeyLiteral); literal {
		l.errf("%s is not supported: put the key in a file and set %s", envCDNSigningKeyLiteral, EnvCDNSigningKeyFile)
	}
	if c.Provider == "" {
		for _, n := range []string{EnvCDNBaseURL, EnvCDNKeyID, EnvCDNSigningKeyFile, EnvCDNCloudFrontDistributionID, EnvCDNCloudCDNProject, EnvCDNCloudCDNURLMap} {
			if l.plain(n, "") != "" {
				l.errf("%s is set but %s is not", n, EnvCDNProvider)
			}
		}
		return c
	}
	if c.Provider != CDNCloudFront && c.Provider != CDNCloudCDN {
		l.errf("%s must be %q or %q", EnvCDNProvider, CDNCloudFront, CDNCloudCDN)
		return CDN{}
	}
	if v := l.plain(EnvCDNBaseURL, ""); v == "" {
		l.errf("%s is required when %s is set", EnvCDNBaseURL, EnvCDNProvider)
	} else if u, err := url.Parse(v); err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Opaque != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "https" && (u.Scheme != "http" || prod)) {
		l.errf("%s must be an https URL of the form https://host, without path, query or credentials (http is allowed only in development)", EnvCDNBaseURL)
	} else {
		c.BaseURL = u.Scheme + "://" + u.Host
	}
	if v := l.plain(EnvCDNKeyID, ""); v == "" {
		l.errf("%s is required when %s is set", EnvCDNKeyID, EnvCDNProvider)
	} else if !cdnKeyIDRE.MatchString(v) {
		l.errf("%s must be 1 to 128 letters, digits, hyphens or underscores", EnvCDNKeyID)
	} else {
		c.KeyID = v
	}
	// Only the edge role signs, so only it needs the file: cdn.NewSigner checks it is set.
	c.SigningKeyFile = l.plain(EnvCDNSigningKeyFile, "")
	switch c.Provider {
	case CDNCloudFront:
		c.CloudFrontDistributionID = l.plain(EnvCDNCloudFrontDistributionID, "")
		if !cdnDistributionRE.MatchString(c.CloudFrontDistributionID) {
			l.errf("%s is required for the cloudfront provider (a distribution ID such as E2EXAMPLE1ABCD)", EnvCDNCloudFrontDistributionID)
		}
	case CDNCloudCDN:
		c.CloudCDNProject = l.plain(EnvCDNCloudCDNProject, "")
		c.CloudCDNURLMap = l.plain(EnvCDNCloudCDNURLMap, "")
		if !cdnGCPNameRE.MatchString(c.CloudCDNProject) {
			l.errf("%s is required for the cloudcdn provider (a GCP project ID)", EnvCDNCloudCDNProject)
		}
		if !cdnGCPNameRE.MatchString(c.CloudCDNURLMap) {
			l.errf("%s is required for the cloudcdn provider (the URL map name)", EnvCDNCloudCDNURLMap)
		}
	}
	return c
}
