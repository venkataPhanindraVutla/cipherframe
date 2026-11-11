package config

import (
	"net"
	"regexp"
	"strconv"
	"time"
)

// Environment variables of the GCP Cloud KMS provider (M2-2).
const (
	// EnvKMSGCPKeyName names the Cloud KMS crypto key: projects/P/locations/L/keyRings/R/cryptoKeys/K.
	EnvKMSGCPKeyName = "CIPHERFRAME_KMS_GCP_KEY_NAME"
	// EnvKMSGCPCredentialsFile is the path of a credentials JSON file. Empty means Application
	// Default Credentials.
	EnvKMSGCPCredentialsFile = "CIPHERFRAME_KMS_GCP_CREDENTIALS_FILE" //nolint:gosec // environment variable name, not a credential
	// EnvKMSGCPEndpoint overrides the Cloud KMS endpoint (host:port).
	EnvKMSGCPEndpoint = "CIPHERFRAME_KMS_GCP_ENDPOINT"
	// EnvKMSGCPTimeout is the per-request timeout of Cloud KMS calls.
	EnvKMSGCPTimeout = "CIPHERFRAME_KMS_GCP_TIMEOUT"
)

const (
	defaultKMSGCPTimeout = 5 * time.Second
	maxKMSGCPTimeout     = 5 * time.Minute
)

// gcpKeyName matches a Cloud KMS crypto key resource name (not a key version).
var gcpKeyName = regexp.MustCompile(`^projects/[^/\s]+/locations/[^/\s]+/keyRings/[^/\s]+/cryptoKeys/[^/\s]+$`)

// KMSGCP holds the GCP Cloud KMS provider settings (M2-2). Nothing here is a secret: the
// credentials file is a path, and its content is read by the provider only.
type KMSGCP struct {
	// KeyName is the crypto key resource name.
	KeyName string
	// CredentialsFile is the path of a credentials file, or empty for Application Default
	// Credentials.
	CredentialsFile string
	// Endpoint is an optional host:port that replaces the Cloud KMS endpoint.
	Endpoint string
	// Timeout bounds each Cloud KMS request.
	Timeout time.Duration
}

// kmsGCP reads the GCP Cloud KMS settings. It runs only when CIPHERFRAME_KMS_PROVIDER names this provider.
func (l *loader) kmsGCP(_ bool) KMSGCP {
	g := KMSGCP{
		KeyName:         l.plain(EnvKMSGCPKeyName, ""),
		CredentialsFile: l.plain(EnvKMSGCPCredentialsFile, ""),
		Endpoint:        l.plain(EnvKMSGCPEndpoint, ""),
		Timeout:         defaultKMSGCPTimeout,
	}
	switch {
	case g.KeyName == "":
		l.errf("%s is required when %s is %s", EnvKMSGCPKeyName, EnvKMSProvider, ProviderGCPKMS)
	case !gcpKeyName.MatchString(g.KeyName):
		l.errf("%s must look like projects/P/locations/L/keyRings/R/cryptoKeys/K (a key, not a key version)", EnvKMSGCPKeyName)
	}
	if g.Endpoint != "" && !validHostPort(g.Endpoint) {
		l.errf("%s must be host:port", EnvKMSGCPEndpoint)
	}
	if v := l.plain(EnvKMSGCPTimeout, ""); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 || d > maxKMSGCPTimeout {
			l.errf("%s must be a duration from 1ms to %s, for example 5s", EnvKMSGCPTimeout, maxKMSGCPTimeout)
		} else {
			g.Timeout = d
		}
	}
	return g
}

func validHostPort(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return false
	}
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n >= 1
}
