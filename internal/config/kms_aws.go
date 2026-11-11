package config

import (
	"regexp"
	"strings"
	"time"
)

// Environment variable names of the AWS KMS provider (M2-2).
const (
	EnvKMSAWSKeyID           = "CIPHERFRAME_KMS_AWS_KEY_ID"
	EnvKMSAWSRegion          = "CIPHERFRAME_KMS_AWS_REGION"
	EnvKMSAWSEndpoint        = "CIPHERFRAME_KMS_AWS_ENDPOINT"
	EnvKMSAWSAccessKeyID     = "CIPHERFRAME_KMS_AWS_ACCESS_KEY_ID"
	EnvKMSAWSSecretAccessKey = "CIPHERFRAME_KMS_AWS_SECRET_ACCESS_KEY" //nolint:gosec // environment variable name, not a credential
	EnvKMSAWSTimeout         = "CIPHERFRAME_KMS_AWS_TIMEOUT"
)

const (
	defaultKMSAWSTimeout = 5 * time.Second
	maxKMSAWSTimeout     = 5 * time.Minute
)

// KMSAWS holds the AWS KMS provider settings. The credentials are three-state Credentials with the
// same meaning as the S3 ones and are redacted in every printed form.
type KMSAWS struct {
	// KeyID names the KEK: a key ARN, an alias ARN or "alias/name".
	KeyID string
	// Region is the AWS region of the key.
	Region string
	// Endpoint is empty for the AWS default. Set it for a VPC endpoint or a KMS-compatible server.
	Endpoint string
	// AccessKeyID and SecretAccessKey are in the same state, as for S3.
	AccessKeyID     Credential
	SecretAccessKey Credential
	// Timeout bounds every KMS call, including the SDK's own retries.
	Timeout time.Duration
}

var awsRegionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)

// validKMSAWSKeyID accepts a key ARN, an alias ARN or "alias/name". A bare key id is refused so the
// stored reference is always unambiguous.
func validKMSAWSKeyID(s string) bool {
	if strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	if rest, ok := strings.CutPrefix(s, "alias/"); ok {
		return rest != ""
	}
	parts := strings.Split(s, ":")
	if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[2] != "kms" || parts[3] == "" || parts[4] == "" {
		return false
	}
	for _, p := range []string{"key/", "alias/"} {
		if rest, ok := strings.CutPrefix(parts[5], p); ok && rest != "" {
			return true
		}
	}
	return false
}

// kmsAWS reads the AWS KMS settings. It runs only when CIPHERFRAME_KMS_PROVIDER names this provider.
// The credential rules are those of S3: in production both must be set (an empty value means the
// SDK default credential chain) and must be in the same state; placeholders are refused.
func (l *loader) kmsAWS(prod bool) KMSAWS {
	a := KMSAWS{Timeout: defaultKMSAWSTimeout}

	a.KeyID = l.plain(EnvKMSAWSKeyID, "")
	switch {
	case a.KeyID == "":
		l.errf("%s is required when %s is %s", EnvKMSAWSKeyID, EnvKMSProvider, ProviderAWSKMS)
	case !validKMSAWSKeyID(a.KeyID):
		l.errf("%s must be a KMS key ARN, an alias ARN or alias/<name>", EnvKMSAWSKeyID)
	}

	a.Region = l.plain(EnvKMSAWSRegion, "")
	switch {
	case a.Region == "":
		l.errf("%s is required when %s is %s", EnvKMSAWSRegion, EnvKMSProvider, ProviderAWSKMS)
	case !awsRegionPattern.MatchString(a.Region):
		l.errf("%s is not a valid AWS region", EnvKMSAWSRegion)
	}

	a.Endpoint = l.endpoint(EnvKMSAWSEndpoint)

	a.AccessKeyID = l.credential(EnvKMSAWSAccessKeyID, prod)
	a.SecretAccessKey = l.credential(EnvKMSAWSSecretAccessKey, prod)
	if a.AccessKeyID.State() != a.SecretAccessKey.State() {
		l.errf("%s and %s must be in the same state (both unset, both empty, or both set)",
			EnvKMSAWSAccessKeyID, EnvKMSAWSSecretAccessKey)
	}

	if v := l.plain(EnvKMSAWSTimeout, ""); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 || d > maxKMSAWSTimeout {
			l.errf("%s must be a duration such as 5s, greater than zero and at most 5m", EnvKMSAWSTimeout)
		} else {
			a.Timeout = d
		}
	}
	return a
}
