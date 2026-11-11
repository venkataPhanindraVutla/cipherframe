package config

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Environment variable names of the Vault Transit provider (M2-2, ADR 0021).
const (
	EnvKMSVaultAddr         = "CIPHERFRAME_KMS_VAULT_ADDR"
	EnvKMSVaultToken        = "CIPHERFRAME_KMS_VAULT_TOKEN"
	EnvKMSVaultTransitMount = "CIPHERFRAME_KMS_VAULT_TRANSIT_MOUNT"
	EnvKMSVaultKeyName      = "CIPHERFRAME_KMS_VAULT_KEY_NAME"
	EnvKMSVaultNamespace    = "CIPHERFRAME_KMS_VAULT_NAMESPACE"
	EnvKMSVaultCAFile       = "CIPHERFRAME_KMS_VAULT_CA_FILE"
	EnvKMSVaultTimeout      = "CIPHERFRAME_KMS_VAULT_TIMEOUT"
)

// Defaults of the Vault Transit provider.
const (
	DefaultVaultTransitMount = "transit"
	DefaultVaultTimeout      = 5 * time.Second
	maxVaultTimeout          = 5 * time.Minute
)

var (
	vaultMountRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$`)
	vaultKeyRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

// KMSVault holds the Vault Transit provider settings (ADR 0021). It works with HashiCorp Vault and
// OpenBao. Every printed form hides the token; LogValue shows only the non-secret identifiers.
type KMSVault struct {
	// Addr is the server address, an absolute http(s) URL. Production requires https.
	Addr string
	// Token is the Vault token. It is never printed.
	Token Secret
	// TransitMount is the mount path of the Transit secrets engine.
	TransitMount string
	// KeyName is the Transit key that wraps content keys.
	KeyName string
	// Namespace is sent as X-Vault-Namespace when not empty.
	Namespace string
	// CAFile is an optional PEM file of CA certificates that replaces the system roots.
	CAFile string
	// Timeout bounds one request to the server.
	Timeout time.Duration
}

// LogValue implements slog.LogValuer. It shows address, mount, key name and namespace only.
func (v KMSVault) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("addr", v.Addr),
		slog.String("transit_mount", v.TransitMount),
		slog.String("key_name", v.KeyName),
		slog.String("namespace", v.Namespace),
	)
}

// String implements fmt.Stringer. The token is redacted.
func (v KMSVault) String() string {
	return fmt.Sprintf("vault{addr=%s mount=%s key=%s namespace=%s token=%s}",
		v.Addr, v.TransitMount, v.KeyName, v.Namespace, Redacted)
}

// GoString implements fmt.GoStringer.
func (v KMSVault) GoString() string { return v.String() }

// Format implements fmt.Formatter and covers every verb.
func (v KMSVault) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(v.String())) }

// MarshalJSON implements json.Marshaler.
func (v KMSVault) MarshalJSON() ([]byte, error) {
	return []byte(`"` + v.String() + `"`), nil
}

// kmsVault reads the Vault Transit settings. It runs only when CIPHERFRAME_KMS_PROVIDER names this provider.
func (l *loader) kmsVault(prod bool) KMSVault {
	v := KMSVault{
		TransitMount: l.plain(EnvKMSVaultTransitMount, DefaultVaultTransitMount),
		KeyName:      l.plain(EnvKMSVaultKeyName, ""),
		Namespace:    l.plain(EnvKMSVaultNamespace, ""),
		CAFile:       l.plain(EnvKMSVaultCAFile, ""),
		Timeout:      DefaultVaultTimeout,
	}

	v.Addr = l.plain(EnvKMSVaultAddr, "")
	switch u, err := url.Parse(v.Addr); {
	case v.Addr == "":
		l.errf("%s is required when %s is %s", EnvKMSVaultAddr, EnvKMSProvider, ProviderVault)
	case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
		l.errf("%s must be an absolute http or https URL", EnvKMSVaultAddr)
	case u.User != nil || u.RawQuery != "" || u.Fragment != "":
		l.errf("%s must not contain credentials, a query or a fragment", EnvKMSVaultAddr)
	case prod && u.Scheme != "https":
		l.errf("%s must use https in production", EnvKMSVaultAddr)
	}

	tok, ok := l.secret(EnvKMSVaultToken)
	switch {
	case !ok || tok == "":
		l.errf("%s is required when %s is %s", EnvKMSVaultToken, EnvKMSProvider, ProviderVault)
	case strings.ContainsAny(tok, "\r\n\x00") || strings.TrimSpace(tok) != tok:
		l.errf("%s must not contain whitespace or control characters", EnvKMSVaultToken)
	case prod && isPlaceholder(tok):
		l.errf("%s is a development placeholder; not allowed in production", EnvKMSVaultToken)
	}
	v.Token = NewSecret(tok)

	if !vaultMountRe.MatchString(v.TransitMount) {
		l.errf("%s must be a mount path without leading or trailing slash", EnvKMSVaultTransitMount)
	}
	switch {
	case v.KeyName == "":
		l.errf("%s is required when %s is %s", EnvKMSVaultKeyName, EnvKMSProvider, ProviderVault)
	case !vaultKeyRe.MatchString(v.KeyName):
		l.errf("%s may contain only letters, digits, '-', '_' and '.'", EnvKMSVaultKeyName)
	}
	if strings.ContainsFunc(v.Namespace, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		l.errf("%s must not contain control characters", EnvKMSVaultNamespace)
	}

	if v.CAFile != "" {
		b, err := l.read(v.CAFile)
		switch {
		case err != nil:
			l.errf("%s: cannot read the file", EnvKMSVaultCAFile)
		case !x509.NewCertPool().AppendCertsFromPEM(b):
			l.errf("%s: the file holds no PEM certificate", EnvKMSVaultCAFile)
		}
	}

	if raw := l.plain(EnvKMSVaultTimeout, ""); raw != "" {
		d, err := time.ParseDuration(raw)
		switch {
		case err != nil:
			l.errf("%s must be a Go duration such as 5s", EnvKMSVaultTimeout)
		case d <= 0 || d > maxVaultTimeout:
			l.errf("%s must be greater than zero and at most %s", EnvKMSVaultTimeout, maxVaultTimeout)
		default:
			v.Timeout = d
		}
	}
	return v
}
