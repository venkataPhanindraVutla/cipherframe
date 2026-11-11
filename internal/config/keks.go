package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// KEKBytes is the exact decoded length of a local-provider KEK (AES-256, ADR 0020).
const KEKBytes = 32

// KMS provider names (ADR 0019, ADR 0022). Only the names are reserved here; the provider
// registry decides which ones a build can construct.
const (
	ProviderLocal  = "local"
	ProviderVault  = "vault"
	ProviderAWSKMS = "awskms"
	ProviderGCPKMS = "gcpkms"
)

// KMSProviders lists every reserved provider name.
func KMSProviders() []string {
	return []string{ProviderLocal, ProviderVault, ProviderAWSKMS, ProviderGCPKMS}
}

// KMS is the key-management configuration.
type KMS struct {
	// Provider is the provider that wraps new content keys.
	Provider string
	// UnwrapProviders are providers, other than Provider, that may only unwrap keys they made
	// earlier, so content keys can be moved between providers (M2-4). Their settings are loaded
	// into the fields below like the current provider's.
	UnwrapProviders []string
	// LocalKEKs is the local provider's key set. It is empty unless Provider or UnwrapProviders names "local".
	LocalKEKs KEKs
	// Vault, AWS and GCP hold provider-specific settings. Each is filled only when Provider or
	// UnwrapProviders names that provider; each lives in its own file (kms_vault.go, kms_aws.go, kms_gcp.go).
	Vault KMSVault
	AWS   KMSAWS
	GCP   KMSGCP
}

// KEKs is the versioned set of local-provider key-encryption keys plus the current version,
// mirroring Peppers (ADR 0016). The decoded KEK bytes are held as Secrets.
type KEKs struct {
	byVersion map[int]Secret
	current   int
}

// Get returns the KEK for version.
func (k KEKs) Get(version int) (Secret, bool) {
	s, ok := k.byVersion[version]
	return s, ok
}

// Current returns the current version and its KEK.
func (k KEKs) Current() (int, Secret) { return k.current, k.byVersion[k.current] }

// Versions returns all configured versions in ascending order.
func (k KEKs) Versions() []int {
	v := make([]int, 0, len(k.byVersion))
	for n := range k.byVersion {
		v = append(v, n)
	}
	slices.Sort(v)
	return v
}

// Len returns the number of configured KEKs.
func (k KEKs) Len() int { return len(k.byVersion) }

// String shows versions only, never KEK values.
func (k KEKs) String() string {
	return fmt.Sprintf("keks(versions=%v current=%d values=%s)", k.Versions(), k.current, Redacted)
}

// GoString implements fmt.GoStringer.
func (k KEKs) GoString() string { return k.String() }

// Format implements fmt.Formatter, for the same reason as Peppers.Format.
func (k KEKs) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(k.String())) }

// parseKEKs parses "version:base64,version:base64". Every decoded KEK must be exactly KEKBytes
// long. Errors name the variable and entry position, never the value.
func parseKEKs(raw string) (map[int]Secret, []error) {
	var errs []error
	out := map[int]Secret{}
	for i, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		pos := i + 1
		ver, enc, ok := strings.Cut(entry, ":")
		if !ok {
			errs = append(errs, fmt.Errorf("%s: entry %d must be version:base64", EnvKMSLocalKEKs, pos))
			continue
		}
		n, ok := parseVersion(ver)
		if !ok {
			errs = append(errs, fmt.Errorf("%s: entry %d has an invalid version (want a positive integer)", EnvKMSLocalKEKs, pos))
			continue
		}
		dec, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: version %d is not valid standard base64", EnvKMSLocalKEKs, n))
			continue
		}
		if len(dec) != KEKBytes {
			errs = append(errs, fmt.Errorf("%s: version %d must decode to exactly %d bytes", EnvKMSLocalKEKs, n, KEKBytes))
			continue
		}
		if _, dup := out[n]; dup {
			errs = append(errs, fmt.Errorf("%s: version %d appears more than once", EnvKMSLocalKEKs, n))
			continue
		}
		out[n] = NewSecret(string(dec))
	}
	if len(errs) == 0 && len(out) == 0 {
		errs = append(errs, errors.New(EnvKMSLocalKEKs+": no KEKs configured"))
	}
	return out, errs
}
