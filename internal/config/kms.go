package config

import (
	"slices"
	"strconv"
	"strings"
)

// kms reads the key-management settings (ADR 0019). The default provider is local in development;
// production requires an explicit provider and refuses local.
func (l *loader) kms(prod bool) KMS {
	var k KMS
	k.Provider = l.plain(EnvKMSProvider, "")
	switch {
	case k.Provider == "" && prod:
		l.errf("%s is required in production", EnvKMSProvider)
		return k
	case k.Provider == "":
		k.Provider = ProviderLocal
	case !slices.Contains(KMSProviders(), k.Provider):
		l.errf("%s must be one of %s", EnvKMSProvider, strings.Join(KMSProviders(), ", "))
		return k
	}
	l.kmsProvider(&k, k.Provider, prod)
	k.UnwrapProviders = l.unwrapProviders(k.Provider)
	for _, name := range k.UnwrapProviders {
		l.kmsProvider(&k, name, prod)
	}
	return k
}

// unwrapProviders reads the providers that may only unwrap keys they made earlier (M2-4). Each is
// loaded and validated exactly like the current provider; it must be a known name, listed once, and
// not the current provider.
func (l *loader) unwrapProviders(current string) []string {
	raw := l.plain(EnvKMSUnwrapProviders, "")
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	for _, name := range strings.Split(raw, ",") {
		name = strings.TrimSpace(name)
		switch {
		case name == "":
			l.errf("%s must not contain an empty entry", EnvKMSUnwrapProviders)
		case !slices.Contains(KMSProviders(), name):
			l.errf("%s must list only %s", EnvKMSUnwrapProviders, strings.Join(KMSProviders(), ", "))
		case name == current:
			l.errf("%s must not list the current provider %s", EnvKMSUnwrapProviders, name)
		case slices.Contains(out, name):
			l.errf("%s lists %s more than once", EnvKMSUnwrapProviders, name)
		default:
			out = append(out, name)
		}
	}
	return out
}

// kmsProvider loads and validates the settings of one provider into k.
func (l *loader) kmsProvider(k *KMS, name string, prod bool) {
	switch name {
	case ProviderVault:
		k.Vault = l.kmsVault(prod)
	case ProviderAWSKMS:
		k.AWS = l.kmsAWS(prod)
	case ProviderGCPKMS:
		k.GCP = l.kmsGCP(prod)
	default:
		if prod {
			l.errf("%s=%s is development-only; not allowed in production", kmsVarFor(k, name), ProviderLocal)
		}
		k.LocalKEKs = l.localKEKs(prod)
	}
}

// kmsVarFor names the variable that selected the local provider, for the production refusal.
func kmsVarFor(k *KMS, name string) string {
	if name == k.Provider {
		return EnvKMSProvider
	}
	return EnvKMSUnwrapProviders
}

func (l *loader) localKEKs(prod bool) KEKs {
	var k KEKs
	raw, ok := l.secret(EnvKMSLocalKEKs)
	switch {
	case !ok || raw == "":
		l.errf("%s is required when %s is %s", EnvKMSLocalKEKs, EnvKMSProvider, ProviderLocal)
	default:
		m, errs := parseKEKs(raw)
		l.errs = append(l.errs, errs...)
		k.byVersion = m
		if prod {
			for _, v := range k.Versions() {
				if isPlaceholder(m[v].Reveal()) {
					l.errf("%s: version %d is a development placeholder; not allowed in production", EnvKMSLocalKEKs, v)
				}
			}
		}
	}

	cur := l.plain(EnvKMSLocalKEKCurrent, "")
	n, valid := parseVersion(cur)
	switch {
	case cur == "":
		l.errf("%s is required when %s is %s", EnvKMSLocalKEKCurrent, EnvKMSProvider, ProviderLocal)
	case !valid:
		l.errf("%s must be a positive integer", EnvKMSLocalKEKCurrent)
	case len(k.byVersion) > 0:
		if _, found := k.byVersion[n]; !found {
			l.errf("%s names version %d, which is not in %s", EnvKMSLocalKEKCurrent, n, EnvKMSLocalKEKs)
		}
	}
	if valid {
		k.current = n
	}
	return k
}

func kekVersions(k KEKs) string {
	vs := k.Versions()
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = strconv.Itoa(v)
	}
	return strings.Join(out, ",")
}
