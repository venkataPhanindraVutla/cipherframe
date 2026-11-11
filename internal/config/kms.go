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
	if k.Provider != ProviderLocal {
		return k
	}
	if prod {
		l.errf("%s=%s is development-only; not allowed in production", EnvKMSProvider, ProviderLocal)
	}
	k.LocalKEKs = l.localKEKs(prod)
	return k
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
