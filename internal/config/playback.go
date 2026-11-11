package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Playback token variables (ADR 0028).
const (
	EnvPlaybackTokenKeys       = "CIPHERFRAME_PLAYBACK_TOKEN_KEYS"        //nolint:gosec // environment variable name, not a credential
	EnvPlaybackTokenKeyCurrent = "CIPHERFRAME_PLAYBACK_TOKEN_KEY_CURRENT" //nolint:gosec // environment variable name, not a credential
)

// MinPlaybackKeyBytes is the minimum decoded length of a playback-token signing key.
const MinPlaybackKeyBytes = 32

// PlaybackKeys is the versioned set of playback-token signing keys plus the current version,
// mirroring Peppers (ADR 0016, ADR 0028). The decoded key bytes are held as Secrets.
//
// The set is optional at load time, because the loader does not know the process roles: only the
// api and edge roles need it, and the server calls Require for them. A set that is present is
// always fully validated.
type PlaybackKeys struct {
	byVersion map[int]Secret
	current   int
}

// Configured reports whether any key was configured.
func (p PlaybackKeys) Configured() bool { return len(p.byVersion) > 0 }

// Require returns an error, naming the variables, when no keys are configured. Call it when the
// api or edge role runs.
func (p PlaybackKeys) Require() error {
	if !p.Configured() {
		return fmt.Errorf("%s and %s are required when the api or edge role runs",
			EnvPlaybackTokenKeys, EnvPlaybackTokenKeyCurrent)
	}
	return nil
}

// Get returns the key for version.
func (p PlaybackKeys) Get(version int) (Secret, bool) {
	s, ok := p.byVersion[version]
	return s, ok
}

// Current returns the current version and its key.
func (p PlaybackKeys) Current() (int, Secret) { return p.current, p.byVersion[p.current] }

// Versions returns all configured versions in ascending order.
func (p PlaybackKeys) Versions() []int {
	v := make([]int, 0, len(p.byVersion))
	for k := range p.byVersion {
		v = append(v, k)
	}
	slices.Sort(v)
	return v
}

// Len returns the number of configured keys.
func (p PlaybackKeys) Len() int { return len(p.byVersion) }

// String shows versions only, never key values.
func (p PlaybackKeys) String() string {
	return fmt.Sprintf("playback-keys(versions=%v current=%d values=%s)", p.Versions(), p.current, Redacted)
}

// GoString implements fmt.GoStringer.
func (p PlaybackKeys) GoString() string { return p.String() }

// Format implements fmt.Formatter, for the same reason as Peppers.Format.
func (p PlaybackKeys) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(p.String())) }

func versionList(vs []int) string {
	s := make([]string, len(vs))
	for i, v := range vs {
		s[i] = strconv.Itoa(v)
	}
	return strings.Join(s, ",")
}

// KeyMaterial returns the decoded keys by version, for building a token keyring. The bytes are
// copies the caller may keep.
func (p PlaybackKeys) KeyMaterial() map[int][]byte {
	out := make(map[int][]byte, len(p.byVersion))
	for v, s := range p.byVersion {
		out[v] = []byte(s.Reveal())
	}
	return out
}

// parsePlaybackKeys parses "kid:base64,kid:base64". The key ID is a positive integer, as for
// peppers, and each decoded key must be at least MinPlaybackKeyBytes long. Errors name the
// variable and entry position, never the value.
func parsePlaybackKeys(raw string) (map[int]Secret, []error) {
	var errs []error
	out := map[int]Secret{}
	for i, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		pos := i + 1
		ver, enc, ok := strings.Cut(entry, ":")
		if !ok {
			errs = append(errs, fmt.Errorf("%s: entry %d must be kid:base64", EnvPlaybackTokenKeys, pos))
			continue
		}
		n, ok := parseVersion(ver)
		if !ok {
			errs = append(errs, fmt.Errorf("%s: entry %d has an invalid key ID (want a positive integer)", EnvPlaybackTokenKeys, pos))
			continue
		}
		dec, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: key %d is not valid standard base64", EnvPlaybackTokenKeys, n))
			continue
		}
		if len(dec) < MinPlaybackKeyBytes {
			errs = append(errs, fmt.Errorf("%s: key %d is shorter than %d bytes", EnvPlaybackTokenKeys, n, MinPlaybackKeyBytes))
			continue
		}
		if _, dup := out[n]; dup {
			errs = append(errs, fmt.Errorf("%s: key %d appears more than once", EnvPlaybackTokenKeys, n))
			continue
		}
		out[n] = NewSecret(string(dec))
	}
	if len(errs) == 0 && len(out) == 0 {
		errs = append(errs, errors.New(EnvPlaybackTokenKeys+": no keys configured"))
	}
	return out, errs
}

func (l *loader) playbackKeys(prod bool) PlaybackKeys {
	var p PlaybackKeys
	raw, hasKeys := l.secret(EnvPlaybackTokenKeys)
	cur := l.plain(EnvPlaybackTokenKeyCurrent, "")
	if !hasKeys && cur == "" {
		return p // not configured; the api and edge roles refuse to start without it
	}
	switch {
	case !hasKeys || raw == "":
		l.errf("%s is required when %s is set", EnvPlaybackTokenKeys, EnvPlaybackTokenKeyCurrent)
	default:
		m, errs := parsePlaybackKeys(raw)
		l.errs = append(l.errs, errs...)
		p.byVersion = m
		if prod {
			for _, v := range p.Versions() {
				if isPlaceholder(m[v].Reveal()) {
					l.errf("%s: key %d is a development placeholder; not allowed in production", EnvPlaybackTokenKeys, v)
				}
			}
		}
	}

	n, valid := parseVersion(cur)
	switch {
	case cur == "":
		l.errf("%s is required when %s is set", EnvPlaybackTokenKeyCurrent, EnvPlaybackTokenKeys)
	case !valid:
		l.errf("%s must be a positive integer", EnvPlaybackTokenKeyCurrent)
	case len(p.byVersion) > 0:
		if _, found := p.byVersion[n]; !found {
			l.errf("%s names key %d, which is not in %s", EnvPlaybackTokenKeyCurrent, n, EnvPlaybackTokenKeys)
		}
	}
	if valid {
		p.current = n
	}
	return p
}
