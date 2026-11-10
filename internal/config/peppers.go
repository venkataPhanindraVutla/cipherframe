package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// MinPepperBytes is the minimum decoded length of an API-key pepper.
const MinPepperBytes = 32

// Peppers is the versioned set of API-key peppers plus the current version
// (ADR 0016). The decoded pepper bytes are held as Secrets.
type Peppers struct {
	byVersion map[int]Secret
	current   int
}

// Get returns the pepper for version.
func (p Peppers) Get(version int) (Secret, bool) {
	s, ok := p.byVersion[version]
	return s, ok
}

// Current returns the current version and its pepper.
func (p Peppers) Current() (int, Secret) { return p.current, p.byVersion[p.current] }

// Versions returns all configured versions in ascending order.
func (p Peppers) Versions() []int {
	v := make([]int, 0, len(p.byVersion))
	for k := range p.byVersion {
		v = append(v, k)
	}
	slices.Sort(v)
	return v
}

// Len returns the number of configured peppers.
func (p Peppers) Len() int { return len(p.byVersion) }

// String shows versions only, never pepper values.
func (p Peppers) String() string {
	return fmt.Sprintf("peppers(versions=%v current=%d values=%s)", p.Versions(), p.current, Redacted)
}

// GoString implements fmt.GoStringer.
func (p Peppers) GoString() string { return p.String() }

// Format implements fmt.Formatter. The fields are unexported, so fmt could not
// otherwise call Secret's own formatter on them.
func (p Peppers) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(p.String())) }

// parseVersion parses a positive decimal integer (digits only).
func parseVersion(s string) (int, bool) {
	if s == "" || len(s) > 9 {
		return 0, false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}

// parsePeppers parses "version:base64,version:base64" and validates it. The
// returned errors name the variable and entry position, never the value.
func parsePeppers(raw string) (map[int]Secret, []error) {
	var errs []error
	out := map[int]Secret{}
	for i, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		pos := i + 1
		ver, enc, ok := strings.Cut(entry, ":")
		if !ok {
			errs = append(errs, fmt.Errorf("%s: entry %d must be version:base64", EnvAPIKeyPeppers, pos))
			continue
		}
		n, ok := parseVersion(ver)
		if !ok {
			errs = append(errs, fmt.Errorf("%s: entry %d has an invalid version (want a positive integer)", EnvAPIKeyPeppers, pos))
			continue
		}
		dec, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: version %d is not valid standard base64", EnvAPIKeyPeppers, n))
			continue
		}
		if len(dec) < MinPepperBytes {
			errs = append(errs, fmt.Errorf("%s: version %d is shorter than %d bytes", EnvAPIKeyPeppers, n, MinPepperBytes))
			continue
		}
		if _, dup := out[n]; dup {
			errs = append(errs, fmt.Errorf("%s: version %d appears more than once", EnvAPIKeyPeppers, n))
			continue
		}
		out[n] = NewSecret(string(dec))
	}
	if len(errs) == 0 && len(out) == 0 {
		errs = append(errs, errors.New(EnvAPIKeyPeppers+": no peppers configured"))
	}
	return out, errs
}
