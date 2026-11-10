package auth

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// PepperCounter reports how many active keys reference each pepper version. *db.Repos implements
// it.
type PepperCounter interface {
	CountAPIKeysByPepperVersion(ctx context.Context, now time.Time) (map[int]int64, error)
}

// CheckPeppers fails when an active key references a pepper version that is not configured
// (ADR 0016). The error names version numbers only, never pepper values or key data.
func CheckPeppers(ctx context.Context, c PepperCounter, p Peppers, now time.Time) error {
	usage, err := c.CountAPIKeysByPepperVersion(ctx, now)
	if err != nil {
		return fmt.Errorf("count keys by pepper version: %w", err)
	}
	var missing []string
	for _, v := range sortedVersions(usage) {
		if _, ok := p.Get(v); !ok {
			missing = append(missing, strconv.Itoa(v))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("active API keys reference pepper version(s) %s, which are not configured", strings.Join(missing, ", "))
	}
	return nil
}

func sortedVersions(m map[int]int64) []int {
	out := make([]int, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}

// PepperUsageLines formats usage as one "version N: COUNT" line per version, ascending, plus the
// versions in the configured set that no active key uses. It is the output of
// `cipherframe-server admin pepper-usage`.
func PepperUsageLines(usage map[int]int64, configured []int, current int) []string {
	versions := map[int]int64{}
	for _, v := range configured {
		versions[v] = 0
	}
	for v, n := range usage {
		versions[v] = n
	}
	var lines []string
	for _, v := range sortedVersions(versions) {
		line := fmt.Sprintf("version %d: %d active keys", v, versions[v])
		if v == current {
			line += " (current)"
		}
		if !slices.Contains(configured, v) {
			line += " (NOT CONFIGURED)"
		}
		lines = append(lines, line)
	}
	return lines
}
