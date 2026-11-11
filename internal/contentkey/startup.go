package contentkey

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
)

// KEKCounter reports how many content keys each KEK version wraps. *db.Repos implements it.
type KEKCounter interface {
	CountContentKeysByKEK(ctx context.Context) ([]db.KEKUsage, error)
}

// CheckKEKs fails when a stored content key needs a provider that is not configured or, for a
// provider whose versions are known locally (the local provider), a KEK version it no longer holds
// (ADR 0020). It mirrors auth.CheckPeppers: the process refuses to start, so a missing KEK shows
// at deploy time and not as a failed key request. Providers whose versions live in a remote
// service are checked for presence only. The error names providers and versions, never key data.
func CheckKEKs(ctx context.Context, c KEKCounter, reg *kms.Registry) error {
	usage, err := c.CountContentKeysByKEK(ctx)
	if err != nil {
		return fmt.Errorf("count content keys by KEK: %w", err)
	}
	var missing, versions []string
	for _, u := range usage {
		p, err := reg.Lookup(u.KEK.Provider)
		if err != nil {
			if !slices.Contains(missing, u.KEK.Provider) {
				missing = append(missing, u.KEK.Provider)
			}
			continue
		}
		if chk, ok := p.(kms.KEKChecker); ok && !chk.HasKEK(kms.KeyRef{KeyID: u.KEK.KeyID, Version: u.KEK.Version}) {
			versions = append(versions, fmt.Sprintf("%s version %s", u.KEK.Provider, u.KEK.Version))
		}
	}
	var problems []string
	if len(missing) > 0 {
		problems = append(problems, fmt.Sprintf("content keys are wrapped by provider(s) %s, which are not configured "+
			"(add them to %s)", strings.Join(missing, ", "), config.EnvKMSUnwrapProviders))
	}
	if len(versions) > 0 {
		problems = append(problems, fmt.Sprintf("content keys are wrapped by KEK %s, which are not configured",
			strings.Join(versions, ", ")))
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}
