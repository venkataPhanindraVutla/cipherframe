// Package registry builds the key-provider registry from configuration (ADR 0022). It is the only
// package that imports the provider packages, so a build can drop a provider by build tag without
// touching the rest of the core. Each M2-2 provider registers itself from its own file
// (registry_vault.go; registry_aws.go and registry_gcp.go behind the nokms_aws and nokms_gcp tags).
package registry

import (
	"fmt"
	"log/slog"
	"slices"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/local"
)

// FromConfig builds the registry for cfg: the configured provider wraps new keys and unwraps its
// own. It fails with a message that names the variable or the provider, never a value, when the
// provider is unknown, not built into this binary, or misconfigured, so the process can refuse to
// start instead of failing on the first key request.
func FromConfig(cfg *config.Config, log *slog.Logger) (*kms.Registry, error) {
	if cfg == nil {
		return nil, fmt.Errorf("kms: no configuration")
	}
	if !slices.Contains(config.KMSProviders(), cfg.KMS.Provider) {
		return nil, fmt.Errorf("kms: %s names an unknown provider", config.EnvKMSProvider)
	}
	build, ok := factories[cfg.KMS.Provider]
	if !ok {
		return nil, fmt.Errorf("kms: %s=%s is not available in this build", config.EnvKMSProvider, cfg.KMS.Provider)
	}
	p, err := build(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("kms: %s=%s: %w", config.EnvKMSProvider, cfg.KMS.Provider, err)
	}
	reg, err := kms.NewRegistry(p)
	if err != nil {
		return nil, fmt.Errorf("kms: %w", err)
	}
	return reg, nil
}

// factory builds one provider from configuration.
type factory func(cfg *config.Config, log *slog.Logger) (kms.Provider, error)

// factories maps provider names to constructors. local is always built in; each other provider
// registers itself from its own file, which a build tag can exclude (ADR 0022).
var factories = map[string]factory{
	config.ProviderLocal: func(cfg *config.Config, log *slog.Logger) (kms.Provider, error) {
		return local.New(cfg.Env, cfg.KMS.LocalKEKs, log)
	},
}

func register(name string, f factory) { factories[name] = f }
