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
// own, and every provider in KMS.UnwrapProviders is registered for unwrap only (the registry's
// current provider is the only one that wraps). It fails with a message that names the variable or
// the provider, never a value, when a provider is unknown, not built into this binary, or
// misconfigured, so the process can refuse to start instead of failing on the first key request.
func FromConfig(cfg *config.Config, log *slog.Logger) (*kms.Registry, error) {
	if cfg == nil {
		return nil, fmt.Errorf("kms: no configuration")
	}
	p, err := build(cfg, cfg.KMS.Provider, config.EnvKMSProvider, log)
	if err != nil {
		return nil, err
	}
	var others []kms.Provider
	for _, name := range cfg.KMS.UnwrapProviders {
		o, err := build(cfg, name, config.EnvKMSUnwrapProviders, log)
		if err != nil {
			return nil, err
		}
		others = append(others, o)
	}
	reg, err := kms.NewRegistry(p, others...)
	if err != nil {
		return nil, fmt.Errorf("kms: %w", err)
	}
	return reg, nil
}

// build constructs the provider called name; envName is the variable that named it, for messages.
func build(cfg *config.Config, name, envName string, log *slog.Logger) (kms.Provider, error) {
	if !slices.Contains(config.KMSProviders(), name) {
		return nil, fmt.Errorf("kms: %s names an unknown provider", envName)
	}
	f, ok := factories[name]
	if !ok {
		return nil, fmt.Errorf("kms: %s=%s is not available in this build", envName, name)
	}
	p, err := f(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("kms: %s=%s: %w", envName, name, err)
	}
	return p, nil
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

// register is called from provider files that a build tag can exclude; keep the symbol referenced
// so a build without any of them still compiles cleanly.
var _ = register
