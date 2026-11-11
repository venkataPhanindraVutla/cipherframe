// Package registry builds the key-provider registry from configuration (ADR 0022). It is the only
// package that imports the provider packages, so a build can drop a provider by build tag without
// touching the rest of the core. M2-2 adds the vault, awskms and gcpkms constructors here.
package registry

import (
	"fmt"
	"log/slog"

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
	var p kms.Provider
	switch cfg.KMS.Provider {
	case config.ProviderLocal:
		lp, err := local.New(cfg.Env, cfg.KMS.LocalKEKs, log)
		if err != nil {
			return nil, fmt.Errorf("kms: %s=%s: %w", config.EnvKMSProvider, config.ProviderLocal, err)
		}
		p = lp
	case config.ProviderVault, config.ProviderAWSKMS, config.ProviderGCPKMS:
		return nil, fmt.Errorf("kms: %s=%s is reserved but not available in this build",
			config.EnvKMSProvider, cfg.KMS.Provider)
	default:
		return nil, fmt.Errorf("kms: %s names an unknown provider", config.EnvKMSProvider)
	}
	reg, err := kms.NewRegistry(p)
	if err != nil {
		return nil, fmt.Errorf("kms: %w", err)
	}
	return reg, nil
}
