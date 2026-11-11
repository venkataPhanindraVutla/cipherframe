package registry

import (
	"log/slog"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/vault"
)

// The Vault Transit provider speaks plain HTTP and pulls in no SDK, so it has no exclusion build
// tag (ADR 0022).
func init() {
	register(config.ProviderVault, func(cfg *config.Config, log *slog.Logger) (kms.Provider, error) {
		return vault.New(cfg.KMS.Vault, log)
	})
}
