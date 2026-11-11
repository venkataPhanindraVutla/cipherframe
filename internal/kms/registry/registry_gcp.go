//go:build !nokms_gcp

package registry

import (
	"context"
	"log/slog"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/gcpkms"
)

// The GCP Cloud KMS provider is built in unless the nokms_gcp tag excludes it (ADR 0022).
func init() {
	register(config.ProviderGCPKMS, func(cfg *config.Config, _ *slog.Logger) (kms.Provider, error) {
		p, err := gcpkms.New(context.Background(), cfg.KMS.GCP)
		if err != nil {
			return nil, err
		}
		return p, nil
	})
}
