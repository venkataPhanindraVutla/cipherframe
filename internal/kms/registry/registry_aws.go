//go:build !nokms_aws

package registry

import (
	"context"
	"log/slog"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/awskms"
)

// The AWS KMS provider is built in unless the nokms_aws tag drops it (ADR 0022).
func init() {
	register(config.ProviderAWSKMS, func(cfg *config.Config, log *slog.Logger) (kms.Provider, error) {
		return awskms.New(context.Background(), cfg.KMS.AWS, log)
	})
}
