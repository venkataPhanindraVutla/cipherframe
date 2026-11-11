//go:build nokms_aws

package registry_test

import (
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/registry"
)

// A build without the AWS provider refuses to start when it is configured (ADR 0022).
func TestFromConfigAWSNotInThisBuild(t *testing.T) {
	cfg := load(t, map[string]string{
		config.EnvKMSProvider:  config.ProviderAWSKMS,
		config.EnvKMSAWSKeyID:  "alias/cipherframe",
		config.EnvKMSAWSRegion: "eu-west-1",
	})
	_, err := registry.FromConfig(cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "not available in this build") {
		t.Fatalf("want a not-available refusal, got %v", err)
	}
}
