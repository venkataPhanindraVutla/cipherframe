//go:build nokms_gcp

package registry_test

import (
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/registry"
)

func TestFromConfigGCPExcludedByTag(t *testing.T) {
	cfg := load(t, map[string]string{
		config.EnvKMSProvider:   config.ProviderGCPKMS,
		config.EnvKMSGCPKeyName: "projects/p/locations/global/keyRings/r/cryptoKeys/k",
	})
	_, err := registry.FromConfig(cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "not available in this build") {
		t.Fatalf("want a not-available refusal, got %v", err)
	}
}
