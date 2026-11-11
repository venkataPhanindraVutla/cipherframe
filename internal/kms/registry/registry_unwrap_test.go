package registry_test

import (
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/registry"
)

func TestFromConfigUnwrapProviders(t *testing.T) {
	cfg := load(t, map[string]string{
		config.EnvKMSProvider:        config.ProviderVault,
		config.EnvKMSVaultAddr:       "http://127.0.0.1:1",
		config.EnvKMSVaultToken:      "t",
		config.EnvKMSVaultKeyName:    "k",
		config.EnvKMSUnwrapProviders: config.ProviderLocal,
	})
	reg, err := registry.FromConfig(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reg.Current().Name() != "vault" {
		t.Fatalf("current provider = %s, want vault", reg.Current().Name())
	}
	if got := reg.Names(); len(got) != 2 || got[0] != "local" || got[1] != "vault" {
		t.Fatalf("names = %v, want [local vault]", got)
	}

	cfg.KMS.LocalKEKs = config.KEKs{} // as if the loader had been bypassed
	if _, err := registry.FromConfig(cfg, nil); err == nil || !strings.Contains(err.Error(), config.EnvKMSUnwrapProviders) {
		t.Fatalf("want a refusal naming %s, got %v", config.EnvKMSUnwrapProviders, err)
	}
}
