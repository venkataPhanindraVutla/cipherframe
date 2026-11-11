package registry_test

import (
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/registry"
)

func TestFromConfigVault(t *testing.T) {
	const token = "hvs.registry-token-distinct" //nolint:gosec // test fixture
	cfg := load(t, map[string]string{
		config.EnvKMSProvider:     config.ProviderVault,
		config.EnvKMSVaultAddr:    "http://127.0.0.1:1",
		config.EnvKMSVaultToken:   token,
		config.EnvKMSVaultKeyName: "cipherframe",
	})
	reg, err := registry.FromConfig(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reg.Current().Name() != "vault" {
		t.Fatalf("current provider = %s, want vault", reg.Current().Name())
	}
	if _, err := reg.Lookup("vault"); err != nil {
		t.Fatal(err)
	}
}

func TestFromConfigVaultRequiresSettings(t *testing.T) {
	cfg := load(t, map[string]string{
		config.EnvKMSProvider:     config.ProviderVault,
		config.EnvKMSVaultAddr:    "http://127.0.0.1:1",
		config.EnvKMSVaultToken:   "t",
		config.EnvKMSVaultKeyName: "k",
	})
	cfg.KMS.Vault.KeyName = "" // as if the loader had been bypassed
	_, err := registry.FromConfig(cfg, nil)
	if err == nil || !strings.Contains(err.Error(), config.EnvKMSProvider) {
		t.Fatalf("want a refusal naming the variable, got %v", err)
	}
}
