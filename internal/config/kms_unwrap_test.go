package config

import (
	"strings"
	"testing"
)

func TestKMSUnwrapProviders(t *testing.T) {
	e := vaultEnv().with(EnvKMSUnwrapProviders, "local")
	c, err := load(e, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.KMS.UnwrapProviders; len(got) != 1 || got[0] != ProviderLocal {
		t.Fatalf("unwrap providers = %v", got)
	}
	if c.KMS.LocalKEKs.Len() != 1 || c.KMS.Vault.KeyName != "cipherframe" {
		t.Fatal("both providers' settings must be loaded")
	}
}

func TestKMSUnwrapProvidersRules(t *testing.T) {
	tests := []struct {
		name string
		env  env
		want string
	}{
		{"current listed", vaultEnv().with(EnvKMSUnwrapProviders, "vault"), "current provider"},
		{"unknown", vaultEnv().with(EnvKMSUnwrapProviders, "nope"), "must list only"},
		{"duplicate", vaultEnv().with(EnvKMSUnwrapProviders, "local,local"), "more than once"},
		{"empty entry", vaultEnv().with(EnvKMSUnwrapProviders, "local,"), "empty entry"},
		{"unwrap provider validated", vaultEnv().with(EnvKMSUnwrapProviders, "local", EnvKMSLocalKEKs, "1:"+pepper('a', 31)), "exactly 32"},
		{"unwrap provider missing settings", base.with(EnvKMSUnwrapProviders, "vault"), EnvKMSVaultAddr},
		{"local refused in production", prod.with(
			EnvKMSProvider, ProviderVault,
			EnvKMSVaultAddr, "https://vault.example.com:8200",
			EnvKMSVaultToken, vaultTestToken,
			EnvKMSVaultKeyName, "cipherframe",
			EnvKMSUnwrapProviders, "local",
		), "development-only"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := load(tc.env, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want mention of %q", err, tc.want)
			}
		})
	}
}

func TestKMSUnwrapProvidersEmptyIsNone(t *testing.T) {
	c, err := load(base.with(EnvKMSUnwrapProviders, " "), nil)
	if err != nil || len(c.KMS.UnwrapProviders) != 0 {
		t.Fatalf("got %v, %v", c.KMS.UnwrapProviders, err)
	}
}
