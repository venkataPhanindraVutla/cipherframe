//go:build !nokms_gcp

package registry_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/registry"
)

const gcpKey = "projects/p/locations/global/keyRings/r/cryptoKeys/k"

func TestFromConfigGCP(t *testing.T) {
	// A service-account-shaped file; nothing contacts Google when the provider is built.
	path := filepath.Join(t.TempDir(), "creds.json")
	if err := os.WriteFile(path, []byte(`{"type":"authorized_user","client_id":"x","client_secret":"y","refresh_token":"z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := load(t, map[string]string{
		config.EnvKMSProvider:           config.ProviderGCPKMS,
		config.EnvKMSGCPKeyName:         gcpKey,
		config.EnvKMSGCPCredentialsFile: path,
		config.EnvKMSGCPEndpoint:        "localhost:1",
	})
	reg, err := registry.FromConfig(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reg.Current().Name() != "gcpkms" {
		t.Fatalf("current = %s", reg.Current().Name())
	}
}

func TestFromConfigGCPBadCredentialsFile(t *testing.T) {
	cfg := load(t, map[string]string{
		config.EnvKMSProvider:           config.ProviderGCPKMS,
		config.EnvKMSGCPKeyName:         gcpKey,
		config.EnvKMSGCPCredentialsFile: filepath.Join(t.TempDir(), "missing.json"),
	})
	_, err := registry.FromConfig(cfg, nil)
	if err == nil || !strings.Contains(err.Error(), config.EnvKMSProvider) {
		t.Fatalf("want a refusal naming the variable, got %v", err)
	}
}
