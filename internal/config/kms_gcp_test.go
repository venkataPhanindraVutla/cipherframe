package config

import (
	"strings"
	"testing"
	"time"
)

const gcpKey = "projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k"

func TestKMSGCPDefaults(t *testing.T) {
	c, err := load(prod.with(EnvKMSProvider, ProviderGCPKMS, EnvKMSGCPKeyName, gcpKey), nil)
	if err != nil {
		t.Fatal(err)
	}
	g := c.KMS.GCP
	if g.KeyName != gcpKey || g.CredentialsFile != "" || g.Endpoint != "" || g.Timeout != 5*time.Second {
		t.Fatalf("unexpected settings: %+v", g)
	}
}

func TestKMSGCPAllSettings(t *testing.T) {
	c, err := load(base.with(EnvKMSProvider, ProviderGCPKMS, EnvKMSGCPKeyName, gcpKey,
		EnvKMSGCPCredentialsFile, "/run/secrets/gcp.json", EnvKMSGCPEndpoint, "kms.internal:443",
		EnvKMSGCPTimeout, "750ms"), nil)
	if err != nil {
		t.Fatal(err)
	}
	g := c.KMS.GCP
	if g.CredentialsFile != "/run/secrets/gcp.json" || g.Endpoint != "kms.internal:443" || g.Timeout != 750*time.Millisecond {
		t.Fatalf("unexpected settings: %+v", g)
	}
}

func TestKMSGCPRules(t *testing.T) {
	with := func(kv ...string) env {
		return base.with(append([]string{EnvKMSProvider, ProviderGCPKMS, EnvKMSGCPKeyName, gcpKey}, kv...)...)
	}
	tests := []struct {
		name string
		env  env
		want string
	}{
		{"key name required", base.with(EnvKMSProvider, ProviderGCPKMS), EnvKMSGCPKeyName},
		{"key version refused", with(EnvKMSGCPKeyName, gcpKey+"/cryptoKeyVersions/1"), EnvKMSGCPKeyName},
		{"key ring only", with(EnvKMSGCPKeyName, "projects/p/locations/l/keyRings/r"), EnvKMSGCPKeyName},
		{"garbage key name", with(EnvKMSGCPKeyName, "my-key"), EnvKMSGCPKeyName},
		{"endpoint without port", with(EnvKMSGCPEndpoint, "kms.internal"), EnvKMSGCPEndpoint},
		{"endpoint with scheme", with(EnvKMSGCPEndpoint, "https://kms.internal:443"), EnvKMSGCPEndpoint},
		{"timeout not a duration", with(EnvKMSGCPTimeout, "5"), EnvKMSGCPTimeout},
		{"timeout zero", with(EnvKMSGCPTimeout, "0s"), EnvKMSGCPTimeout},
		{"timeout negative", with(EnvKMSGCPTimeout, "-1s"), EnvKMSGCPTimeout},
		{"timeout too long", with(EnvKMSGCPTimeout, "1h"), EnvKMSGCPTimeout},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := load(tc.env, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want mention of %q", err, tc.want)
			}
		})
	}
}

func TestKMSGCPSettingsIgnoredForOtherProviders(t *testing.T) {
	if _, err := load(base.with(EnvKMSGCPKeyName, "not-a-key"), nil); err != nil {
		t.Fatalf("GCP settings must be ignored unless the provider is gcpkms: %v", err)
	}
}
