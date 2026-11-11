package registry_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/registry"
)

func load(t *testing.T, extra map[string]string) *config.Config {
	t.Helper()
	env := map[string]string{ //nolint:gosec // test fixture
		config.EnvDatabaseURL:         "postgres://app:pw@db:5432/cf",
		config.EnvS3SourceBucket:      "cf-source",
		config.EnvS3DeliveryBucket:    "cf-delivery",
		config.EnvAPIKeyPeppers:       "1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'p'}, 32)),
		config.EnvAPIKeyPepperCurrent: "1",
		config.EnvKMSLocalKEKs:        "1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'k'}, 32)),
		config.EnvKMSLocalKEKCurrent:  "1",
	}
	for k, v := range extra {
		env[k] = v
	}
	cfg, err := config.Load(
		func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		func(string) ([]byte, error) { return nil, errors.New("no files") },
	)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestFromConfigLocal(t *testing.T) {
	reg, err := registry.FromConfig(load(t, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if reg.Current().Name() != "local" || len(reg.Names()) != 1 {
		t.Fatalf("unexpected registry: current %s, names %v", reg.Current().Name(), reg.Names())
	}
}

func TestFromConfigRefusesLocalInProduction(t *testing.T) {
	cfg := load(t, nil)
	cfg.Env = config.Production // as if the loader had been bypassed: the provider still refuses
	if _, err := registry.FromConfig(cfg, nil); err == nil || !strings.Contains(err.Error(), "development-only") {
		t.Fatalf("want a development-only refusal, got %v", err)
	}
}

func TestFromConfigReservedProvidersFailFast(t *testing.T) {
	for _, p := range []string{config.ProviderAWSKMS, config.ProviderGCPKMS} {
		cfg := load(t, map[string]string{config.EnvKMSProvider: p})
		_, err := registry.FromConfig(cfg, nil)
		if err == nil || !strings.Contains(err.Error(), config.EnvKMSProvider) || !strings.Contains(err.Error(), p) {
			t.Fatalf("%s: want a clear refusal naming the variable, got %v", p, err)
		}
	}
}

func TestFromConfigNil(t *testing.T) {
	if _, err := registry.FromConfig(nil, nil); err == nil {
		t.Fatal("nil config accepted")
	}
}
