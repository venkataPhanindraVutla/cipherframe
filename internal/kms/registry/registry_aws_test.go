//go:build !nokms_aws

package registry_test

import (
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/registry"
)

func awsEnv() map[string]string {
	return map[string]string{
		config.EnvKMSProvider:           config.ProviderAWSKMS,
		config.EnvKMSAWSKeyID:           "alias/cipherframe",
		config.EnvKMSAWSRegion:          "eu-west-1",
		config.EnvKMSAWSEndpoint:        "http://127.0.0.1:1", // never contacted: building the provider makes no call
		config.EnvKMSAWSAccessKeyID:     "AKIAEXAMPLE",
		config.EnvKMSAWSSecretAccessKey: "example",
	}
}

func TestFromConfigAWS(t *testing.T) {
	reg, err := registry.FromConfig(load(t, awsEnv()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if reg.Current().Name() != "awskms" || len(reg.Names()) != 1 {
		t.Fatalf("unexpected registry: current %s, names %v", reg.Current().Name(), reg.Names())
	}
}

func TestFromConfigAWSRequiresItsSettings(t *testing.T) {
	e := awsEnv()
	delete(e, config.EnvKMSAWSKeyID)
	_, err := config.Load(
		func(k string) (string, bool) { v, ok := e[k]; return v, ok },
		func(string) ([]byte, error) { return nil, nil },
	)
	if err == nil || !strings.Contains(err.Error(), config.EnvKMSAWSKeyID) {
		t.Fatalf("want a refusal naming %s, got %v", config.EnvKMSAWSKeyID, err)
	}
}
