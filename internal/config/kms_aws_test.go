package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const awsKeyARN = "arn:aws:kms:eu-west-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"

// awsBase is a valid development environment that selects AWS KMS.
var awsBase = base.with(
	EnvKMSProvider, ProviderAWSKMS,
	EnvKMSAWSKeyID, awsKeyARN,
	EnvKMSAWSRegion, "eu-west-1",
)

// awsProd is a valid production environment that selects AWS KMS with the SDK credential chain.
var awsProd = prod.with(
	EnvKMSProvider, ProviderAWSKMS,
	EnvKMSAWSKeyID, "alias/cipherframe",
	EnvKMSAWSRegion, "eu-west-1",
	EnvKMSAWSAccessKeyID, "",
	EnvKMSAWSSecretAccessKey, "",
)

func TestKMSAWSDefaults(t *testing.T) {
	c, err := load(awsBase, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := c.KMS.AWS
	if a.KeyID != awsKeyARN || a.Region != "eu-west-1" || a.Endpoint != "" || a.Timeout != 5*time.Second {
		t.Fatalf("unexpected settings: %+v", a)
	}
	if a.AccessKeyID.State() != Unset || a.SecretAccessKey.State() != Unset {
		t.Fatal("credentials should be unset in development when absent")
	}
}

func TestKMSAWSKeyIDForms(t *testing.T) {
	for _, id := range []string{
		awsKeyARN,
		"arn:aws:kms:eu-west-1:123456789012:alias/cipherframe",
		"arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/mrk-1234",
		"alias/cipherframe",
	} {
		if _, err := load(awsBase.with(EnvKMSAWSKeyID, id), nil); err != nil {
			t.Errorf("%q rejected: %v", id, err)
		}
	}
	for _, id := range []string{
		"1234abcd-12ab-34cd-56ef-1234567890ab",
		"alias/",
		"arn:aws:s3:::bucket",
		"arn:aws:kms:eu-west-1:123456789012:key/",
		"arn:aws:kms:eu-west-1:123456789012:thing/x",
		"arn:aws:kms:eu-west-1::key/x",
		"alias/has space",
	} {
		if _, err := load(awsBase.with(EnvKMSAWSKeyID, id), nil); err == nil || !strings.Contains(err.Error(), EnvKMSAWSKeyID) {
			t.Errorf("%q accepted or error does not name the variable: %v", id, err)
		}
	}
}

func TestKMSAWSRules(t *testing.T) {
	tests := []struct {
		name string
		env  env
		want string
	}{
		{"key id required", awsBase.with(EnvKMSAWSKeyID, "\x00"), EnvKMSAWSKeyID},
		{"region required", awsBase.with(EnvKMSAWSRegion, "\x00"), EnvKMSAWSRegion},
		{"bad region", awsBase.with(EnvKMSAWSRegion, "Europe"), EnvKMSAWSRegion},
		{"bad endpoint", awsBase.with(EnvKMSAWSEndpoint, "kms.local"), EnvKMSAWSEndpoint},
		{"ftp endpoint", awsBase.with(EnvKMSAWSEndpoint, "ftp://kms.local"), EnvKMSAWSEndpoint},
		{"bad timeout", awsBase.with(EnvKMSAWSTimeout, "soon"), EnvKMSAWSTimeout},
		{"zero timeout", awsBase.with(EnvKMSAWSTimeout, "0s"), EnvKMSAWSTimeout},
		{"negative timeout", awsBase.with(EnvKMSAWSTimeout, "-1s"), EnvKMSAWSTimeout},
		{"huge timeout", awsBase.with(EnvKMSAWSTimeout, "1h"), EnvKMSAWSTimeout},
		{"mixed credential states", awsBase.with(EnvKMSAWSAccessKeyID, "AKIA", EnvKMSAWSSecretAccessKey, ""), "same state"},
		{"id only", awsBase.with(EnvKMSAWSAccessKeyID, "AKIA"), "same state"},
		{"prod: credentials required", awsProd.with(EnvKMSAWSAccessKeyID, "\x00", EnvKMSAWSSecretAccessKey, "\x00"), "must be set in production"},
		{"prod: placeholder id", awsProd.with(EnvKMSAWSAccessKeyID, PlaceholderPrefix+"id", EnvKMSAWSSecretAccessKey, "s"), "placeholder"},
		{"prod: placeholder secret", awsProd.with(EnvKMSAWSAccessKeyID, "id", EnvKMSAWSSecretAccessKey, PlaceholderPrefix+"s"), "placeholder"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := load(tc.env, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want mention of %q", err, tc.want)
			}
		})
	}
}

func TestKMSAWSAcceptedConfigurations(t *testing.T) {
	c, err := load(awsProd, nil)
	if err != nil {
		t.Fatalf("production with the credential chain rejected: %v", err)
	}
	if c.KMS.AWS.AccessKeyID.State() != ProviderChain {
		t.Fatal("empty credential should select the provider chain")
	}

	c, err = load(awsProd.with(
		EnvKMSAWSAccessKeyID, "AKIAEXAMPLE",
		EnvKMSAWSSecretAccessKey, "s3cr3t",
		EnvKMSAWSEndpoint, "https://vpce-1.kms.eu-west-1.vpce.amazonaws.com",
		EnvKMSAWSTimeout, "750ms",
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	a := c.KMS.AWS
	if a.AccessKeyID.State() != Static || a.SecretAccessKey.Secret().Reveal() != "s3cr3t" ||
		a.Endpoint == "" || a.Timeout != 750*time.Millisecond {
		t.Fatalf("unexpected settings: %+v", a)
	}

	// The secret may come from a file.
	c, err = load(awsProd.with(EnvKMSAWSAccessKeyID, "AKIAEXAMPLE", EnvKMSAWSSecretAccessKey, "\x00",
		EnvKMSAWSSecretAccessKey+"_FILE", "/run/secrets/aws"), map[string]string{"/run/secrets/aws": "from-file\n"})
	if err != nil {
		t.Fatal(err)
	}
	if c.KMS.AWS.SecretAccessKey.Secret().Reveal() != "from-file" {
		t.Fatal("secret file not read")
	}
}

func TestKMSAWSIgnoredForOtherProviders(t *testing.T) {
	c, err := load(base.with(EnvKMSAWSKeyID, "not valid"), nil)
	if err != nil {
		t.Fatalf("AWS settings must be ignored when the provider is local: %v", err)
	}
	if c.KMS.AWS.KeyID != "" {
		t.Fatal("AWS settings were read for another provider")
	}
}

func TestKMSAWSNeverPrintsCredentials(t *testing.T) {
	const idv, secv = "AKIADISTINCT7Q", "SECRETDISTINCT-zz91"
	c, err := load(awsBase.with(EnvKMSAWSAccessKeyID, idv, EnvKMSAWSSecretAccessKey, secv), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{
		fmt.Sprintf("%v|%+v|%#v|%s", c.KMS.AWS, c.KMS.AWS, c.KMS.AWS, c.KMS.AWS),
		fmt.Sprintf("%v|%+v|%#v", c, c, c.KMS),
		fmt.Sprint(c.LogValue()),
	} {
		if strings.Contains(out, idv) || strings.Contains(out, secv) {
			t.Fatalf("a credential leaked: %s", out)
		}
	}

	// Error messages name variables, never values.
	_, err = load(awsBase.with(EnvKMSAWSAccessKeyID, idv, EnvKMSAWSSecretAccessKey, "\x00", EnvKMSAWSKeyID, secv), nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), idv) || strings.Contains(err.Error(), secv) {
		t.Fatalf("error leaks a value: %v", err)
	}
}
