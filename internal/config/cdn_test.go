package config

import (
	"strings"
	"testing"
)

var cdnCloudFront = base.with(
	EnvCDNProvider, "cloudfront",
	EnvCDNBaseURL, "https://cdn.example.com",
	EnvCDNKeyID, "K2JCJMDEHXQW5F",
	EnvCDNSigningKeyFile, "/run/secrets/cdn-key",
	EnvCDNCloudFrontDistributionID, "E2EXAMPLE1ABCD",
)

var cdnCloudCDN = base.with(
	EnvCDNProvider, "cloudcdn",
	EnvCDNBaseURL, "https://media.example.com/",
	EnvCDNKeyID, "cipherframe-key",
	EnvCDNSigningKeyFile, "/run/secrets/cdn-key",
	EnvCDNCloudCDNProject, "my-project",
	EnvCDNCloudCDNURLMap, "cipherframe-map",
)

func TestCDNOffByDefault(t *testing.T) {
	c, err := load(base, nil)
	if err != nil || c.CDN.Enabled() {
		t.Fatalf("default: %+v, %v", c.CDN, err)
	}
}

func TestCDNValid(t *testing.T) {
	c, err := load(cdnCloudFront, nil)
	if err != nil || !c.CDN.Enabled() || c.CDN.Provider != CDNCloudFront || c.CDN.BaseURL != "https://cdn.example.com" ||
		c.CDN.CloudFrontDistributionID != "E2EXAMPLE1ABCD" {
		t.Fatalf("cloudfront: %+v, %v", c.CDN, err)
	}
	if c, err = load(cdnCloudCDN, nil); err != nil || c.CDN.BaseURL != "https://media.example.com" || c.CDN.CloudCDNURLMap != "cipherframe-map" {
		t.Fatalf("cloudcdn: %+v, %v", c.CDN, err)
	}
	p := prod.with(EnvCDNProvider, "cloudfront", EnvCDNBaseURL, "https://cdn.example.com", EnvCDNKeyID, "K1",
		EnvCDNSigningKeyFile, "/k", EnvCDNCloudFrontDistributionID, "E2EXAMPLE1ABCD")
	if _, err = load(p, nil); err != nil {
		t.Fatalf("production: %v", err)
	}
}

func TestCDNInvalid(t *testing.T) {
	for name, tc := range map[string]struct {
		e    env
		want string // the variable the message names
	}{
		"unknown provider":     {cdnCloudFront.with(EnvCDNProvider, "fastly"), EnvCDNProvider},
		"no base url":          {cdnCloudFront.with(EnvCDNBaseURL, "\x00"), EnvCDNBaseURL},
		"base url with path":   {cdnCloudFront.with(EnvCDNBaseURL, "https://cdn.example.com/v1"), EnvCDNBaseURL},
		"base url with query":  {cdnCloudFront.with(EnvCDNBaseURL, "https://cdn.example.com/?a=b"), EnvCDNBaseURL},
		"base url credentials": {cdnCloudFront.with(EnvCDNBaseURL, "https://u:p@cdn.example.com"), EnvCDNBaseURL},
		"no key id":            {cdnCloudFront.with(EnvCDNKeyID, "\x00"), EnvCDNKeyID},
		"key id with space":    {cdnCloudFront.with(EnvCDNKeyID, "a b"), EnvCDNKeyID},
		"literal key":          {cdnCloudFront.with(envCDNSigningKeyLiteral, "test-fixture-key"), envCDNSigningKeyLiteral},
		"no distribution":      {cdnCloudFront.with(EnvCDNCloudFrontDistributionID, "\x00"), EnvCDNCloudFrontDistributionID},
		"no project":           {cdnCloudCDN.with(EnvCDNCloudCDNProject, "\x00"), EnvCDNCloudCDNProject},
		"no url map":           {cdnCloudCDN.with(EnvCDNCloudCDNURLMap, "\x00"), EnvCDNCloudCDNURLMap},
		"settings without it":  {base.with(EnvCDNBaseURL, "https://cdn.example.com"), EnvCDNProvider},
		"http in production":   {prod.with(EnvCDNProvider, "cloudfront", EnvCDNBaseURL, "http://cdn.example.com", EnvCDNKeyID, "K1", EnvCDNSigningKeyFile, "/k", EnvCDNCloudFrontDistributionID, "E2EXAMPLE1ABCD"), EnvCDNBaseURL},
	} {
		_, err := load(tc.e, nil)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: the error does not name %s: %v", name, tc.want, err)
		}
	}
}

// The key file is needed by the edge role only, so the loader does not demand it.
func TestCDNKeyFileIsOptionalAtLoad(t *testing.T) {
	if _, err := load(cdnCloudFront.with(EnvCDNSigningKeyFile, "\x00"), nil); err != nil {
		t.Fatal(err)
	}
}

func TestCDNNeverPrintsKeyMaterial(t *testing.T) {
	c, err := load(cdnCloudFront, map[string]string{"/run/secrets/cdn-key": "test-fixture-cdn-key-material"}) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(c.LogValue().String(), "test-fixture-cdn-key-material") {
		t.Fatal("the key material is in the logged configuration")
	}
}
