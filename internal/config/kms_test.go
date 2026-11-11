package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func kekPlaceholder() string {
	b := []byte(PlaceholderPrefix)
	for len(b) < KEKBytes {
		b = append(b, 'x')
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestKMSDevelopmentDefaultsToLocal(t *testing.T) {
	c, err := load(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.KMS.Provider != ProviderLocal {
		t.Fatalf("provider = %q, want local", c.KMS.Provider)
	}
	if cur, s := c.KMS.LocalKEKs.Current(); cur != 1 || len(s.Reveal()) != KEKBytes {
		t.Fatal("current KEK wrong")
	}
	if got := c.KMS.LocalKEKs.Versions(); len(got) != 1 || got[0] != 1 {
		t.Fatalf("versions = %v", got)
	}
}

func TestKMSLocalRules(t *testing.T) {
	tests := []struct {
		name string
		env  env
		want string
	}{
		{"missing keks", base.with(EnvKMSLocalKEKs, "\x00"), EnvKMSLocalKEKs},
		{"missing current", base.with(EnvKMSLocalKEKCurrent, "\x00"), EnvKMSLocalKEKCurrent},
		{"31 bytes", base.with(EnvKMSLocalKEKs, "1:"+pepper('a', 31)), "exactly 32"},
		{"33 bytes", base.with(EnvKMSLocalKEKs, "1:"+pepper('a', 33)), "exactly 32"},
		{"bad base64", base.with(EnvKMSLocalKEKs, "1:!!!"), "base64"},
		{"no colon", base.with(EnvKMSLocalKEKs, "nope"), "version:base64"},
		{"zero version", base.with(EnvKMSLocalKEKs, "0:"+pepper('a', 32)), "invalid version"},
		{"duplicate version", base.with(EnvKMSLocalKEKs, "1:"+pepper('a', 32)+",1:"+pepper('b', 32)), "more than once"},
		{"current not in set", base.with(EnvKMSLocalKEKCurrent, "2"), "not in"},
		{"current not an int", base.with(EnvKMSLocalKEKCurrent, "x"), "positive integer"},
		{"unknown provider", base.with(EnvKMSProvider, "nope"), EnvKMSProvider},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := load(tc.env, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want mention of %q", err, tc.want)
			}
		})
	}
}

func TestKMSMultipleVersionsAndFile(t *testing.T) {
	e := base.with(EnvKMSLocalKEKs, "\x00", EnvKMSLocalKEKs+"_FILE", "/keks", EnvKMSLocalKEKCurrent, "2")
	c, err := load(e, map[string]string{"/keks": "1:" + pepper('a', 32) + ",2:" + pepper('b', 32) + "\n"})
	if err != nil {
		t.Fatal(err)
	}
	if cur, s := c.KMS.LocalKEKs.Current(); cur != 2 || s.Reveal() != strings.Repeat("b", 32) {
		t.Fatal("current KEK wrong")
	}
	if c.KMS.LocalKEKs.Len() != 2 {
		t.Fatal("want two KEKs")
	}
}

func TestKMSProduction(t *testing.T) {
	tests := []struct {
		name string
		env  env
		want string
	}{
		{"provider required", prod.with(EnvKMSProvider, "\x00"), EnvKMSProvider},
		{"local refused", prod.with(EnvKMSProvider, ProviderLocal), "development-only"},
		{"placeholder kek", prod.with(EnvKMSProvider, ProviderLocal, EnvKMSLocalKEKs, "1:"+kekPlaceholder()), "placeholder"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := load(tc.env, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want mention of %q", err, tc.want)
			}
		})
	}
	for _, p := range []string{ProviderVault, ProviderAWSKMS} {
		if _, err := load(prod.with(EnvKMSProvider, p), nil); err != nil {
			t.Fatalf("production with %s rejected: %v", p, err)
		}
	}
	// gcpkms needs its key name (see kms_gcp_test.go).
}

func TestKMSDevelopmentAcceptsPlaceholder(t *testing.T) {
	if _, err := load(base.with(EnvKMSLocalKEKs, "1:"+kekPlaceholder()), nil); err != nil {
		t.Fatal(err)
	}
}

func TestKMSErrorsNeverContainKEKs(t *testing.T) {
	const bad = "KEKSECRET-distinct-zz91"
	for _, e := range []env{
		base.with(EnvKMSLocalKEKs, "1:"+bad),
		base.with(EnvKMSLocalKEKs, bad),
		base.with(EnvKMSLocalKEKs, bad+":"+pepper('a', 32)),
		base.with(EnvKMSLocalKEKs, "1:"+base64.StdEncoding.EncodeToString([]byte(bad))),
		base.with(EnvKMSLocalKEKs, "1:"+pepper('a', 32)+",1:"+bad),
	} {
		_, err := load(e, nil)
		if err == nil {
			t.Fatal("expected error")
		}
		enc := base64.StdEncoding.EncodeToString([]byte(bad))
		if strings.Contains(err.Error(), bad) || strings.Contains(err.Error(), enc) {
			t.Fatalf("error leaks a KEK value: %v", err)
		}
	}
}
