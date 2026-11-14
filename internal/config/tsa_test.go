package config

import (
	"testing"
	"time"
)

func TestTSA(t *testing.T) {
	c, err := load(base, nil)
	if err != nil || c.TSA.Enabled() || c.TSA.Timeout != 10*time.Second {
		t.Fatalf("default: %+v, %v", c.TSA, err)
	}
	c, err = load(prod.with(EnvTSAURL, "https://tsa.example.com/tsr", EnvTSATimeout, "3s", EnvTSAPolicyOID, "1.2.3.4"), nil)
	if err != nil || c.TSA.URL != "https://tsa.example.com/tsr" || c.TSA.Timeout != 3*time.Second || c.TSA.PolicyOID != "1.2.3.4" {
		t.Fatalf("production https: %+v, %v", c.TSA, err)
	}
	if c, err = load(base.with(EnvTSAURL, "http://127.0.0.1:3000/tsr"), nil); err != nil || !c.TSA.Enabled() {
		t.Fatalf("http in development: %+v, %v", c.TSA, err)
	}
	for name, e := range map[string]env{
		"http in production":  prod.with(EnvTSAURL, "http://tsa.example.com/tsr"),
		"other scheme":        base.with(EnvTSAURL, "ftp://tsa.example.com"),
		"credentials":         base.with(EnvTSAURL, "https://u:p@tsa.example.com"),
		"no host":             base.with(EnvTSAURL, "https:///tsr"),
		"bad timeout":         base.with(EnvTSATimeout, "0s"),
		"timeout over limit":  base.with(EnvTSATimeout, "1h"),
		"bad policy oid":      base.with(EnvTSAPolicyOID, "not-an-oid"),
		"single arc policy":   base.with(EnvTSAPolicyOID, "1"),
		"leading zero in arc": base.with(EnvTSAPolicyOID, "1.02.3"),
	} {
		if _, err := load(e, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
