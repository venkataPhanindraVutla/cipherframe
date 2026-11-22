package config

import (
	"fmt"
	"strings"
	"testing"
)

const testMetricsToken = "test-fixture-metrics-token"

func TestMetricsDefaults(t *testing.T) {
	c, err := load(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Metrics.Token.IsEmpty() || c.Metrics.TenantLabel || c.WorkerListen != ":8082" {
		t.Fatalf("defaults = %+v %q", c.Metrics, c.WorkerListen)
	}
}

func TestMetricsFromEnvAndFile(t *testing.T) {
	c, err := load(base.with(EnvMetricsToken, testMetricsToken, EnvMetricsTenantLabel, "true", EnvWorkerListen, "127.0.0.1:9100"), nil)
	if err != nil || c.Metrics.Token.Reveal() != testMetricsToken || !c.Metrics.TenantLabel || c.WorkerListen != "127.0.0.1:9100" {
		t.Fatalf("env: %+v %q %v", c.Metrics, c.WorkerListen, err)
	}
	c, err = load(base.with(EnvMetricsToken+"_FILE", "/run/token"), map[string]string{"/run/token": testMetricsToken + "\n"})
	if err != nil || c.Metrics.Token.Reveal() != testMetricsToken {
		t.Fatalf("file: %v", err)
	}
}

func TestMetricsInvalid(t *testing.T) {
	for name, e := range map[string]env{
		EnvMetricsToken + " short":       base.with(EnvMetricsToken, "short"),
		EnvMetricsToken + " both":        base.with(EnvMetricsToken, testMetricsToken, EnvMetricsToken+"_FILE", "/x"),
		EnvMetricsTenantLabel:            base.with(EnvMetricsTenantLabel, "maybe"),
		EnvWorkerListen:                  base.with(EnvWorkerListen, "nope"),
		EnvMetricsToken + " placeholder": prod.with(EnvMetricsToken, PlaceholderPrefix+"metrics-token"),
	} {
		_, err := load(e, nil)
		if err == nil || !strings.Contains(err.Error(), strings.Fields(name)[0]) {
			t.Errorf("%s: error = %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "maybe") {
			t.Errorf("%s: the error quotes the value", name)
		}
	}
}

func TestMetricsTokenNeverPrinted(t *testing.T) {
	c, err := load(base.with(EnvMetricsToken, testMetricsToken), nil)
	if err != nil {
		t.Fatal(err)
	}
	if s := fmt.Sprintf("%v %+v %#v", c, c, c.Metrics); strings.Contains(s, testMetricsToken) {
		t.Fatal("the scrape token is printable")
	}
}
