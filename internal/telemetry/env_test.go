package telemetry

import (
	"context"
	"testing"
)

func env(kv ...string) func(string) string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return func(k string) string { return m[k] }
}

func TestExporterSelection(t *testing.T) {
	const (
		generic = "OTEL_EXPORTER_OTLP_ENDPOINT"
		traces  = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"
		metrics = "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"
	)
	cases := []struct {
		name            string
		env             func(string) string
		wantTr, wantMet bool
	}{
		{"nothing", env(), false, false},
		{"generic endpoint traces only", env(generic, "http://c:4318"), true, false},
		{"generic endpoint and otlp metrics", env(generic, "http://c:4318", "OTEL_METRICS_EXPORTER", "otlp"), true, true},
		{"traces endpoint", env(traces, "http://c:4318"), true, false},
		{"metrics endpoint", env(metrics, "http://c:4318"), false, true},
		{"traces none", env(generic, "http://c:4318", "OTEL_TRACES_EXPORTER", "none"), false, false},
		{"metrics none", env(metrics, "http://c:4318", "OTEL_METRICS_EXPORTER", "none"), false, false},
		{"sdk disabled", env(generic, "http://c:4318", "OTEL_SDK_DISABLED", "true"), false, false},
	}
	for _, c := range cases {
		if got := tracesEnabled(c.env); got != c.wantTr {
			t.Errorf("%s: traces = %v", c.name, got)
		}
		if got := metricsEnabled(c.env); got != c.wantMet {
			t.Errorf("%s: metrics = %v", c.name, got)
		}
	}
}

func TestProtocol(t *testing.T) {
	for _, c := range []struct {
		env  func(string) string
		want string
		ok   bool
	}{
		{env(), "http", true},
		{env("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"), "grpc", true},
		{env("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc", "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "http/protobuf"), "http", true},
		{env("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json"), "", false},
	} {
		got, err := protocol(c.env, "TRACES")
		if got != c.want || (err == nil) != c.ok {
			t.Errorf("protocol = %q, %v", got, err)
		}
	}
}

func TestSetupWithoutEndpointHasNoExporter(t *testing.T) {
	tel, err := Setup(context.Background(), Options{Roles: []string{"api"}, Getenv: env()})
	if err != nil {
		t.Fatal(err)
	}
	defer tel.Shutdown(context.Background()) //nolint:errcheck // nothing to flush
	if tel.Tracing() || tel.tp != nil || tel.mp != nil {
		t.Fatal("exporters were created without an endpoint")
	}
	if got := serviceName([]string{"api"}); got != "cipherframe-api" {
		t.Fatalf("service name = %q", got)
	}
	if got := serviceName([]string{"api", "edge"}); got != "cipherframe" {
		t.Fatalf("combined service name = %q", got)
	}
}
