package config

import "strconv"

// Observability variables (M9-1a, ADR 0053). The OpenTelemetry exporter variables
// (OTEL_EXPORTER_OTLP_*) are read by the telemetry package, not here.
const (
	EnvMetricsToken       = "CIPHERFRAME_METRICS_TOKEN"        //nolint:gosec // environment variable name, not a credential
	EnvMetricsTenantLabel = "CIPHERFRAME_METRICS_TENANT_LABEL" //nolint:gosec // environment variable name, not a credential
	EnvWorkerListen       = "CIPHERFRAME_WORKER_LISTEN"
)

const (
	defaultWorkerListen = ":8082"
	// MinMetricsTokenBytes is the shortest scrape token accepted.
	MinMetricsTokenBytes = 16
)

// Metrics configures the /metrics endpoint and its labels.
type Metrics struct {
	// Token is the bearer token a scraper presents. Empty: /metrics is not served.
	Token Secret
	// TenantLabel adds tenant_id to the refusal metrics (ADR 0053). Off by default.
	TenantLabel bool
}

func (l *loader) metrics(prod bool) Metrics {
	var m Metrics
	if v, ok := l.secret(EnvMetricsToken); ok {
		switch {
		case len(v) < MinMetricsTokenBytes:
			l.errf("%s must be at least %d bytes", EnvMetricsToken, MinMetricsTokenBytes)
		case prod && isPlaceholder(v):
			l.errf("%s is a development placeholder; not allowed in production", EnvMetricsToken)
		default:
			m.Token = NewSecret(v)
		}
	}
	if v := l.plain(EnvMetricsTenantLabel, ""); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			l.errf("%s must be a boolean", EnvMetricsTenantLabel)
		}
		m.TenantLabel = b
	}
	return m
}
