// Package telemetry is Cipherframe's observability core (ADR 0053): OpenTelemetry traces exported
// over OTLP, and Prometheus metrics served on /metrics and optionally pushed over OTLP.
//
// Pitfall 9 governs everything here. A span, a metric label or a log line never carries a URL
// path or query, a header, a client address, a token, a session ID or any other identifier. Span
// names and the route label come from the route template ("/v1/play/{session_id}/key"), and every
// label value comes from a fixed set (see the Record functions).
//
// The package is a leaf: it imports no other Cipherframe package but version, so any other package
// may call it. Until
// Setup runs, and after Shutdown, every function is a cheap no-op.
package telemetry

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	prombridge "go.opentelemetry.io/contrib/bridges/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/venkataPhanindraVutla/cipherframe/internal/version"
)

const tracerName = "github.com/venkataPhanindraVutla/cipherframe"

// pushInterval is how often the Prometheus registry is pushed over OTLP.
const pushInterval = 30 * time.Second

// propagator is the W3C trace context propagator. It is a value, not an otel global, so tests and
// processes that never call Setup behave the same.
var propagator propagation.TextMapPropagator = propagation.TraceContext{}

// Options configure Setup.
type Options struct {
	// Roles are the roles this process runs ("api", "edge", "worker"); one role names the service
	// cipherframe-<role>, several name it cipherframe.
	Roles []string
	// MetricsToken is the bearer token /metrics requires. Empty: /metrics is not served. Only its
	// hash is kept.
	MetricsToken string
	// TenantLabel adds tenant_id to the refusal metrics.
	TenantLabel bool
	// Getenv reads the OTEL_* variables; nil means os.Getenv.
	Getenv func(string) string
	// SpanExporter, when set, replaces the OTLP trace exporter. Tests use an in-memory one.
	SpanExporter sdktrace.SpanExporter
}

// Telemetry is the live telemetry of one process.
type Telemetry struct {
	// Registry holds the Go and process collectors and the Cipherframe metrics.
	Registry *prometheus.Registry

	tracer      trace.Tracer
	m           *metrics
	tokenHash   [sha256.Size]byte
	hasToken    bool
	tracing     bool
	tp          *sdktrace.TracerProvider
	mp          *sdkmetric.MeterProvider
	shutdownRan atomic.Bool
}

var current atomic.Pointer[Telemetry]

func cur() *Telemetry { return current.Load() }

// Setup builds the telemetry of this process and makes it the one the package-level Record
// functions and middleware use. Without an OTLP endpoint in the environment it creates no
// exporter and no SDK: spans are no-ops and only the Prometheus registry is live.
func Setup(ctx context.Context, o Options) (*Telemetry, error) {
	getenv := o.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	t := &Telemetry{Registry: prometheus.NewRegistry(), tracer: noop.NewTracerProvider().Tracer(tracerName), hasToken: o.MetricsToken != "", tokenHash: sha256.Sum256([]byte(o.MetricsToken))}
	t.Registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	t.m = newMetrics(t.Registry, o.TenantLabel)

	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		attribute.String("service.name", serviceName(o.Roles)),
		attribute.String("service.version", version.Get().Version),
	))
	if err != nil {
		return nil, fmt.Errorf("telemetry: resource: %w", err)
	}

	exp := o.SpanExporter
	if exp == nil && tracesEnabled(getenv) {
		if exp, err = newSpanExporter(ctx, getenv); err != nil {
			return nil, err
		}
	}
	if exp != nil {
		t.tp = sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
		t.tracer = t.tp.Tracer(tracerName)
		t.tracing = true
	}

	if metricsEnabled(getenv) {
		mexp, err := newMetricExporter(ctx, getenv)
		if err != nil {
			_ = t.Shutdown(ctx)
			return nil, err
		}
		reader := sdkmetric.NewPeriodicReader(mexp, sdkmetric.WithInterval(pushInterval),
			sdkmetric.WithProducer(prombridge.NewMetricProducer(prombridge.WithGatherer(t.Registry))))
		t.mp = sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader), sdkmetric.WithResource(res))
	}
	current.Store(t)
	return t, nil
}

// Shutdown flushes pending spans and metrics and stops the exporters. It is safe to call twice.
func (t *Telemetry) Shutdown(ctx context.Context) error {
	if t == nil || !t.shutdownRan.CompareAndSwap(false, true) {
		return nil
	}
	current.CompareAndSwap(t, nil)
	var errs []error
	if t.tp != nil {
		errs = append(errs, t.tp.Shutdown(ctx))
	}
	if t.mp != nil {
		errs = append(errs, t.mp.Shutdown(ctx))
	}
	return errors.Join(errs...)
}

// Flush exports pending spans now.
func (t *Telemetry) Flush(ctx context.Context) error {
	if t == nil || t.tp == nil {
		return nil
	}
	return t.tp.ForceFlush(ctx)
}

// Tracing reports whether spans are exported.
func (t *Telemetry) Tracing() bool { return t != nil && t.tracing }

// MetricsEnabled reports whether /metrics is served (a scrape token is configured).
func (t *Telemetry) MetricsEnabled() bool { return t != nil && t.hasToken }

func serviceName(roles []string) string {
	if len(roles) == 1 {
		return "cipherframe-" + roles[0]
	}
	return "cipherframe"
}

func tracesEnabled(getenv func(string) string) bool {
	if disabled(getenv) || strings.EqualFold(getenv("OTEL_TRACES_EXPORTER"), "none") {
		return false
	}
	return getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" || getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != ""
}

// metricsEnabled follows the brief: the metrics endpoint variable alone enables the push; the
// generic endpoint needs OTEL_METRICS_EXPORTER=otlp, so that a trace-only collector setting does
// not start pushing metrics.
func metricsEnabled(getenv func(string) string) bool {
	if disabled(getenv) || strings.EqualFold(getenv("OTEL_METRICS_EXPORTER"), "none") {
		return false
	}
	if getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT") != "" {
		return true
	}
	return getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" && strings.EqualFold(getenv("OTEL_METRICS_EXPORTER"), "otlp")
}

func disabled(getenv func(string) string) bool {
	return strings.EqualFold(getenv("OTEL_SDK_DISABLED"), "true")
}

// protocol returns the OTLP protocol of a signal: grpc or http. signal is "TRACES" or "METRICS".
func protocol(getenv func(string) string, signal string) (string, error) {
	p := getenv("OTEL_EXPORTER_OTLP_" + signal + "_PROTOCOL")
	if p == "" {
		p = getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}
	switch p {
	case "grpc":
		return "grpc", nil
	case "", "http/protobuf":
		return "http", nil
	}
	return "", fmt.Errorf("telemetry: OTEL_EXPORTER_OTLP_PROTOCOL must be grpc or http/protobuf")
}

func newSpanExporter(ctx context.Context, getenv func(string) string) (sdktrace.SpanExporter, error) {
	p, err := protocol(getenv, "TRACES")
	if err != nil {
		return nil, err
	}
	if p == "grpc" {
		return otlptracegrpc.New(ctx)
	}
	return otlptracehttp.New(ctx)
}

func newMetricExporter(ctx context.Context, getenv func(string) string) (sdkmetric.Exporter, error) {
	p, err := protocol(getenv, "METRICS")
	if err != nil {
		return nil, err
	}
	if p == "grpc" {
		return otlpmetricgrpc.New(ctx)
	}
	return otlpmetrichttp.New(ctx)
}
