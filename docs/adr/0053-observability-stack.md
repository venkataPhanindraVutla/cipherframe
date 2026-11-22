# 0053. Observability stack

- Status: Accepted
- Date: 2026-11-22
- Gate: P14
- Deciders: project owner

## Context

M9-1 adds traces across api, edge and worker (including FFmpeg job spans), Prometheus-style metrics
(queue depth, transcode time, key-endpoint latency, anomalies), structured audit log export and a
dashboard. ADR 0047 deferred quota metrics and their tenant label to this gate. Pitfall 9 still
holds: no token, key, signed URL, session ID or source object key may appear in a span, a metric
label or a log line.

## Options considered

- **Traces:** OpenTelemetry over OTLP; OpenTelemetry written to stdout only; no tracing in v1.
- **Metrics:** a Prometheus `/metrics` endpoint; OpenTelemetry metrics with OTLP and a Prometheus
  bridge; both side by side.
- **Where `/metrics` listens:** a separate internal port; the service's own port behind a scrape
  token.
- **Tenant label:** off by default and opt-in; always on; never.

## Decision

**Traces**

- OpenTelemetry SDK, exported over OTLP (gRPC or HTTP) to any collector. Tracing is off unless an
  OTLP endpoint is configured, using the standard `OTEL_EXPORTER_OTLP_*` variables.
- W3C trace context crosses from the api to the worker inside job metadata, so an upload, its
  processing job and the FFmpeg runs inside it form one trace.

**Metrics: both, Prometheus by default**

- Metrics are recorded once, with the Prometheus client library, and named `cipherframe_...` in
  Prometheus style (unit in the name, `_total` on counters).
- `/metrics` is the default output.
- When an OTLP metrics endpoint is configured, the same metrics are also pushed over OTLP through
  the OpenTelemetry Prometheus bridge, so there is one set of instruments and one set of names.
- A Grafana dashboard JSON and Prometheus alert rules ship in the repository.

**Where `/metrics` listens**

- On each service's own port, behind a scrape bearer token read from an environment variable or a
  file, never logged, compared in constant time.
- Without a configured token `/metrics` is not served, and startup logs that once. A
  deployment's public ingress should still not route `/metrics`.
- A process that runs only the worker role has no port today. It gets one listen address of its
  own for health and `/metrics`.

**Tenant label**

- Off by default. `CIPHERFRAME_METRICS_TENANT_LABEL=true` adds `tenant_id` to the quota, session
  and refusal metrics. Per-tenant figures are always available through the usage API (ADR 0047).
- No other identifier (asset, session, client, viewer, key) is ever a label.

## Consequences

- Traces and metrics work with any OTLP collector or Prometheus-compatible scraper; no vendor is
  built in.
- `/metrics` sits on the public surface, protected only by the token. A leaked scrape token reveals
  operating figures, not content or keys, and is rotated by changing the variable or file.
- With the tenant label on, the series count grows with the number of tenants, and tenant IDs reach
  the metrics store.
- An automated test scans the spans and log lines produced by an end-to-end run for secret material
  (pitfall 9).
