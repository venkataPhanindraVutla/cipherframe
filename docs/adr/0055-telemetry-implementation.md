# 0055. Telemetry implementation choices

- Status: Accepted (flagged for owner review)
- Date: 2026-11-22
- Gate: none (M9-1a; choices ADR 0053 left open)
- Deciders: none yet; flagged for the project owner

## Context

ADR 0053 fixes the stack: OpenTelemetry traces over OTLP, Prometheus metrics with an optional OTLP
push, a token-protected `/metrics` on each service's own port, and an opt-in tenant label. Building
it left several details open. Pitfall 9 stays the constraint: no path, query, header, client
address, token or ID in a span or a label.

## Decision

- **A hand-rolled HTTP middleware, not otelhttp.** One small middleware in `internal/telemetry`
  starts the span and observes the histogram. It records the method, the route template and the
  status code, and nothing else, so there is no attribute filter to get wrong. An incoming
  `traceparent` header is honoured as the parent.
- **The router reports the route template.** `httpx.Router` tells the middleware which pattern
  matched through the request context, because the router matches on a copy of the request that
  outer middleware cannot read `Pattern` from. The span starts as `HTTP <method>` and is renamed
  `METHOD template` when the request ends. An unmatched request is `route="other"`; an unknown
  method is `OTHER`. The template of a mounted handler is its prefix (the tus mount), which holds no
  IDs.
- **The middleware is outermost** on the api and edge chains, so it also covers the playback gate
  and the access log. (Not changed here: the existing access-log middleware reads `Request.Pattern`
  on the outer request and so logs `unmatched` on the edge. It is a logging gap, not a leak, and is
  left alone.)
- **One process-wide telemetry.** `telemetry.Setup` stores the live instance in a package-level
  atomic pointer, and the Record functions (`telemetry.Refusal`, `telemetry.Anomaly`, ...) use it.
  They are no-ops before `Setup` and after `Shutdown`. This avoids threading a metrics handle
  through the quota, anomaly, media and job packages. The package imports no Cipherframe package
  except `version`, because `config` imports `media`; the scrape token reaches it as a string and is
  kept only as a SHA-256 digest, compared in constant time.
- **OTLP exporters are chosen by the environment, without autoexport.** Tracing is on only when
  `OTEL_EXPORTER_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is set (and
  `OTEL_TRACES_EXPORTER` is not `none`, `OTEL_SDK_DISABLED` not `true`). The metrics push is on when
  `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` is set, or the generic endpoint is set with
  `OTEL_METRICS_EXPORTER=otlp`, so a collector set up for traces does not start receiving metrics
  by surprise. `..._PROTOCOL` accepts `grpc` and `http/protobuf` (the default); `http/json` is an
  error. The SDK exporters read the remaining `OTEL_EXPORTER_OTLP_*` settings themselves. The
  push interval is fixed at 30 seconds. `autoexport` was not used because it cannot attach the
  Prometheus bridge as a producer of its reader and pulls in exporters we do not want.
- **Job trace context is River metadata**, key `traceparent`, written at insert and read by the
  worker wrapper, which starts `job <kind>` as a child. The job attempt outcome is `succeeded`,
  `failed` (it will retry or be discarded), `cancelled` or `snoozed`.
- **Queue depth is read at scrape time**, one `GROUP BY kind, state` query over `river_job` for
  the states available, scheduled, retryable and running, cached for 5 seconds. A kind seen once keeps
  reporting 0 in drained states. A failed query serves the last counts and reports nothing before the
  first success (a database failure is not "zero jobs").
- **Transcode metric labels.** One FFmpeg process encodes the whole ladder, so a per-rendition
  duration does not exist. `cipherframe_transcode_duration_seconds` is labelled `outcome`
  (`succeeded`, `failed`), and `cipherframe_transcode_seconds_of_media_total` adds the source
  duration of successful runs. Spans are `ffmpeg transcode` and `ffmpeg probe`.
- **Key endpoint outcome from the status.** `served` is a 2xx, `denied` a 401, 403 or 429,
  `not_found` a 404, `error` anything else. It is measured in the middleware on the template
  `/v1/play/{session_id}/key`, so requests the guard rejects (bad token) count as `denied`.
- **Refusals** are counted where they are decided: the quota checks (`quota_exceeded`) and the
  control-plane limiter (`rate_limited`). Only refusals carry the optional `tenant_id` label. The
  other limits of the key endpoint are anomalies, counted in `cipherframe_anomalies_total` when
  an event is newly recorded.
- **No active-sessions gauge.** There is no cheap source: counting needs a scan of the sessions
  table per tenant at every scrape. The usage API (ADR 0047) stays the source for that figure.
- **Scrape token rules.** At least 16 bytes; a placeholder (`dev-placeholder-`) is refused in
  production; an empty or short value is a configuration error, not "off". Unset is off. Any failed
  authentication is a bare 401.
- **Worker listener.** A process with the worker role and neither api nor edge opens
  `CIPHERFRAME_WORKER_LISTEN` (default `:8082`), serving `/healthz` and `/readyz` in the same JSON
  shape as the other listeners, and `/metrics`. It has no request instrumentation.
- **`/metrics` is mounted outside the application router**, in front of it, so it has no request ID
  or access-log line and does not appear in the OpenAPI spec or in the HTTP histogram.

## New dependencies

All Apache-2.0 or BSD, all from the OpenTelemetry and Prometheus projects, versions matching the
OpenTelemetry release already present indirectly (otel 1.47.0):

- `github.com/prometheus/client_golang`: the metrics registry and exposition (ADR 0053 requires it).
  Already an indirect dependency.
- `go.opentelemetry.io/otel`, `otel/trace`, `otel/sdk`, `otel/sdk/metric`: the tracer and the periodic
  metric reader.
- `go.opentelemetry.io/otel/exporters/otlp/otlptrace/{otlptracegrpc,otlptracehttp}` and
  `otlpmetric/{otlpmetricgrpc,otlpmetrichttp}`: the OTLP exporters for both protocols.
- `go.opentelemetry.io/contrib/bridges/prometheus`: pushes the Prometheus registry over OTLP
  (ADR 0053).

A few indirect modules moved to newer minor versions as a result (`go mod tidy`).

## Consequences

- With no OTLP variables set the process creates no SDK and no exporter; only the registry exists.
- The series count is bounded by the route templates and the fixed label sets. With the tenant label
  on, `cipherframe_refusals_total` grows with the tenants that are refused.
- Because the telemetry is global, tests that call `Setup` must `Shutdown` it (they do).
- A trace that starts at a client continues only if the client sends `traceparent`; the edge honours
  it from anyone, so a caller can place a request's span in a trace of its choosing. That is the
  standard behaviour and carries no data into Cipherframe.
