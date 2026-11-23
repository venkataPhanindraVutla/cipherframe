# Observability

Cipherframe emits OpenTelemetry traces and Prometheus metrics (ADR 0053, ADR 0055). Neither carries
a URL path or query, a header, a client address, a token, a session ID or any other identifier:
spans are named by the route template (`GET /v1/play/{session_id}/key`) and every metric label comes
from a fixed set.

## Traces

Tracing is **off** unless an OTLP endpoint is set, and then costs nothing beyond a no-op tracer.

| Variable | Meaning |
| --- | --- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Collector for traces (and, with `OTEL_METRICS_EXPORTER=otlp`, metrics). |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Collector for traces only. |
| `OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` | `grpc` or `http/protobuf` (default). |
| `OTEL_TRACES_EXPORTER=none`, `OTEL_SDK_DISABLED=true` | Turn tracing off even with an endpoint. |

The other standard `OTEL_EXPORTER_OTLP_*` variables (headers, TLS, timeouts) are read by the
OpenTelemetry exporters themselves. The service is named `cipherframe-api`, `cipherframe-edge` or
`cipherframe-worker` when the process runs one role, and `cipherframe` when it runs several;
`service.version` is the build version.

What you get:

- One server span per api or edge request, `METHOD template`, with the method, the route template
  (`http.route`) and the status code. An incoming `traceparent` is the parent.
- When the api inserts a job, the trace context goes into the job's metadata. The worker starts
  `job <kind>` as a child, with the attempt and the outcome (`succeeded`, `failed`, `cancelled`,
  `snoozed`). An upload, its processing job and the FFmpeg runs inside it form one trace.
- `ffmpeg transcode` and `ffmpeg probe` spans under the job. They never carry a command line, a
  path or a URL.

## Metrics

`/metrics` is served by the api and edge listeners, and by the worker listener of a process that
runs the worker role without api or edge (`CIPHERFRAME_WORKER_LISTEN`, default `:8082`, which also
serves `/healthz` and `/readyz`).

| Variable | Meaning |
| --- | --- |
| `CIPHERFRAME_METRICS_TOKEN` or `CIPHERFRAME_METRICS_TOKEN_FILE` | Bearer token, at least 16 bytes. Without it `/metrics` does not exist (404) and startup logs one info line saying so. |
| `CIPHERFRAME_METRICS_TENANT_LABEL` | `true` adds `tenant_id` to `cipherframe_refusals_total`. |
| `CIPHERFRAME_WORKER_LISTEN` | Listen address of the worker-only listener. |
| `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | Also push the same metrics over OTLP every 30 seconds. The generic endpoint does the same when `OTEL_METRICS_EXPORTER=otlp`. `OTEL_EXPORTER_OTLP_METRICS_PROTOCOL` picks grpc or http/protobuf. |

A scrape sends `Authorization: Bearer <token>`. The token is compared in constant time; anything
else gets a bare 401. Rotate it by changing the variable or file and restarting.

```yaml
# Prometheus
scrape_configs:
  - job_name: cipherframe-edge
    authorization: { credentials_file: /etc/prometheus/cipherframe-token }
    static_configs: [{ targets: ["edge.internal:8081"] }]
```

**`/metrics` must not be routed by a public ingress.** It sits on each service's own port behind the
token, and the token protects operating figures, not content or keys. Route only the API and the
edge's public paths through the ingress, and scrape the pod or service address inside the network.

The registry also holds the standard Go and process collectors.

| Metric | Labels | Meaning |
| --- | --- | --- |
| `cipherframe_http_request_duration_seconds` | `service` (api, edge), `route`, `method`, `status_class` | Request duration. `route` is the OpenAPI template; `other` for an unmatched request; `method` is `OTHER` for a non-standard method. |
| `cipherframe_job_duration_seconds` | `kind`, `outcome` | One job attempt. Outcomes: succeeded, failed, cancelled, snoozed. |
| `cipherframe_jobs` | `kind`, `state` | Queue depth read from the job table: available, scheduled, retryable, running. Cached 5 seconds; present only in a process with a database. |
| `cipherframe_transcode_duration_seconds` | `outcome`, `encoder` | One FFmpeg transcode of the whole rendition ladder. Outcomes: succeeded, failed. `encoder` is `software`, `nvenc`, `vaapi`, `qsv` or `videotoolbox` (ADR 0066), the encoder that ran. |
| `cipherframe_extra_codec_failures_total` | `codec`, `reason` | Extra codecs (`hevc`, `av1`) an asset asked for and did not get, by reason (`encoder_unavailable`, `transcode_failed`, `transcode_timeout`, `output_invalid`). The asset is still ready in H.264 (ADR 0064, ADR 0067). |
| `cipherframe_encoder_fallbacks_total` | `encoder`, `stage` | Times a hardware encoder was replaced by libx264: `startup` (the worker's test encode failed) or `job` (a hardware transcode failed and was repeated in software). |
| `cipherframe_transcode_seconds_of_media_total` | none | Seconds of source media transcoded successfully. |
| `cipherframe_key_request_duration_seconds` | `outcome` | Content key requests at the edge: served (2xx), denied (401, 403, 429), not_found, error. |
| `cipherframe_anomalies_total` | `kind` | Anomaly events newly recorded (key_replay, key_rate, session_limit, rapid_session_creation, segments_without_key). |
| `cipherframe_refusals_total` | `reason`, and `tenant_id` if enabled | Requests refused: `quota_exceeded` or `rate_limited`. |

Not provided: an active-sessions gauge (no cheap source; use the usage API, ADR 0047), and no
asset, session, client, viewer or key ID is ever a label.

## The tenant label

`CIPHERFRAME_METRICS_TENANT_LABEL=true` gives `cipherframe_refusals_total` a `tenant_id` label so
you can see which tenant hits its limits. The cost: the series count grows with the number of
tenants that are refused, and tenant IDs reach your metrics store and anyone who can read it. It is
off by default; per-tenant usage is always available through the usage API.

## Pointing at a collector

```sh
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318   # http/protobuf
export OTEL_METRICS_EXPORTER=otlp                              # also push metrics
# or, for gRPC:
export OTEL_EXPORTER_OTLP_PROTOCOL=grpc OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
```

## Dashboard and alerts

`deploy/observability/` holds a Grafana dashboard (`grafana/cipherframe.json`, data source chosen on
import) and Prometheus alert rules with unit tests (`prometheus/alerts.yaml`). The alerts cover a
growing queue, a high job failure ratio, 5xx on api and edge, a slow key endpoint (p99), an anomaly
spike, a refusal spike and a target that cannot be scraped. Thresholds are starting points. Import,
scrape configuration and the checks are in
[deploy/observability/README.md](../deploy/observability/README.md).

## Trying it in the development stack

```sh
cd deploy/compose
docker compose -f compose.yaml -f compose.observability.yaml --profile worker --profile observability up --build
```

The `observability` profile adds an OpenTelemetry Collector, Prometheus (scraping api, edge and
worker with a placeholder token read from a file) and Grafana with the dashboard provisioned.
`compose.observability.yaml` points the services at the collector and gives them the scrape token.
A plain `docker compose up` starts none of this. Development only.

## Audit log export

`GET /v1/audit-events` (scope `admin`) returns your tenant's audit events oldest first, as
structured JSON, in pages. `cipherframe audit export [--since T] [--until T]` writes them all as
NDJSON. See [api.md](api.md#audit-log-export-adr-0058) and [usage.md](usage.md). Feed the NDJSON to
your log store on a schedule, with an overlap (re-export from a little before the last time you
read), because an event can commit slightly after one with a later timestamp.

## The end-to-end secret scan

CI runs the stack with traces going to a collector that writes them to a file, runs the CLI end to
end, then searches the spans and the logs of every container for each secret the run handled: the
API key, the playback token, the session ID, the content key (raw, hex, base64), the source object
key, the upload ID and the scrape token, and for the signed-URL parameters `X-Amz-Signature`,
`X-Amz-Credential` and `X-Amz-Security-Token`. The job fails on any hit and prints only the kind
of secret and the file, never the value (`deploy/compose/secret-scan.sh`, ADR 0058). It can only
find what it was told about; it is a regression net.
