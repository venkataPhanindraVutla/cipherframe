# Observability files

Dashboard, alert rules and the development collector setup for the metrics and traces described in
[docs/observability.md](../../docs/observability.md) (ADR 0053, 0055, 0058).

| Path | What |
| --- | --- |
| `grafana/cipherframe.json` | Grafana dashboard: request rate and latency by service and route, error rate, key endpoint latency and outcomes, job duration and outcomes, queue depth, transcode duration, anomalies, refusals. |
| `grafana/provisioning/` | Data source and dashboard provisioning of the development stack. |
| `prometheus/alerts.yaml` | Alert rules. |
| `prometheus/alerts_test.yaml` | `promtool` unit tests of the rules. |
| `prometheus/prometheus.yaml` | Scrape configuration of the development stack. |
| `otel/collector.yaml` | Collector of the development stack: OTLP in, a debug summary and a span file out. |
| `dev/metrics-token` | The development scrape token, a public placeholder. |

## Import the dashboard

Grafana, Dashboards, New, Import, upload `grafana/cipherframe.json`, then pick your Prometheus data
source in the "Data source" field. The file pins no data source UID. To provision it instead, point a
file provider at the directory that holds it (see `grafana/provisioning/dashboards/cipherframe.yaml`).

## Scrape configuration

Every Cipherframe listener serves `/metrics` behind a bearer token (`CIPHERFRAME_METRICS_TOKEN` or
`CIPHERFRAME_METRICS_TOKEN_FILE`, at least 16 bytes). Give Prometheus the token as a file, not inline:

```yaml
scrape_configs:
  - job_name: cipherframe-api
    authorization: { credentials_file: /etc/prometheus/cipherframe-metrics-token }
    static_configs: [{ targets: ["api.internal:8080"] }]
  - job_name: cipherframe-edge
    authorization: { credentials_file: /etc/prometheus/cipherframe-metrics-token }
    static_configs: [{ targets: ["edge.internal:8081"] }]
  - job_name: cipherframe-worker
    authorization: { credentials_file: /etc/prometheus/cipherframe-metrics-token }
    static_configs: [{ targets: ["worker.internal:8082"] }]
```

Keep the job names: the alert rules match `cipherframe-.*`. On Kubernetes, mount the token from a
Secret and use pod or service discovery for the targets. Scrape inside the network; never route
`/metrics` through a public ingress.

Load the rules with `rule_files: [/etc/prometheus/alerts.yaml]`. Thresholds are starting points.

## Check the rules

```sh
cd deploy/observability/prometheus
promtool check rules alerts.yaml
promtool test rules alerts_test.yaml
```

CI runs both from the pinned `prom/prometheus` image (the one the development stack uses).

## Try it locally

```sh
cd deploy/compose
docker compose -f compose.yaml -f compose.observability.yaml --profile worker --profile observability up --build
```

Grafana is on http://127.0.0.1:3000 (user `admin`, password `dev-placeholder-grafana`), Prometheus on
http://127.0.0.1:9090, and the collector accepts OTLP over HTTP on 127.0.0.1:4318. Without
`compose.observability.yaml` and the profile, `docker compose up` is the unchanged stack. Development
only: every credential is a public placeholder.
