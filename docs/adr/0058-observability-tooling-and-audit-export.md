# 0058. Observability tooling and audit export

- Status: Accepted (flagged for owner review)
- Date: 2026-11-22
- Gate: none (M9-1b; choices ADR 0053 and 0055 leave open)
- Deciders: implementation, pending the project owner's review

## Context

ADR 0053 promises a dashboard, alert rules, structured audit log export, a bundled collector in the
development stack and an automated secret scan of spans and logs (pitfall 9). ADR 0055 fixed the
metric names and labels. Building the rest left several details open.

## Decision

**Dashboard and alerts**

- One Grafana dashboard, `deploy/observability/grafana/cipherframe.json`, over the metrics of ADR
  0055. The data source is a template variable (`DS_PROMETHEUS`), so the file holds no UID of any
  installation and imports into any Grafana with a Prometheus data source. A `service` variable
  filters the HTTP panels.
- Seven alert rules in `deploy/observability/prometheus/alerts.yaml` with a `promtool` unit test
  file. Thresholds are starting points (queue over 50 and growing for 15 minutes, job failure ratio
  over 25% with at least three failures, 5xx ratio over 5% on api and edge with some traffic, key
  endpoint p99 over 500 ms, over 20 anomaly events in 15 minutes, over 50 refusals in 15 minutes,
  target down for 5 minutes). Rules that divide by traffic carry a minimum-traffic guard so a quiet
  service does not page.
- CI runs `promtool check rules`, `promtool test rules` and `promtool check config` from the same
  pinned `prom/prometheus` image (by digest) that the development stack runs, so one pin serves
  both. No release binary is downloaded.

**Development stack**

- The collector (`otel/opentelemetry-collector-contrib`, which has the file exporter), Prometheus and
  Grafana are services of `deploy/compose/compose.yaml` in the profile `observability`, each pinned
  by tag and digest. A plain `docker compose up` does not start them, and CI asserts it.
- The services' own settings (the OTLP endpoint and the scrape token file) are in a second file,
  `compose.observability.yaml`, merged with `-f`. They could not live in `compose.yaml` behind an
  interpolated default: an empty `CIPHERFRAME_METRICS_TOKEN` is a configuration error (ADR 0055), so
  "unset" cannot be written as a default in a mapping. A profile cannot add environment variables
  to a service in another profile; a merge file can.
- Prometheus reads the scrape token from a file (`deploy/observability/dev/metrics-token`, a
  `dev-placeholder-` value), as the production example does. The collector runs as root so it can
  write its named volume; it is development only.
- The collector writes every span to `/otel-out/traces.jsonl` (rotated at 50 MB) for the scan, and
  prints batch summaries. There is no metrics pipeline: Prometheus scrapes.

**Audit export: `GET /v1/audit-events`**

- Scope `admin`, tenant of the caller. Oldest first, ordered by `(created_at, id)`, which is a total
  order, so a page never repeats or skips a row that was committed before the read began.
- Query: `limit` 1 to 500 (default 100), `after` (the opaque cursor), `since` (inclusive) and
  `until` (exclusive), both RFC 3339, `until` after `since`. The cursor is
  `base64url("1.<created_at in microseconds>.<event id>")`; a bad one is a 400 on field `after`.
  The last page has no `next_cursor`.
- Each item holds `id`, `action`, `created_at` and, when present, `target`, `client_id`, `key_id`
  and `request_id`. That is every column of the row except `tenant_id` (the caller's own). Nothing is
  redacted or added: the writers already store only IDs, labels and a short hash prefix of a
  session, never a token, key secret, signed URL, session ID or source object key.
- `key_id` (not `api_key_id`) follows the name `whoami` and the key schemas already use.
- No filter by action or client in this version; it is an export, not a query API.

**CLI: `cipherframe audit export [--since T] [--until T]`**

- Writes one compact JSON object per line (NDJSON) to stdout, following `next_cursor` until it is
  absent, 500 events a page. The output is NDJSON with or without `--json`; `--json` still changes
  how an error is printed. Times are RFC 3339.

**End-to-end secret scan**

- In the CI compose job the services send traces to the collector. `cli-e2e.sh`, when given
  `CIPHERFRAME_SCAN_SECRETS_FILE`, writes one `kind=value` line per secret it handled to a file in a
  private temp directory: the API key (whole and its secret part), the playback token, the session
  ID, the content key (hex and base64), the source object key and the multipart upload ID (read from
  the database before the asset is deleted) and the scrape token. They also go to `::add-mask::`, so
  a failure that prints logs still hides them.
- After the run the job stops the collector (which flushes), copies the span file and writes the
  logs of every service of the stack, then `deploy/compose/secret-scan.sh` searches those files for
  each value and, by name, for `X-Amz-Signature`, `X-Amz-Credential` and `X-Amz-Security-Token`. It
  prints the kind and the file of a hit, never a value, and passes values to `grep -f` through a
  file. A value shorter than 8 characters is an error, not a silent weak check. A separate step
  checks that spans exist (an `ffmpeg transcode` span and the key request span) so an empty file
  cannot pass.
- The logs of all containers are scanned, including third-party ones (SeaweedFS, Postgres, Grafana,
  Prometheus). A hit in one of those is still a real leak of that run's secret into a log, and the
  file name says whose.
- The span and log files are not uploaded as a CI artefact: on a failure they would contain the
  secret.
- The scanner has its own self-test (`secret-scan-test.sh`) in CI.

## Consequences

- The observability pieces are optional and the default stack is unchanged.
- The audit export cannot see a row that commits after the reader has moved past its timestamp:
  `created_at` is the transaction's start time, so a long transaction can commit a row older than
  rows already exported. Re-export from a slightly earlier `--since` to cover it. A sequence number
  would remove the gap and is not part of this milestone.
- The tenant label stays limited to refusals (ADR 0055). Quota usage and limits are read from the
  usage API, not from metrics: a per-tenant usage gauge would need a table scan per scrape.
- The queue-depth panel is empty for a kind that was never non-empty at a scrape (ADR 0055).
- The scan can only find a secret it was told about, in the forms it was told about (raw, hex and
  base64 for the content key). It is a regression net, not a proof.
- The pinned images need a digest update when they are bumped; CI does not do that.
