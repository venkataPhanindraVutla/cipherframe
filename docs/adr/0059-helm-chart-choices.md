# 0059. Helm chart choices

- Status: Accepted (flagged for owner review)
- Date: 2026-11-22
- Gate: none (M9-2; choices ADR 0054 and the plan left open)
- Deciders: project owner (pending review)

## Context

ADR 0054 fixed the chart's database (external Postgres only) but not its shape. The chart has to run
three roles, a migration step, an optional face masker whose rules come from ADR 0027 and 0036 (same
machine, same directory, same UID as the worker), and keep secrets out of manifests (ADR 0013, the
`_FILE` rule).

## Options considered

- **Secrets:** a `secrets` map of references mounted as files with `_FILE` variables; `secretKeyRef`
  environment variables; a chart-managed Secret from values.
- **Configuration:** a named value per setting; a flat map of `CIPHERFRAME_*` variables.
- **Masker:** a separate Deployment; a container in the worker pod.
- **Worker autoscaling query:** a plain `sum`; `max` over pods of a per-pod sum.
- **Ingress paths:** one catch-all path per host with exclusions; explicit prefixes.
- **CRD validation in CI:** third-party schema catalogue; skip the two CRDs.
- **Hook ServiceAccount:** a hook-created one; the namespace default with no token.

## Decision

- **Secrets are references, mounted as files.** Each entry of `secrets` (`NAME: {name, key}`) is a
  read-only secret volume (mode 0440, with `fsGroup`) and a `NAME_FILE` variable. No value is ever
  rendered, and secrets do not appear in `kubectl describe` environment output. Common secrets go to
  every pod and the migration Job; `api.secrets` and `edge.secrets` add the playback keys. A role
  cannot remove a common secret; set it only where it is needed.
- **Configuration is a flat map** (`config`, plus `<role>.env`) of the documented variable names, so
  the chart never lags the variable table in usage.md. Role values are merged over the common map, and
  the listener and work directory variables are set from the role. An empty string is rendered as an
  empty variable, which the S3 and AWS credentials need to mean "default credential chain".
- **The masker is a second container of the worker pod**, not its own Deployment, because the shared
  work directory is node-local and the files are mode 0700 for one UID. It shares the worker's
  ServiceAccount, which is acceptable because it needs no cloud access. The brief's per-component
  ServiceAccount therefore covers api, edge and worker.
- **KEDA query is `max(sum by (pod) (cipherframe_jobs{namespace=...,state="available"}))`.** Every
  process with a database exports the whole table (`cipherframe_jobs`, internal/telemetry), so a plain
  sum multiplies the depth by the pod count. The `pod` and `namespace` labels are added by the
  ServiceMonitor; the query is overridable. The default threshold is 2 jobs per replica.
- **Ingress paths are fixed in the template**: api `/v1`; edge `/v1/play`, `/v1/uploads`,
  `/.well-known`. A catch-all would route `/metrics`, and not every controller can exclude a path.
  CI renders both values files and fails on a path of `/`, `/metrics`, `/healthz` or `/readyz`.
- **kubeconform skips ServiceMonitor and ScaledObject.** A schema catalogue would be an unpinned
  network fetch in CI. Both are small and covered by review and by the operators' own validation.
- **The migration Job uses the namespace default ServiceAccount with no token.** A hook-created
  ServiceAccount would add a second hook for no gain: the Job needs only the database.
- **Pinned tools.** helm v4.3.2 and kubeconform v0.8.0, each checked by SHA-256 in CI.
- **No `values.schema.json`, no required-value checks.** The server validates its whole
  configuration at start and names the variable, and the migration Job (which loads the same
  configuration) fails first on a bad release. Revisit if support questions show typos in values keys.
- **No `kind` smoke test.** The images are not published until M9-6 and the job would need Postgres
  and a mocked object store, which does not fit a few minutes.
- **Chart version 0.1.0, `appVersion` 0.1.0.** Release automation (M9-6) should set both.

## Consequences

- An operator creates the Secrets and the database first, then installs; a missing Secret leaves pods
  in `ContainerCreating`, which is visible and safe.
- Secret rotation needs a rollout restart (the process reads files once at start).
- The masker scales with the worker, one per pod; a deployment that wants more masking than
  transcoding capacity must scale the worker pods.
- The read-only root file system of the masker container has not been exercised on a cluster, and
  the chart has been rendered and schema-validated only, not installed.
- Not covered: bundled Postgres or object store, cert-manager and external-secrets integration,
  Gateway API, and multi-release isolation beyond the namespace label in the KEDA query.
