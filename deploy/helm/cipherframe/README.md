# Cipherframe Helm chart

Runs the three server roles of Cipherframe on Kubernetes (ADR 0008, ADR 0059): one Deployment each
for `api`, `edge` and `worker`, a migration Job, and optional Ingress, ServiceMonitor,
PodDisruptionBudgets, NetworkPolicy, HPA and a KEDA ScaledObject. It is the Kubernetes counterpart of
`deploy/compose/` and follows the same container layout. Nothing in it is applied by the project's
CI; CI renders and validates it (see Checks).

## What you must bring

- **Postgres, external only** (ADR 0054). Any managed Postgres or a CloudNativePG cluster. The chart
  never creates one. Size `max_connections` for the pools of every replica, plus 16 per edge replica
  for tus upload locks ([usage.md](../../../docs/usage.md#uploads)).
- **S3-compatible storage** with a source and a delivery bucket, and **a key provider** (AWS KMS,
  Cloud KMS or Vault; `local` is development-only and production refuses it). The Terraform examples
  ([AWS](../../terraform/aws/README.md), [GCP](../../terraform/gcp/README.md)) create both.
- **Secrets**, created by you, in the release namespace. The chart takes only their names:

  | Variable (in `secrets:`) | Content |
  | --- | --- |
  | `CIPHERFRAME_DATABASE_URL` | `postgres://` URL |
  | `CIPHERFRAME_API_KEY_PEPPERS` | `version:base64,...` |
  | `CIPHERFRAME_PLAYBACK_TOKEN_KEYS` (api, edge) | `kid:base64,...` |
  | `CIPHERFRAME_METRICS_TOKEN` (optional, needed by the ServiceMonitor) | at least 16 bytes |
  | KMS and S3 static credentials (only if you do not use IAM roles) | see [usage.md](../../../docs/usage.md#configuration) |

  ```sh
  kubectl create secret generic cipherframe-database --from-file=url=./database-url.txt
  ```

  Each entry is mounted read-only as a file and the chart sets `<NAME>_FILE` (the `_FILE` rule in
  usage.md), so no secret value is in a manifest, an environment variable or a Helm release.
- **Images.** `image.server.repository` and `image.worker.repository` default to the project's
  GHCR names, but until the release automation publishes them (M9-6) build them from `build/` and
  set the repositories and tags yourself. Set a `digest` to pin by digest.

## Install

```sh
helm install cipherframe deploy/helm/cipherframe -n cipherframe -f my-values.yaml
```

`ci/default-values.yaml` is the smallest working values file (AWS KMS and IRSA) and
`ci/all-features-values.yaml` shows every option switched on. Copy one and edit it.

The `migrate` Job runs `cipherframe-server migrate` as a `pre-install,pre-upgrade` hook, so the
schema is current before new pods start, and a failed migration stops the release. It is deleted
after it succeeds and kept when it fails, so you can read its log. Create the first API key once
with `kubectl exec deploy/cipherframe-api -- /cipherframe-server admin bootstrap ...` (see usage.md).

## Pods

| | api | edge | worker |
| --- | --- | --- | --- |
| Image | server | server | worker (with FFmpeg) |
| Args | `--role=api` | `--role=edge` | `--role=worker` |
| Listener | `:8080` | `:8081` | `:8082` (`CIPHERFRAME_WORKER_LISTEN`) |
| Probes | `/healthz` live, `/readyz` ready | same | same |
| Scratch | `/tmp` emptyDir | `/tmp` emptyDir | `/tmp` and `/work` emptyDirs |

Every pod runs as UID 65532 with a read-only root file system, all capabilities dropped,
`allowPrivilegeEscalation: false`, the `RuntimeDefault` seccomp profile and no service account
token. Each role has its own ServiceAccount; put the IRSA or Workload Identity annotation under
`<role>.serviceAccount.annotations`.

**Face masker.** `worker.masker.enabled=true` adds the masker as a second container of the worker
pod, not a separate Deployment: it must share the worker's work directory and UID on one machine
(ADR 0027, ADR 0036). It needs a database role limited to `external_tasks`
(`deploy/compose/masker-role.sql`, [spec/jobs/README.md](../../../spec/jobs/README.md)); its URL
Secret is `worker.masker.databaseUrlSecret`. The masker has no cloud IAM needs of its own. Its
read-only root file system is the chart default and has not been run against a cluster yet; set
`containerSecurityContext.readOnlyRootFilesystem=false` if it needs more.

## Exposure and `/metrics`

`ingress.api` and `ingress.edge` render only explicit path prefixes: the api gets `/v1`; the edge
gets `/v1/play`, `/v1/uploads` and `/.well-known`. `/metrics`, `/healthz` and `/readyz` are never
routed, whatever the controller (docs/observability.md). If both share a host, the controller must
choose the longest prefix, which the Ingress spec requires. The edge carries uploads, so raise the
controller's body-size limit and turn off request buffering (the nginx annotations are in
`ci/all-features-values.yaml`).

Scrape with the pod or Service address inside the cluster. `serviceMonitor.enabled` creates a
Prometheus Operator ServiceMonitor for all three Services with a bearer token taken from the Secret
you listed as `secrets.CIPHERFRAME_METRICS_TOKEN`. Without a token the server has no `/metrics`.

## Scaling

- `api.autoscaling` and `edge.autoscaling`: a plain CPU HPA. When enabled, `replicas` is not set on
  the Deployment so a Helm upgrade does not reset the count.
- `worker.keda`: a KEDA ScaledObject with the Prometheus scaler on the queue depth,
  `cipherframe_jobs{state="available"}`. Every process with a database reports the whole table, so
  the default query is `max(sum by (pod) (cipherframe_jobs{namespace="<release namespace>",state="available"}))`
  rather than a sum that would count the queue once per pod. It assumes your Prometheus attaches
  `pod` and `namespace` labels, which the ServiceMonitor does; override `worker.keda.query` if not.
  `threshold` is jobs per replica; one worker transcodes one source at a time by default
  (`CIPHERFRAME_WORKER_MEDIA_CONCURRENCY`). Scale-in waits `cooldownPeriod`, and a job running when a
  pod stops is retried after its 20-second grace.
- `<role>.pdb` creates a PodDisruptionBudget.

## NetworkPolicy

`networkPolicy.enabled` selects the three roles' pods. Ingress: `ingressFrom` may reach api and edge;
`metricsFrom` (default: the `monitoring` namespace) may reach all three. Egress stays open until
you list rules in `networkPolicy.egress`; then only DNS and your rules (database, object store,
KMS, OTLP collector) are allowed. Your CNI must enforce NetworkPolicy.

## Cloud IAM per role

The chart does not create cloud identities. Give each ServiceAccount its own role; the least-privilege
tables are in the Terraform READMEs, [AWS](../../terraform/aws/README.md#role-to-permission-table) and
[GCP](../../terraform/gcp/README.md). In short: `api` writes the source bucket and a little of the
delivery bucket and wraps and unwraps keys; `edge` reads delivery, writes uploads to source and only
unwraps; `worker` reads source, writes delivery and wraps and unwraps. Every role also needs read and
list on both buckets for the readiness probe. The masker needs none. With IAM roles, set the S3 and
KMS credential variables to empty strings in `config` (as `ci/default-values.yaml` does) so the SDK
default chain is used; leaving them unset is refused in production.

## Values reference

| Key | Default | Meaning |
| --- | --- | --- |
| `image.{server,worker,masker}.{repository,tag,digest}` | GHCR names, tag = `appVersion` | Images; a digest wins over the tag. |
| `image.pullPolicy`, `imagePullSecrets` | `IfNotPresent`, `[]` | |
| `config` | `CIPHERFRAME_ENV=production`, log level, bucket and URL placeholders | Non-secret `CIPHERFRAME_*` and `OTEL_*` variables for every pod and the migration Job. Quote values. |
| `secrets` | database URL, peppers | Secret variables as `NAME: {name, key}`, for every pod and the Job. |
| `podSecurityContext`, `containerSecurityContext` | non-root 65532, read-only root, drop ALL, seccomp | |
| `<role>.enabled`, `.replicas`, `.port` | true, 2/2/1, 8080/8081/8082 | `<role>` is `api`, `edge` or `worker`. |
| `<role>.env`, `.secrets` | `{}`, playback keys for api and edge | Extra variables and secrets for one role, merged over the common ones. |
| `<role>.serviceAccount.annotations` | `{}` | IRSA or Workload Identity binding. |
| `<role>.resources`, `.nodeSelector`, `.tolerations`, `.affinity`, `.topologySpreadConstraints`, `.podAnnotations` | see values.yaml | Scheduling and sizing. |
| `<role>.pdb.{enabled,minAvailable}` | off, 1 | PodDisruptionBudget. |
| `api.autoscaling`, `edge.autoscaling` | off | CPU HPA. |
| `worker.workDir.sizeLimit` | `30Gi` | Size of the `/work` emptyDir. |
| `worker.terminationGracePeriodSeconds` | `30` | |
| `worker.masker.{enabled,databaseUrlSecret,env,resources}` | off | Face masker sidecar. |
| `worker.keda.*` | off | ScaledObject: counts, polling, `serverAddress`, `threshold`, `query`. |
| `migrate.{enabled,backoffLimit,activeDeadlineSeconds,resources}` | on, 2, 600, small | Migration hook Job. |
| `ingress.{api,edge}.{enabled,className,host,annotations,tls}` | off | Optional Ingresses; paths are fixed. |
| `serviceMonitor.{enabled,interval,labels}` | off | Needs the Prometheus Operator CRDs. |
| `networkPolicy.{enabled,ingressFrom,metricsFrom,egress}` | off | |

## Upgrade notes

- Upgrades run migrations first, while the previous version is still serving. The chart has no
  down migration, so treat a rollback after a migration as needing a release that tolerates the new
  schema, and read the release notes before upgrading across versions.
- Changing a Secret's content does not restart pods (the files update, the process does not re-read
  them). Restart the Deployments after rotating a pepper, playback key, KMS credential or metrics
  token (`kubectl rollout restart`). Rotation procedures are in usage.md and encryption.md.
- Turning an autoscaler on or off changes who owns `replicas`; the first upgrade after enabling it
  leaves the count to the autoscaler.
- With `--atomic` or `--wait`, a pre-upgrade migration that fails aborts before any pod changes.

## Checks

CI runs `helm lint`, `helm template` and `kubeconform -strict` (Kubernetes 1.30 schemas) on both
values files in `ci/`, and fails if an Ingress routes `/`, `/metrics`, `/healthz` or `/readyz`. The
ServiceMonitor and ScaledObject CRDs are skipped by kubeconform. A `kind` install smoke test is not
part of CI: it needs images that are not published yet (M9-6) and a Postgres, and would not stay
within a few minutes.
