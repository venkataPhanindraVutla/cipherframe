# Docker Compose development stack

Postgres, SeaweedFS (private S3 buckets) and `cipherframe-server` for local development.

```sh
docker compose -f deploy/compose/compose.yaml up --build
```

With the `worker` profile (`--profile worker`) it also starts the worker, the face masker and the
shared work volume they need (see [docs/usage.md](../../docs/usage.md#face-masking)).

With the `observability` profile and `compose.observability.yaml` it also starts an OpenTelemetry
Collector, Prometheus and Grafana and points the services at them; a plain `up` starts none of that
(see [deploy/observability/README.md](../observability/README.md)).

Development only: every credential here is a public placeholder. See
[docs/usage.md](../../docs/usage.md#run-locally-with-docker-compose) for services, ports, reset and
limits.
