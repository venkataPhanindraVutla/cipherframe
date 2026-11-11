# Docker Compose development stack

Postgres, SeaweedFS (private S3 buckets) and `cipherframe-server` for local development.

```sh
docker compose -f deploy/compose/compose.yaml up --build
```

Development only: every credential here is a public placeholder. See
[docs/usage.md](../../docs/usage.md#run-locally-with-docker-compose) for services, ports, reset and
limits.
