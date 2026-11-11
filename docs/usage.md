# Usage

> Status: skeleton (M1-6). `cipherframe-server` starts and serves health and readiness; the rest of
> the flow below is planned.

## Planned flow

1. Start the stack locally with Docker Compose and SeaweedFS (M1-8, ADR 0014). No cloud account is needed.
2. Create an API key for your application.
3. Upload a source video (S3 multipart or tus) and commit it.
4. Wait for the asset to become `ready`.
5. From your server, create a playback session for a viewer you have authorized.
6. Load the returned manifest URL in the reference player.
7. Revoke the session to stop playback at the key endpoint.
8. Delete the asset and fetch its signed deletion record.
9. Verify the record with the public-key-only verifier.

The `cipherframe` CLI (M8-1) covers each step.

## Running the server

`cipherframe-server` is one binary with three roles (ADR 0008). Choose the roles with `--role`, a
comma-separated list of `api`, `edge` and `worker`:

```sh
export CIPHERFRAME_DATABASE_URL=... CIPHERFRAME_S3_SOURCE_BUCKET=... # see Configuration below
cipherframe-server migrate                    # apply database migrations and exit
cipherframe-server --role=api                 # control plane on CIPHERFRAME_API_LISTEN
cipherframe-server --role=edge                # data plane on CIPHERFRAME_EDGE_LISTEN
cipherframe-server --role=worker              # background jobs (idle until the queue lands)
cipherframe-server --role=api,edge,worker --migrate   # everything in one process (development)
```

| Flag or command | Meaning |
| --- | --- |
| `--role` | Required. `api`, `edge`, `worker` or a comma-separated list. An unknown or repeated role is an error. |
| `--migrate` | Apply pending database migrations before serving. **Default off.** |
| `migrate` | Subcommand: apply pending migrations and exit. Takes no other arguments. |
| `admin bootstrap` | Subcommand: create the first tenant, client and admin key (see below). |
| `admin pepper-usage` | Subcommand: print active API-key counts per pepper version. |

On start the server loads the configuration (stopping with the variable names, never values, if it
is invalid), connects to the database, refuses PostgreSQL older than version 16, and then, only with
`--migrate`, applies migrations. Migrations are serialised with a Postgres advisory lock, so several
instances started with `--migrate` at once are safe. For a deployment with many replicas, prefer
running `migrate` once as a separate step.

On start the server also refuses to serve if an active API key was hashed with a pepper version
that is not in `CIPHERFRAME_API_KEY_PEPPERS` (ADR 0016); the error names version numbers only.

It also builds the key-provider registry before connecting to the database, so a misconfigured
provider stops the process at once with a message that names the setting (see
[Encryption](encryption.md)). For local development use the built-in `local` provider with a
placeholder KEK (32 decoded bytes, starting with `dev-placeholder-`):

```sh
export CIPHERFRAME_KMS_PROVIDER=local
export CIPHERFRAME_KMS_LOCAL_KEKS=1:ZGV2LXBsYWNlaG9sZGVyLTAxMjM0NTY3ODlhYmNkZWY=
export CIPHERFRAME_KMS_LOCAL_KEK_CURRENT=1
```

The Docker Compose stack (M1-8) is not in the repository yet. When it lands, its shared environment
block must carry these three variables, so the stack runs without a cloud account (ADR 0019).

### First tenant and admin key

After migrating, create the first tenant, client and admin key (all five scopes) in one transaction:

```sh
ADMIN_KEY="$(cipherframe-server admin bootstrap --tenant-name "Acme" --client-name "Main app")"
```

The key is the **only** thing written to stdout; the tenant, client and key IDs go to the JSON log on
stderr. The full key is shown once and is not stored: keep it in a secret store. Use it to create
further clients and keys through the API (see [api.md](api.md)); then prefer narrower keys for
day-to-day work. The command needs the same database and pepper configuration as the server, and
every run creates a new tenant.

To see which pepper versions active keys still use (for example before removing an old pepper):

```sh
cipherframe-server admin pepper-usage
# version 1: 2 active keys
# version 2: 5 active keys (current)
```

Each HTTP listener has a 10 second header-read timeout, a 30 second read timeout, a 60 second
write timeout, a 120 second idle timeout and a 32 KiB header limit. Logs are JSON on stderr at
`CIPHERFRAME_LOG_LEVEL`.

**Shutdown.** `SIGINT` or `SIGTERM` stops accepting connections, lets in-flight requests finish for
up to 25 seconds, then closes the rest and exits. A second signal terminates immediately. The
`worker` role currently logs that no job kinds are registered and waits for the signal.

**Health.** `GET /healthz` (liveness) and `GET /readyz` (readiness: database, source bucket,
delivery bucket) are served on both the api and edge listeners. See [api.md](api.md).

### What running the server does not protect against

- `/healthz` and `/readyz` are public by design. They reveal that the service is up and the names
  and pass/fail of its dependency checks, nothing more (no host names, error text or credentials).
  Keep the api listener off the public internet.
- There is no authentication yet (API keys arrive with M1-7), and the server speaks plain HTTP: put
  a TLS-terminating proxy in front of both listeners.
- Running every role in one process (`--role=api,edge,worker`) removes failure isolation between
  them. It is meant for development; deploy roles separately in production (ADR 0008).

## Run locally with Docker Compose

This starts everything the server needs on your machine, with no cloud account.

**Prerequisites:** Docker with Compose v2 (`docker compose version`), and free ports 8080, 8081 and
8333 on `127.0.0.1`.

```sh
docker compose -f deploy/compose/compose.yaml up --build
```

| Service | What it does | Host port |
| --- | --- | --- |
| `postgres` | PostgreSQL 18.6 (ADR 0017) with a named volume. | none |
| `seaweedfs` | SeaweedFS 4.53 with its S3 gateway (ADR 0014). One development identity, no anonymous access. | `127.0.0.1:8333` |
| `storage-init` | One-shot. On every `up` it creates the `cipherframe-source` and `cipherframe-delivery` buckets if missing and checks that an anonymous GET of each is refused (403). It exits non-zero otherwise, which stops `server` from starting. | none |
| `migrate` | One-shot `cipherframe-server migrate`, run once Postgres is healthy. | none |
| `server` | `cipherframe-server --role=api,edge,worker`. | api `127.0.0.1:8080`, edge `127.0.0.1:8081` |

Check it: `curl http://127.0.0.1:8080/readyz` and `curl http://127.0.0.1:8081/readyz` list the
`database`, `queue`, `storage_source` and `storage_delivery` checks, all `ok`.

SeaweedFS is published on the host because presigned URLs are signed for
`CIPHERFRAME_S3_PUBLIC_ENDPOINT` (`http://localhost:8333`) and must be usable from your browser, while
the server itself talks to `http://seaweedfs:8333` inside the Compose network.

**Reset.** `docker compose -f deploy/compose/compose.yaml down` stops the stack and keeps the data;
adding `-v` also deletes the Postgres and SeaweedFS volumes. Run `up` again afterwards. Use `--build`
after changing Go code to rebuild the image.

**Images.** `build/Dockerfile` builds the `cipherframe-server` image: a static binary on
`distroless/static` as a non-root user, with no shell. It serves the api and edge roles and contains
no FFmpeg (ADR 0008). The separate worker image with FFmpeg arrives with M3 (FFmpeg build and
licensing is gate P8). Until then no job kind needs FFmpeg, so the Compose `server` service runs the
worker role from the same image. Build it alone with
`docker build -f build/Dockerfile --build-arg VERSION=dev -t cipherframe-server .`.

**Secrets.** Every credential in `deploy/compose/` is a public development placeholder (the
`dev-placeholder-` prefix): the Postgres password, the S3 access key and secret, and the API key
pepper. The stack sets `CIPHERFRAME_ENV=development`, the only mode that accepts them; with
`production` the server refuses to start on any of them (ADR 0013).

### What this setup does not protect against

- It is for development only and is not hardened. Do not use it, its credentials or its volumes for
  real data or on a shared or public host.
- The credentials are public: anyone who can reach the published ports can use them. The ports are
  bound to `127.0.0.1` so only your machine can, and that stops being true if you edit the bindings.
- The buckets are private only in that SeaweedFS refuses unsigned requests. Anyone with the
  placeholder S3 credentials can read and write them.
- Traffic is plain HTTP, the database connection has TLS off, and the containers have no resource
  limits.
- There is no authentication on the Cipherframe endpoints yet (API keys arrive with M1-7).

## Configuration

Cipherframe reads only `CIPHERFRAME_*` environment variables (ADR 0013). They are parsed once at
startup into one validated struct. Every problem is reported together, and each message names the
variable, never its value.

| Variable | Default | Required | Secret | Notes |
| --- | --- | --- | --- | --- |
| `CIPHERFRAME_ENV` | `development` | no | no | `development` or `production`. |
| `CIPHERFRAME_LOG_LEVEL` | `info` | no | no | `debug`, `info`, `warn` or `error`. |
| `CIPHERFRAME_API_LISTEN` | `:8080` | no | no | `host:port`, port 1-65535. |
| `CIPHERFRAME_EDGE_LISTEN` | `:8081` | no | no | `host:port`, port 1-65535. |
| `CIPHERFRAME_DATABASE_URL` | none | yes | yes | `postgres://` or `postgresql://` URL. |
| `CIPHERFRAME_S3_ENDPOINT` | empty (provider default) | no | no | Absolute `http(s)` URL. |
| `CIPHERFRAME_S3_PUBLIC_ENDPOINT` | the endpoint | no | no | Absolute `http(s)` URL used by browsers. |
| `CIPHERFRAME_S3_REGION` | `us-east-1` | no | no | |
| `CIPHERFRAME_S3_FORCE_PATH_STYLE` | `false` | no | no | Go `strconv.ParseBool` values. |
| `CIPHERFRAME_S3_SOURCE_BUCKET` | none | yes | no | Valid S3 bucket name (3-63 chars, lowercase letters, digits, `-`, `.`). |
| `CIPHERFRAME_S3_DELIVERY_BUCKET` | none | yes | no | Same rules; must differ from the source bucket. |
| `CIPHERFRAME_S3_ACCESS_KEY_ID` | unset | production: yes | yes | Credential, see below. Both S3 credentials must be in the same state. |
| `CIPHERFRAME_S3_SECRET_ACCESS_KEY` | unset | production: yes | yes | Credential, see below. |
| `CIPHERFRAME_API_KEY_PEPPERS` | none | yes | yes | Comma-separated `version:base64`. Versions are unique positive integers; each decoded pepper is at least 32 bytes (standard base64). |
| `CIPHERFRAME_API_KEY_PEPPER_CURRENT` | none | yes | no | Positive integer naming a version in the set. |
| `CIPHERFRAME_KMS_PROVIDER` | `local` in development | production: yes | no | Key provider that wraps content keys: `local`, `vault`, `awskms` or `gcpkms`. `local` is **development-only**: production requires an explicit provider other than `local` and refuses to start otherwise. `local` and `awskms` are implemented (Docker Compose uses `local` with a `dev-placeholder-` KEK); `vault` and `gcpkms` are reserved names that fail at startup until their M2-2 tasks land (ADR 0019, ADR 0022). |
| `CIPHERFRAME_KMS_LOCAL_KEKS` | none | with `local` | yes | Comma-separated `version:base64`. Versions are unique positive integers; each decoded KEK is **exactly 32 bytes** (standard base64). `_FILE` is supported. Values starting with `dev-placeholder-` are accepted only in development. Ignored unless the provider is `local`. |
| `CIPHERFRAME_KMS_LOCAL_KEK_CURRENT` | none | with `local` | no | Positive integer naming the version in the set that new wraps use. Older versions stay for unwrapping. |
| `CIPHERFRAME_KMS_VAULT_*` | | | | **Stub.** Vault Transit settings arrive with M2-2 (ADR 0021). |
| `CIPHERFRAME_KMS_AWS_KEY_ID` | none | with `awskms` | no | The KEK: a KMS key ARN, an alias ARN or `alias/name` (a bare key id is refused). Ignored unless the provider is `awskms`. |
| `CIPHERFRAME_KMS_AWS_REGION` | none | with `awskms` | no | AWS region of the key, for example `eu-west-1`. |
| `CIPHERFRAME_KMS_AWS_ENDPOINT` | empty (AWS default) | no | no | Absolute `http(s)` URL, for a VPC endpoint or a KMS-compatible server. |
| `CIPHERFRAME_KMS_AWS_ACCESS_KEY_ID` | unset | production: yes | yes | Credential, same rules as the S3 pair: set = static key pair, empty = the AWS SDK default chain (preferred in production), unset = refused in production and the default chain in development. Both must be in the same state. |
| `CIPHERFRAME_KMS_AWS_SECRET_ACCESS_KEY` | unset | production: yes | yes | Credential, see above. |
| `CIPHERFRAME_KMS_AWS_TIMEOUT` | `5s` | no | no | Go duration, above zero and at most `5m`. Bounds every KMS call including SDK retries. |
| `CIPHERFRAME_KMS_GCP_*` | | | | **Stub.** GCP KMS settings arrive with M2-2. |

Empty values of non-secret variables mean "use the default".

### The `_FILE` rule

Every secret variable `X` also accepts `X_FILE`, a path whose contents are the value. One trailing
`\n` or `\r\n` is removed. Setting both `X` and `X_FILE` is an error, and so is a file that cannot be
read (the message names `X_FILE`, not the path or contents). Use it with Docker or Kubernetes
secrets, for example `CIPHERFRAME_DATABASE_URL_FILE=/run/secrets/database_url`.

### Development and production

- `development` allows development placeholders: a secret value starting with `dev-placeholder-`
  (for a pepper, the **decoded** bytes) is accepted.
- `production` refuses to start if any required secret is missing, if any secret is a placeholder
  (for the database URL, the whole value or the password part), or if either S3 credential is unset.
  An invalid `CIPHERFRAME_ENV` is itself an error and is checked as if it were `production`.

### Credential states

`CIPHERFRAME_S3_ACCESS_KEY_ID` and `CIPHERFRAME_S3_SECRET_ACCESS_KEY` have three states that are
never merged:

| State | How to set it | Meaning |
| --- | --- | --- |
| `unset` | variable absent | Development default. Rejected in `production`. |
| `provider_chain` | variable present but empty | Use the cloud SDK's default credential chain, such as an instance role. |
| `static` | non-empty value | Use exactly this key pair. |

### In code

`config.Load` / `config.FromOS` return a `*config.Config`. Secrets are `config.Secret`, whose
`Reveal()` is the only way to read the value; its string, `fmt`, JSON, text and `slog` forms all print
`[redacted]`. Logging the config (`slog.Info("config", "config", cfg)`) shows the effective settings
with secrets redacted and credentials reduced to their state. A `Secret` stays redacted even inside an
unexported struct field: its value is held in a closure, so `fmt`'s reflection fallback prints a
function address, not the value. Compare secrets with `Equal`, not `==`.

### What configuration handling does not protect against

- Anyone who can read the process environment (`/proc/<pid>/environ`, `docker inspect`, a crash dump)
  or the `_FILE` files can read the secrets. Restrict those with file permissions and your platform's
  secret store.
- Redaction covers the types in this package. A secret copied out with `Reveal()` into a plain string
  can still be printed by careless code.
- Placeholder detection is a prefix check. It stops the shipped development values from reaching
  production, not a weak value an operator chose.

## What this does not protect against

See [threat-model.md](threat-model.md#out-of-scope).
