# Usage

> Status: skeleton (M0-4). Nothing is runnable yet.

## Planned flow

1. Start the stack locally with Docker Compose and MinIO (M1-8). No cloud account is needed.
2. Create an API key for your application.
3. Upload a source video (S3 multipart or tus) and commit it.
4. Wait for the asset to become `ready`.
5. From your server, create a playback session for a viewer you have authorized.
6. Load the returned manifest URL in the reference player.
7. Revoke the session to stop playback at the key endpoint.
8. Delete the asset and fetch its signed deletion record.
9. Verify the record with the public-key-only verifier.

The `cipherframe` CLI (M8-1) covers each step.

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
