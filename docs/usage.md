# Usage

> Status: pre-release (`v0.1.0-rc.2`). Every step below works against the local Compose stack; see the
> [roadmap](roadmap.md) for what is not yet verified on real infrastructure.

## The flow

1. Start the stack locally with Docker Compose and SeaweedFS (M1-8, ADR 0014). No cloud account is needed.
2. Create an API key for your application.
3. Upload a source video (S3 multipart or tus) and commit it.
4. Wait for the asset to become `ready`.
5. From your server, create a playback session for a viewer you have authorized.
6. Hand the session response to the reference player ([`player/`](../player/README.md), M8-2).
7. Revoke the session to stop playback at the key endpoint.
8. Delete the asset and fetch its signed deletion record.
9. Verify the record with the public-key-only verifier.

The `cipherframe` CLI (M8-1) covers each step.

## The command line tool

`cipherframe` is one static binary (`CGO_ENABLED=0 go build -o cipherframe ./cmd/cipherframe`). The
commands below follow the curl walkthrough of the stack: they create the asset, upload through the
edge with the resumable tus protocol and commit. Conventions are in [ADR 0051](adr/0051-cli-conventions.md).

```sh
export CIPHERFRAME_SERVER=http://127.0.0.1:8080          # the api listener
export CIPHERFRAME_API_KEY="$(cat key.txt)"               # or --api-key-file key.txt; never a flag value

id=$(cipherframe upload clip.mp4 --wait)                  # create, tus upload, commit, wait until ready
cipherframe status "$id"                                  # ast_...  ready
cipherframe inspect "$id"                                 # the full asset document (JSON)
cipherframe list --limit 20 [--cursor C]                  # one page; prints the next cursor on stderr
cipherframe delete "$id" --wait > record.json             # waits, then prints the signed deletion record
cipherframe verify --deletion-record record.json \
  --keys-url "$CIPHERFRAME_SERVER/.well-known/cipherframe-keys.json"
cipherframe rekey "$id"                                   # queue a content-key re-key (see below)
```

- `upload FILE` takes `--mask-faces`, `--ttl 30d` (or `24h`), `--content-type`, `--wait` and
  `--wait-timeout`. It sends the size and a content type, never the file name. An interrupted
  transfer resumes from the server's offset within the same run. If the commit is refused after the
  bytes arrived (a quota, say), run `cipherframe process ID` once the cause is fixed.
- `rekey ID` queues the audited re-key of a ready asset and prints the job ID (see
  [Re-keying an asset](#re-keying-an-asset)). It has no `--wait`: read the result from the audit log.
- `--json` makes stdout one JSON document (the server's response) and errors one JSON object on
  stderr; progress always goes to stderr. `deletion-record ID` and `delete --wait` print the signed
  record in both modes.
- Problems show the stable `code` and the request ID, never the key. `cipherframe help COMMAND`
  lists a command's flags.

| Exit code | Meaning |
|---|---|
| 0 | success (verify: all ours) |
| 1, 2 | verify and verify-file only: modified, cannot say |
| 3 | usage error |
| 4 | the server refused the request (401, 403, 400, other 4xx, 500) |
| 5 | not found |
| 6 | conflict or quota (409, 429) |
| 7 | network error, timeout or server unavailable |
| 8 | `--wait` ended without success (asset failed, or the wait timed out) |

### Sessions, integrity, subtitles, brand, keys, webhooks

```sh
cipherframe session create "$id" [--viewer ID] [--variant masked] [--show-token]   # session, manifest URL, expiry, heartbeat
cipherframe session show SESSION_ID
cipherframe session revoke SESSION_ID                     # or --viewer V and/or --asset A (never tenant-wide)
cipherframe proof "$id" 720p/seg-0.m4s > proof.json       # then: cipherframe verify --proof proof.json ... FILE
cipherframe verify-file "$id" seg-0.m4s --path 720p/seg-0.m4s   # exit 0 ours, 1 modified, 2 cannot say
cipherframe subtitles import "$id" en.vtt --language en --label English --default   # .json = transcript
cipherframe subtitles list "$id" | delete "$id" SUBTITLE_ID
cipherframe brand set-logo logo.png --corner top_left --opacity 60 | show | remove
cipherframe keys rotate-api-key KEY_ID [--overlap 10m] > new-key.txt
cipherframe webhooks list --status dead | replay DELIVERY_ID | replay --endpoint ID --dead
cipherframe audit export [--since 2026-11-01T00:00:00Z] [--until T] > audit.ndjson   # admin scope
```

- `session create` prints the session ID, the manifest URL on the edge URL the API returned, the
  expiry and the heartbeat interval. The playback token is printed only with `--show-token` (stdout
  only); without it the token is also cut from `--json` and from a manifest URL that carries it
  (`token_transport` `url`). Without `--viewer` a random `cli-` viewer ID is used.
- `proof` prints the inclusion proof JSON exactly as `verify --proof` reads it. `verify-file` hashes
  the file locally and sends only the hash to `POST /v1/verify`; without `--path` it searches the
  tenant's artifacts by hash.
- `audit export` writes the tenant's audit events to stdout as NDJSON, one compact object per line,
  oldest first, following every page (`GET /v1/audit-events`, [api.md](api.md#audit-log-export-adr-0058)).
  `--since` is inclusive and `--until` exclusive (RFC 3339). Output is always NDJSON.
- `keys rotate-api-key` prints the new key alone on stdout, once, and warns on stderr that it will
  not be shown again; the old key works for `--overlap`.
- `subtitles import` reads WebVTT or SRT (the server checks and rewrites it) or, for a `.json` file,
  a transcript `{"cues":[{"start":0,"end":1.5,"text":"...","speaker":"..."}]}`.
- `brand` needs the `admin` scope and is not retroactive: it applies to assets processed afterwards.
- Not in the CLI because the API has no such call: `session list` (use `session show`, or revoke by
  viewer or asset) and `keys rewrap` (the KMS re-wrap is `cipherframe-server admin kms-rewrap`, see
  below).

CI runs `deploy/compose/cli-e2e.sh` against the development stack.

## Reference player (M8-2, ADR 0052)

`player/` holds `<cipherframe-player>`, a framework-free custom element on hls.js. Your backend creates the
session (the API key never goes to a browser) and gives the JSON answer to the page:

```html
<cipherframe-player id="p"></cipherframe-player>
<script type="module">
  import "@cipherframe/player"; // or the built dist/cipherframe-player.js
  p.load(await (await fetch("/my-backend/play/ast_...")).json()); // the session response, unchanged
</script>
```

The player sends the token on every playlist, key and segment request, heartbeats on the session's
interval (each heartbeat returns the next token), stops when the edge answers `401` or `403`, and draws the
overlay watermark ([ADR 0048](adr/0048-overlay-watermark-policy.md)). The tenant must list the page's origin
in `allowed_origins` ([api.md](api.md#playlists-and-segments-on-edge-adr-0027-0030)). Usage, events and styling
are in [player/README.md](../player/README.md).

To try it on the development stack: build the demo (`pnpm build:demo`, then `pnpm preview:demo`, port 4173),
add `http://localhost:4173` to `allowed_origins`, create a session and open
`http://localhost:4173/#<base64url of the session JSON>`.

## Verifying files offline

`cipherframe verify` checks downloaded HLS files against a signed manifest with public keys only
(ADR 0039, [integrity.md](integrity.md#verifying)). Build it with `CGO_ENABLED=0 go build -o cipherframe ./cmd/cipherframe`.

```sh
cipherframe verify --manifest manifest.json --keys keys.json ./download/   # exit 0 ours, 1 modified, 2 cannot say
cipherframe verify --manifest manifest.json --keys keys.json --timestamp ts.json --tsa-ca ca.pem ./download/   # also checks the RFC 3161 token
```

Traces and OTLP metrics are configured with the standard `OTEL_EXPORTER_OTLP_*` variables, not
`CIPHERFRAME_*` ones; see [observability.md](observability.md).

## Re-keying an asset

Re-keying encrypts every segment of an asset again under a freshly generated content key, signs the
integrity manifest again and destroys the old key (M10-4, [ADR 0068](adr/0068-content-key-rekey.md)).
Do it when a content key may have leaked. It is explicit and per asset; nothing re-keys on its own.

```sh
cipherframe rekey "$id"                    # asset_id  re-key queued (job 123)
cipherframe audit export | grep asset.rekey  # asset.rekey_requested, then _completed or _failed
```

The API is `POST /v1/assets/{asset_id}/rekey` (scope `assets:write`, no body) and answers `202` with
`{"asset_id": "...", "job_id": 123}`. An asset that is not `ready` is `409 asset_not_ready`; one that
is being deleted, whose masked variant is still being made, or that already has a re-key waiting or
running is `409 conflict`; another tenant's asset and a deleted one are `404 not_found`. A re-key that
failed for good (the audit log shows `asset.rekey_failed`) can be requested again.

- The asset keeps playing under its old key until the switch, which is one database transaction. A
  failed or interrupted attempt changes nothing and is retried by the worker.
- **Viewers who were playing during the switch** cannot fetch a key any more (`401`) and their old
  segments are deleted: the player must start a new session. Sessions started afterwards use the new
  key. With a CDN configured, the asset's CDN purge is queued with the switch.
- The manifest is signed again (and timestamped again when anchoring is on). `cipherframe verify`
  works with the new manifest and the new files; the old manifest does not match the new bytes.
- The worker needs enough storage for both copies of the segments until the old ones are deleted at
  the end of the job.
- **What it does not do:** it does not help against plaintext, or keys, that a viewer already saved,
  and it does not make ciphertext copied earlier unreadable to someone who holds the old key. Bucket
  versions and backups taken before the re-key still hold the old ciphertext and (in the database
  backup) the old wrapped key. See [the threat model](threat-model.md#content-key-re-key-m10-4-adr-0068).

## Processing a failed asset again

An asset fails for good when the file is not usable, but also when something around it broke for longer
than the retries last: the object store, the key service, a worker that ran out of memory. Those
assets can run again from the original you uploaded, without uploading it again (H-4).

```sh
cipherframe reprocess "$id" --wait         # asset_id  ready (or exit 8 when it fails again)
cipherframe audit export | grep asset.reprocess_requested
```

The API is `POST /v1/assets/{asset_id}/reprocess` (scope `assets:write`, no body) and answers `202` with
the asset, now `committed`. Only a `failed` asset is accepted (`409 asset_not_failed` otherwise), and
only while its original is still stored (`409 source_unavailable` otherwise: upload the video again).
The new run starts clean, uses the same content key, sends the normal `asset.ready` or `asset.failed`
webhook and counts against the transcode minutes again. See [api.md](api.md#assets-and-uploads-adr-0025-0026).

## Running the server

`cipherframe-server` is one binary with three roles (ADR 0008). Choose the roles with `--role`, a
comma-separated list of `api`, `edge` and `worker`:

```sh
export CIPHERFRAME_DATABASE_URL=... CIPHERFRAME_S3_SOURCE_BUCKET=... # see Configuration below
cipherframe-server migrate                    # apply database migrations and exit
cipherframe-server --role=api                 # control plane on CIPHERFRAME_API_LISTEN
cipherframe-server --role=edge                # data plane on CIPHERFRAME_EDGE_LISTEN
cipherframe-server --role=worker              # background jobs (kms.rewrap)
cipherframe-server --role=api,edge,worker --migrate   # everything in one process (needs ffmpeg and ffprobe: use the worker image)
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

The `api` and `worker` roles also make sure the deployment has an integrity signing key (M5-2). The
first one to start creates it, wrapped by the key provider; concurrent starts create exactly one, and
a start with the key provider down stops with an error that says so. There is no new environment
variable: the keys use the same provider and KEK as content keys. The `edge` role only publishes the
public keys (`/.well-known/cipherframe-keys.json`) and does not need the key provider for that.
Rotate and retire keys through the API (see [api.md](api.md#integrity-signing-keys-adr-0033)).

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

### Key rotation and re-wrap

Content keys are wrapped by a key-encryption key (KEK). After changing the KEK version or the key
provider, move the stored keys to the current KEK with the `kms.rewrap` job. A `worker` role process
must be running to do the work; the commands below are the trigger (an HTTP trigger belongs to the
operator API, which is a later decision):

```sh
cipherframe-server admin kms-usage
# provider=local kek_id=local version=1: 120 content keys
# provider=local kek_id=local version=2: 8 content keys

cipherframe-server admin kms-rewrap --wait            # prints the job id on stdout
cipherframe-server admin kms-rewrap --batch-size 250  # keys per run: 1-1000, default 100
```

`kms-rewrap` enqueues the job and prints its id (the only thing on stdout). With `--wait` it polls
every 2 seconds until no content key is left on a KEK other than the current one, printing counts to
stderr, and exits with an error if the job lands in the dead-letter list. Interrupting `--wait` does
not stop the job. `kms-usage` prints counts only, never key material.

At startup every role refuses to run if a stored content key was wrapped by a provider that is not
configured, or (for `local`) by a KEK version that is no longer in `CIPHERFRAME_KMS_LOCAL_KEKS`. The
message names the provider and version only. See [encryption.md](encryption.md) for the full
procedure.

Each HTTP listener has a 10 second header-read timeout, a 30 second read timeout, a 60 second
write timeout, a 120 second idle timeout and a 32 KiB header limit. Logs are JSON on stderr at
`CIPHERFRAME_LOG_LEVEL`.

**Shutdown.** `SIGINT` or `SIGTERM` stops accepting connections, lets in-flight requests finish for
up to 25 seconds, then closes the rest and exits. A second signal terminates immediately. The
`worker` role works the `kms.rewrap` and `asset.delete` job kinds (and the media kinds); a job that is
running when shutdown starts gets 20 seconds to finish and is otherwise retried later.

**Keys on edge.** The `edge` role serves the content key to players (`GET /v1/play/{session_id}/key`, see [api.md](api.md#the-key-endpoint-adr-0027-0028)), so it needs the same key provider settings as the other roles (`CIPHERFRAME_KMS_*`, below) and refuses to start without them. It also needs `CIPHERFRAME_PLAYBACK_TOKEN_KEYS`.

**Health.** `GET /healthz` (liveness) and `GET /readyz` (readiness: database, source bucket,
delivery bucket) are served on both the api and edge listeners. See [api.md](api.md).

### Uploads

The `api` role needs `CIPHERFRAME_EDGE_PUBLIC_URL`; the `edge` role serves the upload endpoints
(`/v1/uploads/tus/` and `/v1/uploads/multipart/…`, see [api.md](api.md#assets-and-uploads-adr-0025-0026)).
Both roles need the source bucket. The edge role opens a second, dedicated pool of up to 16 database
connections for tus upload locks (one per active upload request, so at most 16 concurrent tus writes
per edge replica; further requests wait for a lock). Size Postgres `max_connections` for the main
pools plus 16 per edge replica, and
tus parks incoming data on local disk until a part is complete: provide temporary space of about three
`CIPHERFRAME_UPLOAD_PART_BYTES` per concurrent tus upload. Put a reverse proxy in front of the edge
with request and response timeouts of at least several minutes for these paths, and do not buffer
request bodies there.

### Variants: face-masked playback (ADR 0036)

Create the asset with `"mask_faces": true` to get a second, face-masked variant next to the original.
The asset becomes `ready` with its original variant as usual and records `masking.state: pending`;
the `asset.mask` job, which runs beside `asset.process`, publishes the masked variant (see [Face masking](#face-masking)) and the state
becomes `ready`, or `failed` with the original unaffected. Playback sessions are bound to one variant. For a masking asset the default is `masked`,
and your server must ask for `"variant": "original"` to play the original. For browser-started
sessions the viewer cannot choose: put an optional `variant` claim in the JWT you sign, or approve the
`variant` that the signed callback body names; a request body `variant` that differs is `403`. See
[api.md](api.md#assets-and-uploads-adr-0025-0026) and
[api.md](api.md#browser-started-sessions-jwt-and-signed-callback-adr-0029-0031).

### Face masking

Masking needs a second process next to the worker: the masker, a Python worker (`ml/`,
[ml/README.md](../ml/README.md)) that claims `media.mask_faces` tasks from the hand-off table. Without
a masker, an asset created with `mask_faces` still becomes `ready` and playable as the original; its
`asset.mask` job waits for `CIPHERFRAME_WORKER_MASK_TIMEOUT` (default 2 hours), then marks the masked
variant `failed`.

How a masking asset flows ([ADR 0037](adr/0037-faster-face-masking.md)):

1. Committing the upload enqueues `asset.process` (on the `media` queue) and, in the same
   transaction, `asset.mask` (on the `mask` queue), so the two run side by side. `masking.state` is
   `pending` from the start.
2. `asset.mask` downloads the source into its own job directory under `CIPHERFRAME_WORK_DIR`
   (`job-mask-*`), writes a `media.mask_faces` task whose payload names `<job dir>/source` and
   `<job dir>/masked.mp4` relative to the work directory, and waits.
3. The masker reads the source from the shared work directory, blurs every face and writes
   `masked.mp4` next to it (to a `.part` file first, then renamed), then records the result.
4. `asset.mask` runs `masked.mp4` through the same ladder, segmenter and encryptor as the original,
   under the masked variant's own content key, publishes it under `masked/hls/`, adds it to the
   asset's signed manifest ([integrity.md](integrity.md#the-masked-variant)) and sets `masking.state`
   to `ready` with `faces_detected`, all in one transaction. The job directory, with the plaintext
   source and the masked file, is removed whatever the outcome.

If the masker fails the task for good, does not answer within the timeout, or the masked file cannot
be transcoded, `masking.state` becomes `failed`, any partial masked objects are removed, and the
original variant stays ready and playable. A masked session for an asset whose masking is not `ready`
gets `409 variant_not_ready`; it never falls back to the original. A retryable failure of the job
itself (a storage outage, say) is retried with the usual backoff and starts by clearing the masked
prefix. The source object stays in the source bucket until the asset is deleted, so masking can re-read
it.

**Run it with Docker Compose.** The `worker` profile starts the worker, the masker and what they share:

```sh
docker compose -f deploy/compose/compose.yaml --profile worker up --build
```

The masker image is built from `ml/Dockerfile` with the worker image as its FFmpeg source (the first
build also compiles FFmpeg, which takes minutes, and downloads the face detection model). The two
containers share the named volume `work`, mounted at `/work` as `CIPHERFRAME_WORK_DIR`, and both run
as UID 65532.

**Run it without Compose.** Run the masker on the same host as the worker, with the same work
directory:

```sh
export CIPHERFRAME_WORK_DIR=/var/lib/cipherframe/work    # the worker's directory, same path
export CIPHERFRAME_ML_DATABASE_URL_FILE=/run/secrets/masker-db-url
cipherframe-ml mask-worker                                # see ml/README.md
```

Requirements, none of which can be skipped:

- **Same machine, same directory.** The plaintext source and the masked file may only exist on the
  worker's local disk (ADR 0027, ADR 0036). The masker therefore cannot run on another machine; a
  deployment that needs that needs a different hand-off for plaintext, which is a new decision.
- **Same UID, no wider modes.** The worker creates each job directory with mode 0700 and the source
  file with mode 0600, so the masker must run as the same user as the worker (the images use UID
  65532). Do not loosen the modes or share the directory with other users to make it work; fix the
  user instead. A masker running as another user cannot read the source, its tasks fail
  and masking ends as `failed`.
- **A limited database role.** The masker connects with a role that can only read and update
  `external_tasks` (the grants are in [spec/jobs/README.md](../spec/jobs/README.md); the Compose stack
  creates `cipherframe_masker` from `deploy/compose/masker-role.sql`, a script rather than a migration
  because a role is cluster-wide and carries a password that belongs to the deployment).
- **Queues and speed.** `asset.mask` runs on its own `mask` queue (`CIPHERFRAME_WORKER_MASK_CONCURRENCY`,
  default 1), so it never blocks `asset.process`, and it starts when the upload is committed instead of
  when the original is ready. The masked variant is published only after the original is `ready`; if
  the asset fails or is deleted first, masking ends as `failed` and leaves nothing behind. On a
  42 s 720p recording the masked variant used to be ready after the sum of the two (about 85 s: 22 s
  for the original, then 41 s masker and 21 s transcode); it is now ready after about the longer of
  the two, with the original still ready at about the same time when cores allow. Set
  `CIPHERFRAME_WORKER_LADDER_HEIGHTS` (for example `720,360`) to transcode fewer rungs in both variants.
  `CIPHERFRAME_WORKER_X264_PRESET=veryfast` (worker) and `CIPHERFRAME_ML_DETECT_EVERY=2` (masker) cut
  it further: together they target about 30 to 40 s on that recording on an 8-CPU Docker host (85 s
  before ADR 0037, 62 s after it). Trade-offs: `veryfast` gives lower quality per bit, bounded by the
  existing rate caps; with a stride of 2 a fast-moving face can be one frame behind its box, which the
  25 % padding and the 1 s hold cover. See [ADR 0038](adr/0038-encoder-preset-and-detection-stride.md).
- **Disk.** A masking job needs the source plus the masked file (re-encoded at a high quality, so
  often larger than the source) plus the transcode output: plan for several times the source size in
  `CIPHERFRAME_WORK_DIR` per concurrent masking job, on top of the media jobs that now run beside it.

Masking is a privacy aid, not a guarantee. Detection can miss profiles, small faces and heavily
occluded ones (ADR 0036). Voices are not changed.

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
| `server` | `cipherframe-server --role=api,edge`. | api `127.0.0.1:8080`, edge `127.0.0.1:8081` |
| `worker` | Profile `worker` only. `cipherframe-server --role=worker` from the worker image (FFmpeg inside), with the `work` volume at `/work` as `CIPHERFRAME_WORK_DIR`. | none |
| `masker` | Profile `worker` only. The face masker (`ml/`), built from the worker image's FFmpeg; shares the `work` volume with `worker` and runs as the same UID. See [Face masking](#face-masking). | none |
| `work-init` | Profile `worker` only, one-shot. Gives the `work` volume to UID 65532 with mode 0700 (a new volume is owned by root). | none |
| `masker-db-init` | Profile `worker` only, one-shot. Creates the masker's database role from `deploy/compose/masker-role.sql`. | none |

Check it: `curl http://127.0.0.1:8080/readyz` and `curl http://127.0.0.1:8081/readyz` list the
`database`, `queue`, `storage_source` and `storage_delivery` checks, all `ok`.

SeaweedFS is published on the host because presigned URLs are signed for
`CIPHERFRAME_S3_PUBLIC_ENDPOINT` (`http://localhost:8333`) and must be usable from your browser, while
the server itself talks to `http://seaweedfs:8333` inside the Compose network.

**CDN delivery.** A tenant can set `delivery` to `cdn` once the deployment has a CDN configured
(`CIPHERFRAME_CDN_*` above); the settings endpoint refuses it otherwise. Setup, revocation limits and
purge behaviour are in [cdn.md](cdn.md).

**Presigned delivery and CORS.** A tenant that sets `delivery` to `presigned` (docs/api.md) makes the
player fetch segments from `CIPHERFRAME_S3_PUBLIC_ENDPOINT` directly. A browser then needs the delivery
bucket to allow your page's origin to GET, so a CORS rule on the delivery bucket is required (it is
not needed for `proxy`, where edge answers CORS). Cipherframe does not manage bucket CORS: configure
it where you manage the bucket, with `GET` and `HEAD` for exactly the origins in the tenant's
`allowed_origins`. On the Compose stack, SeaweedFS accepts the S3 API call, so with the AWS CLI and
the development key pair from `compose.yaml`:

```sh
AWS_ACCESS_KEY_ID=dev-placeholder-access-key AWS_SECRET_ACCESS_KEY=dev-placeholder-secret-key \
  aws --endpoint-url http://localhost:8333 --region us-east-1 s3api put-bucket-cors \
  --bucket cipherframe-delivery --cors-configuration file://deploy/compose/seaweedfs/delivery-cors.json
```

`delivery-cors.json` allows `http://localhost:3000`; edit the origin to match your page. The stack
does not apply it for you.

**Reset.** `docker compose -f deploy/compose/compose.yaml down` stops the stack and keeps the data;
adding `-v` also deletes the Postgres and SeaweedFS volumes. Run `up` again afterwards. Use `--build`
after changing Go code to rebuild the image.

**Images.** `build/Dockerfile` builds the `cipherframe-server` image: a static binary on
`distroless/static` as a non-root user, with no shell. It serves the api and edge roles and contains
no FFmpeg (ADR 0008). Build it alone with
`docker build -f build/Dockerfile --build-arg VERSION=dev -t cipherframe-server .`. The worker role
needs FFmpeg and runs from the separate worker image, see below; the Compose `worker` service is in
the `worker` profile so that `up` does not compile FFmpeg (`docker compose --profile worker up
--build` starts it).

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

### Processing and the work directory

The worker role handles `asset.process` jobs (enqueued when an upload is committed). Each job

- streams the source from the source bucket into `CIPHERFRAME_WORK_DIR/job-<random>/` while hashing it,
- transcodes it with one FFmpeg process into the same directory,
- encrypts each segment in memory and uploads it, then deletes the job directory,

and finishes with the asset `ready` or `failed` with
a `failure_code`: `invalid_media`, `transcode_failed`, `transcode_timeout`, `source_mismatch`,
`source_missing`, or `processing_failed` (storage or database problems that outlasted every retry).

**Disk.** Plan for **2 to 3 times the source size per concurrent job** in `CIPHERFRAME_WORK_DIR`:
the downloaded source, plus the plaintext segments of all renditions, which together are about the
size of the source for typical content (the ladder is capped at about 4.5, 2.5, 1.2, 0.7 and 0.35
Mbit/s) and at most a few times the capped rates for the length of the video. A worker process transcodes
`CIPHERFRAME_WORKER_MEDIA_CONCURRENCY` jobs at once (default 1), so size the volume for the
concurrency you allow or run fewer workers per node. The work
directory should be a dedicated volume, not shared with other users: during a job it holds plaintext
video.

**CPU and memory.** FFmpeg uses all cores it can get, one process per job. Segments are encrypted one
at a time in memory (a few megabytes). Set container CPU and memory limits.

**Crashes.** A job removes its directory when it ends, also on failure and on shutdown. If the process
is killed (for example `SIGKILL` or the kernel's out-of-memory killer) a `job-*` directory with
plaintext stays behind; use an ephemeral volume (such as a Kubernetes `emptyDir`) or clear the directory
when the worker starts.

## Media toolchain and your own FFmpeg

The worker role transcodes uploads with FFmpeg and inspects them with FFprobe, each as a **separate
process** started with an argument array (never a shell, never linked as a library). api and edge
never run them and start without FFmpeg installed.

**The worker image.** `build/worker.Dockerfile` builds `cipherframe-worker`: the server binary plus a
minimal, fully static FFmpeg 9.0.2 on `distroless/static` (no libc, no shell), running as non-root.

```sh
docker build -f build/worker.Dockerfile --build-arg VERSION=dev -t cipherframe-worker .
docker run --rm --entrypoint /usr/local/bin/ffmpeg cipherframe-worker -hide_banner -buildconf
```

The FFmpeg in it is configured with `--disable-everything --disable-network --disable-autodetect`
and only what ADR 0024 lists: `file` and `pipe` protocols; MP4/MOV and Matroska/WebM input; H.264,
HEVC, VP8, VP9, AV1 (through dav1d, because FFmpeg's own AV1 decoder needs a hardware accelerator),
AAC, Opus and MP3 decoding; libx264, libx265 (HEVC), SVT-AV1 (AV1) and AAC encoding; MP4 and HLS (fMP4) output; and the
`scale`, `format`, `aresample`, `null`, `anull`, `setsar`, `fps`, `split`, `transpose`, `hflip`,
`vflip`, `trim`, `setpts`, `tile`, `overlay` and `colorchannelmixer` filters (`split` fans the decoded frames out to one scaled branch per rendition; `transpose`, `hflip` and `vflip` apply a rotated phone video's display matrix; `trim`, `setpts` and `tile` make the thumbnails; `overlay` and `colorchannelmixer` draw the brand logo, which arrives as raw pixels through the `rawvideo` demuxer). Everything is pinned by
SHA-256 or digest. `/usr/share/licenses/ffmpeg/` holds the licence texts and `SOURCE.md`, the
written source offer with the exact sources and configure line. The image's `ENV` points
`CIPHERFRAME_FFMPEG_PATH` and `CIPHERFRAME_FFPROBE_PATH` at `/usr/local/bin`.

**HEVC and AV1 renditions (M10-3, off by default).** The worker image can also make HEVC (libx265) and AV1 (SVT-AV1)
renditions beside H.264. A tenant turns them on with `extra_codecs` in `PUT /v1/playback-settings` (`["hevc"]`,
`["av1"]` or both); it applies to assets uploaded afterwards, each codec adds a full ladder of renditions and the
master playlist lists all of them, H.264 first, so the player picks one it can decode. The settings call is
refused while no worker seen in the last 5 minutes can encode the codec (an operator's own FFmpeg may lack
`libx265` or `libsvtav1`; the worker starts anyway and reports what it has). An asset shows what it asked for and
what it did not get in `extra_codecs` (`requested`, `failed` with a reason). Storage, transcode time, the player
matrix and licensing are in [codecs.md](codecs.md).

**Hardware encoders (M10-2).** The static image above cannot use a GPU: libva and the NVIDIA runtime
load their drivers with `dlopen`. `docker build -f build/worker.Dockerfile --target worker-hw -t cipherframe-worker-hw .`
builds a second image with a dynamically linked FFmpeg that has the NVENC, VAAPI and QSV encoders of H.264, HEVC and AV1
(`h264_nvenc`, `hevc_vaapi`, `av1_qsv` and so on; Debian base, no `--enable-nonfree`). Set `CIPHERFRAME_WORKER_ENCODER` and give the container the device;
[hardware-encoders.md](hardware-encoders.md) has the setup per encoder and what was and was not measured.

**Rebuild the worker image after upgrading to the brand logo (M7-4, ADR 0049).** The startup check now
requires the `overlay` and `colorchannelmixer` filters and the `rawvideo` decoder and demuxer. A worker
image (or your own FFmpeg) built before that fails the check and the worker does not start; the message
names what is missing. Rebuild `cipherframe-worker` (or add those components to your FFmpeg) and roll the
worker before the api serves the logo endpoints to tenants.

**Startup check.** A process with the `worker` role runs `ffmpeg -buildconf`, `-encoders`,
`-decoders`, `-muxers`, `-demuxers`, `-protocols` and `-filters` before connecting to anything and
refuses to start if a required piece is missing. The error lists everything missing at once, for
example `missing encoder(s): libx264; missing muxer(s): hls`.

**Using your own FFmpeg.** Set `CIPHERFRAME_FFMPEG_PATH` and `CIPHERFRAME_FFPROBE_PATH`. Your build
needs libx264 and the native AAC encoder (and, only if you want HEVC or AV1 renditions, `libx265` or `libsvtav1`: the startup
check does not require them, the worker reports whether it has them); the `mp4` and `hls` muxers; the `mov` and `matroska`
demuxers; the H.264, HEVC, VP8, VP9, AAC, Opus and MP3 decoders and an AV1 decoder (`libdav1d` or
`libaom-av1`); the `file` and `pipe` protocols; and the filters above (including `split`). A distribution FFmpeg usually
has all of them. If something is missing the worker says so at startup. A full-featured FFmpeg is
a larger attack surface than the worker image's (see below), and H.264 patent licensing is your
concern, not Cipherframe's.

**Running the tests against real binaries.** The binaries are Linux binaries, so on a Mac the tests
run inside a Linux container; see [CONTRIBUTING.md](../CONTRIBUTING.md#media-and-pipeline-tests):

```sh
sh build/test-media.sh                                            # go test -tags=integration,media ./internal/...
sh build/test-media.sh -run TestPipeline -v ./internal/pipeline/  # only the pipeline tests
```

Fixtures are generated at test time by a test-only FFmpeg (the Dockerfile's `fixtures` stage, which
also has the `ssim` and `psnr` filters for quality measurements and is never shipped); no media files
are committed.

### What the media toolchain does not protect against

- **FFmpeg parses untrusted input.** The minimal build removes most demuxers, decoders, filters and
  network access, which narrows what a hostile file can reach, but H.264, HEVC, VP9, AV1 and
  Matroska/MP4 parsers remain and parser bugs have been exploited before. Run workers with least
  privilege: non-root, a read-only root file system, no network beyond object storage and the
  database, dropped capabilities, a seccomp profile, and CPU, memory, process and disk limits. The
  worker image is a distroless static image so there is no shell to land in, but that is not a
  sandbox. Keep FFmpeg updated; the pins are in `build/worker.Dockerfile`.
- Probe limits stop oversized sources early, but a file can still be expensive to decode. The
  transcode timeout and your container limits are the backstop.
- A file's metadata can lie. The duration limit uses what FFprobe reports before encoding; a file
  that decodes to something longer than it claims is cut off by the transcode timeout, not by the
  duration limit.
- The worker's own environment (database URL, key material) is **not** passed to FFmpeg: it runs
  with an empty environment. The process still runs as the same user, so file system and network
  access must be restricted outside Cipherframe.
- The worker image is GPL-licensed software (FFmpeg and x264) next to Apache-2.0 Cipherframe code.
  See `NOTICE` and the licence texts in the image.

## Terraform examples (M9-3, ADR 0056)

`deploy/terraform/aws` and `deploy/terraform/gcp` are example modules that create the buckets, one
identity per server role with least-privilege storage access, and the KMS key for the KEK. Each
README has the role to permission table and maps the outputs to the `CIPHERFRAME_S3_*` and
`CIPHERFRAME_KMS_*` variables below. CI only formats and validates them; the project never applies them.

## Helm chart (M9-2, ADR 0059)

`deploy/helm/cipherframe` runs the api, edge and worker roles on Kubernetes against an external
Postgres, with the migration as a hook Job, secrets mounted as `_FILE` files and optional Ingress,
ServiceMonitor, autoscaling and NetworkPolicy. Its README has the values reference, upgrade notes and
the cloud IAM each role needs. CI only renders and validates it; the project never installs it.

## Load tests (M9-4, ADR 0061)

`cmd/cipherframe-load` is a development tool, not part of a release. Its `play` mode ramps virtual
viewers that create sessions and fetch playlists, the key, segments and heartbeats as the reference
player does, in `proxy` or `presigned` delivery; its `transcode` mode times uploads to `ready`.
[load-tests.md](load-tests.md) has the method, the numbers and how to reproduce them. The API key
comes from `CIPHERFRAME_API_KEY` or `--api-key-file`, never a flag value, and the tool never writes a
token, session ID, key or URL. `play` sets the tenant's `delivery` setting for the run.

## Releases and verifying them (M9-6, ADR 0060)

Tagged releases publish the `cipherframe` CLI and the server as archives, and the `cipherframe-server`,
`cipherframe-worker` and `cipherframe-ml` images on ghcr.io, all signed with cosign (keyless) and carrying
build provenance and SBOMs. [releasing.md](releasing.md) has the versioning policy, the `cosign verify`
and `gh attestation verify` commands and the licensing note for the worker image.

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
| `CIPHERFRAME_WORKER_LISTEN` | `:8082` | no | no | `host:port`. Used only by a process that runs the `worker` role without `api` or `edge`: it serves `/healthz`, `/readyz` and, with a scrape token, `/metrics` there. |
| `CIPHERFRAME_METRICS_TOKEN` | unset (`/metrics` off) | no | yes | Bearer token a scraper presents on `/metrics`, at least 16 bytes. Set it directly or with `CIPHERFRAME_METRICS_TOKEN_FILE`. Without it the route is not served and startup logs that once. See [observability.md](observability.md). |
| `CIPHERFRAME_METRICS_TENANT_LABEL` | `false` | no | no | `true` adds a `tenant_id` label to `cipherframe_refusals_total` (ADR 0053). See the trade-off in [observability.md](observability.md#the-tenant-label). |
| `CIPHERFRAME_DATABASE_URL` | none | yes | yes | `postgres://` or `postgresql://` URL. |
| `CIPHERFRAME_S3_ENDPOINT` | empty (provider default) | no | no | Absolute `http(s)` URL. |
| `CIPHERFRAME_S3_PUBLIC_ENDPOINT` | the endpoint | no | no | Absolute `http(s)` URL a browser can reach. Used only to sign presigned URLs (the `presigned` delivery setting, and uploads); server-side calls always use the endpoint. |
| `CIPHERFRAME_S3_REGION` | `us-east-1` | no | no | |
| `CIPHERFRAME_S3_FORCE_PATH_STYLE` | `false` | no | no | Go `strconv.ParseBool` values. |
| `CIPHERFRAME_S3_SOURCE_BUCKET` | none | yes | no | Valid S3 bucket name (3-63 chars, lowercase letters, digits, `-`, `.`). |
| `CIPHERFRAME_S3_DELIVERY_BUCKET` | none | yes | no | Same rules; must differ from the source bucket. |
| `CIPHERFRAME_S3_ACCESS_KEY_ID` | unset | production: yes | yes | Credential, see below. Both S3 credentials must be in the same state. |
| `CIPHERFRAME_S3_SECRET_ACCESS_KEY` | unset | production: yes | yes | Credential, see below. |
| `CIPHERFRAME_EDGE_PUBLIC_URL` | none | with the `api` role | no | Base URL browsers use to reach the edge listener, for example `https://media.example.com`: absolute `http(s)`, no path, query or credentials. The API puts it in upload instructions, and tus uses it for `Location` headers. The server refuses to start the `api` role without it. |
| `CIPHERFRAME_MAX_SOURCE_BYTES` | `10737418240` (10 GiB) | no | no | Largest source an asset may declare, in bytes (1 MiB to 5 TiB). Checked at asset creation and again at commit. |
| `CIPHERFRAME_UPLOAD_TOKEN_TTL` | `24h` | no | no | How long an upload token works: a Go duration from `1m` to `168h`. |
| `CIPHERFRAME_UPLOAD_PART_BYTES` | `67108864` (64 MiB) | no | no | Part size for multipart uploads and tus chunks to the object store, in bytes (5 MiB to 5 GiB). The maximum source size divided by it may not exceed 10000 parts. |
| `CIPHERFRAME_API_KEY_PEPPERS` | none | yes | yes | Comma-separated `version:base64`. Versions are unique positive integers; each decoded pepper is at least 32 bytes (standard base64). |
| `CIPHERFRAME_API_KEY_PEPPER_CURRENT` | none | yes | no | Positive integer naming a version in the set. |
| `CIPHERFRAME_PLAYBACK_TOKEN_KEYS` | none | with the `api` or `edge` role | yes | Comma-separated `kid:base64`: signing keys for playback tokens (ADR 0028). Key IDs are unique positive integers; each decoded key is at least 32 bytes (standard base64). `_FILE` is supported. Values starting with `dev-placeholder-` are accepted only in development. The `api` role signs tokens and the `edge` role verifies them, so both need the same set. The server refuses to start either role without it. |
| `CIPHERFRAME_PLAYBACK_TOKEN_KEY_CURRENT` | none | with the `api` or `edge` role | no | Positive integer naming the key ID that signs new tokens. Older keys stay in the set so tokens already issued keep verifying until they expire; remove one only after the token lifetime has passed. |
| `CIPHERFRAME_KMS_PROVIDER` | `local` in development | production: yes | no | Key provider that wraps content keys: `local`, `vault`, `awskms` or `gcpkms`. `local` is **development-only**: production requires an explicit provider other than `local` and refuses to start otherwise. Docker Compose uses `local` with a `dev-placeholder-` KEK (ADR 0019, ADR 0022). |
| `CIPHERFRAME_KMS_UNWRAP_PROVIDERS` | unset | no | no | Comma-separated provider names, other than the current one, that may **only unwrap** keys they wrapped earlier (for example `local` while moving to `vault`). Each listed provider's own settings are required and validated exactly like the current provider's, and `local` is refused in production as usual. A name that is unknown, repeated or equal to `CIPHERFRAME_KMS_PROVIDER` is refused. Keep a provider here until `admin kms-usage` shows no content key on it; see [encryption.md](encryption.md#rotation-and-re-wrap). |
| `CIPHERFRAME_KMS_LOCAL_KEKS` | none | with `local` | yes | Comma-separated `version:base64`. Versions are unique positive integers; each decoded KEK is **exactly 32 bytes** (standard base64). `_FILE` is supported. Values starting with `dev-placeholder-` are accepted only in development. Ignored unless the provider is `local`. |
| `CIPHERFRAME_KMS_LOCAL_KEK_CURRENT` | none | with `local` | no | Positive integer naming the version in the set that new wraps use. Older versions stay for unwrapping. |
| `CIPHERFRAME_KMS_VAULT_ADDR` | none | with `vault` | no | Server address, an absolute `http(s)` URL without credentials, query or fragment. Production requires `https`. A path prefix (reverse proxy) is allowed. Ignored unless the provider is `vault`. |
| `CIPHERFRAME_KMS_VAULT_TOKEN` | none | with `vault` | yes | Vault or OpenBao token. `_FILE` is supported. Must not contain whitespace. Values starting with `dev-placeholder-` are accepted only in development. |
| `CIPHERFRAME_KMS_VAULT_TRANSIT_MOUNT` | `transit` | no | no | Mount path of the Transit secrets engine, without leading or trailing slash (nested paths such as `team/transit` are allowed). |
| `CIPHERFRAME_KMS_VAULT_KEY_NAME` | none | with `vault` | no | Transit key that wraps content keys: letters, digits, `-`, `_` and `.`. Must be an AEAD type (`aes256-gcm96` recommended); other types are refused on first use. |
| `CIPHERFRAME_KMS_VAULT_NAMESPACE` | unset | no | no | Sent as `X-Vault-Namespace` (HashiCorp Vault Enterprise and OpenBao namespaces). |
| `CIPHERFRAME_KMS_VAULT_CA_FILE` | system roots | no | no | Path to a PEM file of CA certificates that **replaces** the system roots for the connection to the server. The file is read and checked at startup. |
| `CIPHERFRAME_KMS_VAULT_TIMEOUT` | `5s` | no | no | Go duration for one request to the server; greater than zero, at most `5m`. |
| `CIPHERFRAME_KMS_AWS_KEY_ID` | none | with `awskms` | no | The KEK: a KMS key ARN, an alias ARN or `alias/name` (a bare key id is refused). Ignored unless the provider is `awskms`. |
| `CIPHERFRAME_KMS_AWS_REGION` | none | with `awskms` | no | AWS region of the key, for example `eu-west-1`. |
| `CIPHERFRAME_KMS_AWS_ENDPOINT` | empty (AWS default) | no | no | Absolute `http(s)` URL, for a VPC endpoint or a KMS-compatible server. |
| `CIPHERFRAME_KMS_AWS_ACCESS_KEY_ID` | unset | production: yes | yes | Credential, same rules as the S3 pair: set = static key pair, empty = the AWS SDK default chain (preferred in production), unset = refused in production and the default chain in development. Both must be in the same state. |
| `CIPHERFRAME_KMS_AWS_SECRET_ACCESS_KEY` | unset | production: yes | yes | Credential, see above. |
| `CIPHERFRAME_KMS_AWS_TIMEOUT` | `5s` | no | no | Go duration, above zero and at most `5m`. Bounds every KMS call including SDK retries. |
| `CIPHERFRAME_KMS_GCP_KEY_NAME` | none | with `gcpkms` | no | Cloud KMS crypto key, `projects/P/locations/L/keyRings/R/cryptoKeys/K`. A key version name is refused. The key must be a symmetric `ENCRYPT_DECRYPT` key; new wraps use its primary version. Ignored unless the provider is `gcpkms`. |
| `CIPHERFRAME_KMS_GCP_CREDENTIALS_FILE` | unset (Application Default Credentials) | no | no | Path of a credentials JSON file (`service_account`, `authorized_user`, `external_account` or `impersonated_service_account`). It is a path, not a secret; its content is never logged. Unset means Application Default Credentials (workload identity, attached service account, `GOOGLE_APPLICATION_CREDENTIALS`). The identity needs `cloudkms.cryptoKeys.get` and `cloudkms.cryptoKeyVersions.useToEncrypt`/`useToDecrypt` (for example `roles/cloudkms.cryptoOperator` plus `roles/cloudkms.viewer`). |
| `CIPHERFRAME_KMS_GCP_ENDPOINT` | the Cloud KMS endpoint | no | no | Optional `host:port` that replaces `cloudkms.googleapis.com:443`, for a private endpoint (Private Service Connect). The connection uses TLS. |
| `CIPHERFRAME_KMS_GCP_TIMEOUT` | `5s` | no | no | Go duration from 1ms to 5m, applied to each Cloud KMS request (including SDK retries). |
| `CIPHERFRAME_FFMPEG_PATH` | `ffmpeg` (found on `PATH`) | no | no | FFmpeg binary the **worker** role runs: a path or a bare name. Executed directly, never through a shell, with an empty environment. A value starting with `-` or containing control characters is refused. See [Media toolchain](#media-toolchain-and-your-own-ffmpeg). |
| `CIPHERFRAME_FFPROBE_PATH` | `ffprobe` (found on `PATH`) | no | no | FFprobe binary, same rules. |
| `CIPHERFRAME_MAX_SOURCE_DURATION` | `4h` | no | no | Longest accepted source, a Go duration above zero and at most `168h`. Checked by the probe step before any encoding (ADR 0025). |
| `CIPHERFRAME_MAX_SOURCE_WIDTH` | `3840` | no | no | Largest accepted picture width in pixels, 16 to 16384. Applies to the picture a viewer sees and to the stored frame, in either orientation: a `2160x3840` portrait video passes the default `3840x2160` limit. |
| `CIPHERFRAME_MAX_SOURCE_HEIGHT` | `2160` | no | no | Largest accepted picture height, same rules. |
| `CIPHERFRAME_TRANSCODE_TIMEOUT` | `6h` | no | no | Longest one transcode may run, a Go duration above zero and at most `168h`. A transcode that exceeds it fails the asset with `transcode_timeout`. |
| `CIPHERFRAME_WORK_DIR` | `<OS temp dir>/cipherframe` | no | no | Absolute path of the **worker's** private scratch directory. Created with mode 0700 (and tightened if it already exists with wider permissions). Each `asset.process` job works in its own subdirectory, which holds the downloaded source and the plaintext segments FFmpeg writes and is deleted when the job ends. See [Processing](#processing-and-the-work-directory). |
| `CIPHERFRAME_WORKER_MEDIA_CONCURRENCY` | `1` | no | no | How many `asset.process` jobs one **worker** process transcodes at once, 1 to 64. They run on their own `media` queue, so transcodes never take a slot from other jobs such as `kms.rewrap` (those keep 10 slots). Each FFmpeg run already uses all cores, so scale throughput by adding worker replicas rather than raising this. Disk need is 2 to 3 times the source size per concurrent job in `CIPHERFRAME_WORK_DIR`. |
| `CIPHERFRAME_WORKER_MASK_TIMEOUT` | `2h` | no | no | How long an `asset.mask` job waits for the masker to finish one video, and again for the original variant to become `ready` before it publishes, a Go duration above zero and at most `168h`. Past it the asset's masked variant is marked `failed` and the original stays playable. See [Face masking](#face-masking). |
| `CIPHERFRAME_WORKER_MASK_CONCURRENCY` | `1` | no | no | How many `asset.mask` jobs one **worker** process runs at once, 1 to 64. They run on their own `mask` queue, apart from `media`, so masking never takes a slot from `asset.process` and the two overlap. The masker itself uses several cores, so scale by adding masker and worker replicas. Disk need adds up with the media concurrency. See [Face masking](#face-masking). |
| `CIPHERFRAME_WORKER_LADDER_HEIGHTS` | all rungs | no | no | Restricts the renditions of both variants to a comma-separated subset of the rung heights `1080,720,480,360,240` (ADR 0024), for example `720,360`. Known heights only, no duplicates. A rung taller than the source is skipped; a source shorter than every selected rung gets one rendition at its own height. Fewer rungs mean a proportionally faster transcode. |
| `CIPHERFRAME_ACCESS_LOG_RETENTION_DAYS` | `90` | no | no | How many days the access trail (`playback_access_log`) and the anomaly events (`playback_events`) are kept, a whole number from 1 to 3650 (ADR 0040). The **worker** role's retention job drops whole monthly partitions past the window and deletes the older rows of the rest, every five minutes. Assets have no deployment-wide time-to-live: they are kept until deleted unless the request or the tenant's `asset_ttl_seconds` sets one ([api.md](api.md#assets-and-uploads-adr-0025-0026)). |
| `CIPHERFRAME_WORKER_X264_PRESET` | `medium` | no | no | The libx264 preset of every rendition in both variants (ADR 0038): `ultrafast`, `superfast`, `veryfast`, `faster`, `fast`, `medium`, `slow`, `slower` or `veryslow`. Faster presets cut transcode time and give lower quality per bit; the bitrate caps of ADR 0024 still apply. Keyframe alignment is unaffected. |
| `CIPHERFRAME_WORKER_CRF` | `23` | no | no | The constant quality (CRF) of every H.264 rendition, a whole number from 0 to 51; lower is better quality and larger files. The bitrate caps of ADR 0024 still apply. Hardware encoders translate it with their own scale (docs/hardware-encoders.md). Recorded per rung in the signed manifest. |
| `CIPHERFRAME_WORKER_CRF_HEVC` | `26` | no | no | The same for the HEVC renditions (ADR 0067), 0 to 51. |
| `CIPHERFRAME_WORKER_CRF_AV1` | `35` | no | no | The same for the AV1 renditions (ADR 0067), 0 to 63. |
| `CIPHERFRAME_WORKER_ENCODER` | `software` | no | no | Video encoder of the **worker** (ADR 0063, ADR 0066): `software` (libx264), `nvenc`, `vaapi`, `qsv` or `videotoolbox`. Hardware is a property of the machine, so this is per worker, not per tenant. At startup the worker runs a short test encode; if it fails it logs one warning naming the encoder and uses software. A hardware transcode that fails during a job is repeated once with libx264. See [hardware-encoders.md](hardware-encoders.md). |
| `CIPHERFRAME_WORKER_HW_DEVICE` | `/dev/dri/renderD128` | no | no | The render node `vaapi` and `qsv` open: a plain path under `/dev`. Ignored by the other encoders. |
| `CIPHERFRAME_TSA_URL` | unset (anchoring off) | no | no | Endpoint of an RFC 3161 time-stamping authority (ADR 0041). `https` only; `http` is accepted only when `CIPHERFRAME_ENV=development`, for a local authority. Set on the **worker** role, which runs the `manifest.anchor` job. See [Timestamp anchoring](#timestamp-anchoring-optional). |
| `CIPHERFRAME_TSA_TIMEOUT` | `10s` | no | no | Go duration for one request to the authority, above zero and at most `2m`. |
| `CIPHERFRAME_TSA_POLICY_OID` | unset | no | no | Policy the request asks for, dotted decimal such as `1.2.3.4`. Leave unset to accept the authority's default. |
| `CIPHERFRAME_CDN_PROVIDER` | unset (no CDN) | no | no | `cloudfront` or `cloudcdn`. Turns on the `cdn` delivery setting (ADR 0062, [cdn.md](cdn.md)). Set the CDN variables on **every** role (the key file only on the edge): the api role needs to know a CDN exists, the edge signs, the worker purges. With no provider, any other `CIPHERFRAME_CDN_*` variable is an error. |
| `CIPHERFRAME_CDN_BASE_URL` | none | with a provider | no | The CDN as browsers reach it: `https://host`, no path or query (`http` only in development). Its origin must be the delivery bucket root. |
| `CIPHERFRAME_CDN_KEY_ID` | none | with a provider | no | The CloudFront public key ID (of a key in a trusted key group), or the Cloud CDN signing key name. Not secret. |
| `CIPHERFRAME_CDN_SIGNING_KEY_FILE` | none | on the **edge** role | **yes, file only** | Path of the signing key: an RSA 2048 PEM private key (CloudFront), or the 16-byte Cloud CDN key in URL-safe base64. There is no variable for the key itself; `CIPHERFRAME_CDN_SIGNING_KEY` is refused. Only the **edge** role reads the file, at startup, and refuses to start without it. |
| `CIPHERFRAME_CDN_CLOUDFRONT_DISTRIBUTION_ID` | none | provider `cloudfront` | no | The distribution the **worker** invalidates after a deletion. |
| `CIPHERFRAME_CDN_CLOUDCDN_PROJECT` | none | provider `cloudcdn` | no | Project of the URL map the worker invalidates. Credentials come from Application Default Credentials (Workload Identity on GKE). |
| `CIPHERFRAME_CDN_CLOUDCDN_URL_MAP` | none | provider `cloudcdn` | no | Name of the URL map in front of the delivery bucket's backend bucket. |

Empty values of non-secret variables mean "use the default".

### Timestamp anchoring (optional)

Anchoring is off until you set `CIPHERFRAME_TSA_URL`. Cipherframe then asks the authority for an
RFC 3161 token over SHA-256 of each signed manifest, so the manifest's time no longer rests on your
clock alone (how it works and how to verify it: [integrity.md](integrity.md#anchoring-optional)).
The request carries a digest and nothing else: no file, name, tenant or asset identifier. You choose
the authority and accept its terms; Cipherframe enables none and endorses none.

[ADR 0034](adr/0034-timestamp-authority-recommendations.md) (2026-11-12) names these public
authorities: the free RFC 3161 services of DigiCert, Sectigo and GlobalSign, which are WebTrust-audited
certificate authorities, and FreeTSA as a community option. The ADR records no endpoint URLs and
providers change them, so take the current URL and the CA certificate from the provider's own
documentation, and check its terms and rate limits before relying on it.

```sh
CIPHERFRAME_TSA_URL=https://tsa.example.com/rfc3161   # from your chosen provider
CIPHERFRAME_TSA_TIMEOUT=10s
```

The authority's CA certificate (PEM) is what an auditor passes to `cipherframe verify --tsa-ca`;
without it the system roots are used.

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

## Backups and key loss

See [disaster-recovery.md](disaster-recovery.md): what to back up, the restore order, and why losing
the KEK (or access to the KMS key) makes every asset permanently unreadable.

## What this does not protect against

See [threat-model.md](threat-model.md#out-of-scope).
