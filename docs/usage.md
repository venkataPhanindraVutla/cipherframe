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
`worker` role works the `kms.rewrap` job kind; a job that is running when shutdown starts gets 20
seconds to finish and is otherwise retried later.

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
AAC, Opus and MP3 decoding; libx264 and AAC encoding; MP4 and HLS (fMP4) output; and the
`scale`, `format`, `aresample`, `null`, `anull`, `setsar`, `fps`, `split`, `transpose`, `hflip` and
`vflip` filters (`split` fans the decoded frames out to one scaled branch per rendition) (the last three apply a rotated phone video's display matrix). Everything is pinned by
SHA-256 or digest. `/usr/share/licenses/ffmpeg/` holds the licence texts and `SOURCE.md`, the
written source offer with the exact sources and configure line. The image's `ENV` points
`CIPHERFRAME_FFMPEG_PATH` and `CIPHERFRAME_FFPROBE_PATH` at `/usr/local/bin`.

**Startup check.** A process with the `worker` role runs `ffmpeg -buildconf`, `-encoders`,
`-decoders`, `-muxers`, `-demuxers`, `-protocols` and `-filters` before connecting to anything and
refuses to start if a required piece is missing. The error lists everything missing at once, for
example `missing encoder(s): libx264; missing muxer(s): hls`.

**Using your own FFmpeg.** Set `CIPHERFRAME_FFMPEG_PATH` and `CIPHERFRAME_FFPROBE_PATH`. Your build
needs libx264 and the native AAC encoder; the `mp4` and `hls` muxers; the `mov` and `matroska`
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
| `CIPHERFRAME_WORKER_X264_PRESET` | `medium` | no | no | The libx264 preset of every rendition in both variants (ADR 0038): `ultrafast`, `superfast`, `veryfast`, `faster`, `fast`, `medium`, `slow`, `slower` or `veryslow`. Faster presets cut transcode time and give lower quality per bit; the bitrate caps of ADR 0024 still apply. Keyframe alignment is unaffected. |

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
