# Cipherframe

Cipherframe is a self-hostable service that sits between private S3-compatible object storage and a
browser. It turns a source video into encrypted, adaptive-bitrate HLS, keeps the original private, and
serves playback only to viewers that an embedding application has explicitly authorized, through
short-lived, revocable sessions. It records who watched, signs a record of everything it produced, and
can delete an asset verifiably by destroying its encryption key and signing a record of the deletion.

It is a building block that applications embed, not a video platform. The embedding application
decides *who may watch what*. Cipherframe decides *how those bytes reach the browser safely* and *how
they stop existing*.

> **Status: pre-release.** The v1.0.0 feature set is built and runs in CI on every change (unit,
> integration on two Postgres versions, FFmpeg media tests, fuzzing, browser end-to-end). The first
> pre-release, [`v0.1.0-rc.2`](https://github.com/venkataPhanindraVutla/cipherframe/releases), ships
> signed images and binaries with build provenance. It has not yet run in production; GPU encoders and
> live CDN signing are untested on real hardware and cloud accounts ([roadmap](docs/roadmap.md)).

## Who it is for

Products where the video is somebody's personal data and deletion rights must actually work:
HR and interview recordings, telehealth, legal, education, finance and KYC.

## What it does

- **Ingest:** resumable uploads (tus or S3 multipart), H.264 adaptive ladder in CMAF, optional HEVC
  and AV1 renditions, hardware encoders with software fallback ([codecs](docs/codecs.md),
  [hardware encoders](docs/hardware-encoders.md)).
- **Encryption:** AES-128 HLS with a fresh IV per segment; one content key per asset, wrapped by AWS
  KMS, Google Cloud KMS, HashiCorp Vault or OpenBao Transit, or a local key; audited re-key ([encryption](docs/encryption.md)).
- **Playback:** short-lived, revocable sessions per viewer, a key endpoint that enforces them,
  heartbeats, anomaly detection, an access trail, and a per-session on-screen watermark code that traces
  a leak back to a session. Delivery through the edge, presigned storage URLs, or CloudFront / Cloud CDN
  signed URLs ([cdn](docs/cdn.md)).
- **Privacy:** an optional face-blurred variant per asset, per-asset time-to-live, no original file
  names stored, IP and user agent off by default ([privacy](docs/privacy.md)).
- **Proof:** a signed manifest for every asset with per-segment proofs, optional RFC 3161 timestamps,
  and a public-key-only verifier; verified deletion that destroys the key and signs a deletion record
  ([integrity](docs/integrity.md)).
- **Around it:** subtitles and transcript import, poster and thumbnail sprites, tenant branding,
  signed webhooks, quotas, a CLI, an embeddable `<cipherframe-player>`, metrics and traces with a
  Grafana dashboard, Helm chart, Terraform examples and published load tests
  ([load tests](docs/load-tests.md)).

## Try it locally

You need Docker with Compose v2 and Go 1.27 (or a CLI binary from the
[releases](https://github.com/venkataPhanindraVutla/cipherframe/releases)). No cloud account is needed.

```sh
docker compose -f deploy/compose/compose.yaml --profile worker up -d --build   # first build compiles FFmpeg
umask 077
docker compose -f deploy/compose/compose.yaml run --rm -T server \
  admin bootstrap --tenant-name demo --client-name demo | tail -1 > key.txt  # an admin API key
go build -o cipherframe ./cmd/cipherframe
export CIPHERFRAME_SERVER=http://127.0.0.1:8080

id=$(./cipherframe upload clip.mp4 --wait --api-key-file key.txt)   # upload, transcode, encrypt
./cipherframe session create "$id" --viewer alice --api-key-file key.txt   # a playback session
./cipherframe delete "$id" --wait --api-key-file key.txt > record.json     # verified deletion
```

Play the session in the [reference player](player/README.md); the full walkthrough is in
[usage](docs/usage.md).

## What it does not protect against

Cipherframe raises the cost of casual copying and makes deletion verifiable. It does **not** protect
against:

- screen recording or camera capture of playback,
- an authorized viewer keeping a copy of what they were allowed to watch,
- scripted reassembly of segments while a session is valid,
- compromise of the operator's own storage or KMS credentials.

Standard HLS AES-128 encryption is **not DRM**. Cipherframe never claims that video "cannot be
downloaded".

## Repository layout

| Path | Contents |
|---|---|
| `cmd/cipherframe-server` | The service: `--role=api,edge,worker`, migrations, admin commands |
| `cmd/cipherframe` | The CLI, including the offline verifier |
| `cmd/cipherframe-load` | The load-test tool |
| `internal/` | Go packages private to the service |
| `spec/openapi.yaml` | The HTTP API, the source of truth for the server and the CLI client |
| `player/` | The reference player (TypeScript, hls.js) |
| `ml/` | The face masker (Python) |
| `deploy/` | Docker Compose, Helm chart, Terraform examples, Grafana and alert rules |
| `docs/` | [Usage](docs/usage.md), [API](docs/api.md), [architecture](docs/architecture.md), [threat model](docs/threat-model.md), [releasing](docs/releasing.md), [roadmap](docs/roadmap.md); `docs/adr/` holds the decision records |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

## Licence

[Apache-2.0](LICENSE).
