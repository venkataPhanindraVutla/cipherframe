# Cipherframe

Cipherframe is a self-hostable service that sits between private S3-compatible object storage and a
browser. It turns a source video into encrypted, adaptive-bitrate HLS, keeps the original private, and
serves playback only to viewers that an embedding application has explicitly authorized, through
short-lived, revocable sessions. It records who watched, signs a record of everything it produced, and
can delete an asset verifiably by destroying its encryption key and signing a record of the deletion.

It is a building block that applications embed, not a video platform. The embedding application
decides *who may watch what*. Cipherframe decides *how those bytes reach the browser safely* and *how
they stop existing*.

> **Status: early development.** Nothing is usable yet. Design decisions are recorded in
> [`docs/adr/`](docs/adr/).

## Who it is for

Products where the video is somebody's personal data and deletion rights must actually work:
HR and interview recordings, telehealth, legal, education, finance and KYC.

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
| `cmd/` | Binaries (added once the service topology is decided) |
| `internal/` | Go packages private to the service |
| `docs/` | Architecture, threat model and other docs; `docs/adr/` holds decision records |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

## Licence

[Apache-2.0](LICENSE).
