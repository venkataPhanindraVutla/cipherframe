# cipherframe-ml

The face masker (ADR 0036): a Python worker that claims `media.mask_faces` tasks from the
`external_tasks` hand-off table (ADR 0010, `spec/jobs/README.md`), blurs every face in a video and
writes the result back. It is a privacy aid, not a guarantee: profiles, tiny faces (detection runs on
a 640 px wide copy) and heavy occlusion can be missed.

## How it works

1. Claim a task with `FOR UPDATE SKIP LOCKED`, hold the lease, and extend it by heartbeat every third
   of the lease (60 s). If the lease is lost the worker stops and writes nothing.
2. Resolve `payload.input` and `payload.output` inside `CIPHERFRAME_WORK_DIR` (the directory shared
   with the Go worker). Absolute paths, `..`, backslashes and symlinks leaving the directory are
   rejected as a permanent `invalid_payload` failure.
3. Decode with OpenCV, detect faces with YuNet (score 0.6, on a copy 640 px wide), pad each box 25 %
   per side, hold the last boxes for 1 s after detection drops, pixelate (8 px blocks) then Gaussian-blur
   every face, and pipe raw frames to FFmpeg (libx264 CRF 12, `yuv420p`) with the source audio copied.
4. Write `{"status": "succeeded", "output": {"faces_detected": N, "frames": M}}`, where
   `faces_detected` counts frames with at least one detected face. The masked file stays in the work
   directory; it is not an artifact and never goes to storage (ADR 0027).

Failures: `invalid_payload`, `input_not_found`, `decode_failed`, `unsupported_envelope` are not
retryable; `encode_failed` and `internal_error` are.

Schemas: `spec/jobs/kinds/media.mask_faces.{payload,output}.schema.json`, with vectors in
`spec/jobs/vectors`.

## Run

```sh
uv sync
uv run python scripts/fetch_model.py          # downloads models/face_detection_yunet_2026may.onnx
export CIPHERFRAME_ML_DATABASE_URL=postgres://...      # or CIPHERFRAME_ML_DATABASE_URL_FILE
export CIPHERFRAME_WORK_DIR=/var/lib/cipherframe/work  # absolute; shared with the Go worker
uv run cipherframe-ml mask-worker
```

| Variable | Default |
|---|---|
| `CIPHERFRAME_ML_DATABASE_URL` / `_FILE` | required (use the limited `cipherframe_worker` role from `spec/jobs/README.md`) |
| `CIPHERFRAME_WORK_DIR` | `<tmp>/cipherframe` |
| `CIPHERFRAME_FFMPEG_PATH` | `ffmpeg` |
| `CIPHERFRAME_ML_MODEL_PATH` | `models/face_detection_yunet_2026may.onnx` |

The worker refuses to start if the model's SHA-256 does not match the one pinned in
`src/cipherframe_ml/model.py`. The FFmpeg must be able to read raw video from a pipe; the worker
image's FFmpeg enables the `rawvideo` demuxer and decoder for this.

## Image

```sh
docker build -f build/worker.Dockerfile -t cipherframe-worker .
docker build -f ml/Dockerfile --build-arg FFMPEG_IMAGE=cipherframe-worker -t cipherframe-ml ml
```

Run it next to the Go worker with the same work directory mounted, as the same non-root UID (the
worker creates job directories with mode 0700). The Compose stack does this: `docker compose -f
deploy/compose/compose.yaml --profile worker up --build` starts the worker, the masker and the shared
`work` volume, and creates the limited database role from `deploy/compose/masker-role.sql`.

The Go side of the hand-off is the `asset.mask` job (`internal/pipeline/mask.go`). See
[docs/usage.md](../docs/usage.md#face-masking) for how to enable masking and the requirements of
running the two together, and [docs/architecture.md](../docs/architecture.md#processing-pipeline) for
the flow.

## Tests

```sh
uv run ruff check . && uv run pytest
uv run pytest -m "not docker"     # skip the Postgres tests (they need Docker)
```

FFmpeg tests are skipped when `ffmpeg` is not on `PATH`. `CIPHERFRAME_TEST_PG_IMAGE` selects the
Postgres image for the integration tests (default `postgres:16.15`).
