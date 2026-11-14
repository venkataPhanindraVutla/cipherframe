# cipherframe-ml image: the face masker (ADR 0036). Run it next to the Go worker with the same
# CIPHERFRAME_WORK_DIR mounted, because plaintext video stays on local disk (ADR 0027).
#
#   docker build -f build/worker.Dockerfile -t cipherframe-worker .     # the worker image, once
#   docker build -f ml/Dockerfile --build-arg FFMPEG_IMAGE=cipherframe-worker -t cipherframe-ml ml
#
# FFmpeg is the worker image's static binary (build/worker.Dockerfile); no second FFmpeg is built.
# FFmpeg and x264 are GPL: see NOTICE and /usr/share/licenses/ffmpeg/ (copied from the worker image).

ARG FFMPEG_IMAGE=cipherframe-worker
ARG PYTHON_IMAGE=python:3.12-slim-bookworm
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.10.10

FROM ${FFMPEG_IMAGE} AS ffmpeg
FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE}
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /app
COPY --from=uv /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev
COPY scripts ./scripts
# Bake in the model; the fetch verifies its SHA-256, and the worker verifies it again at start.
RUN /opt/venv/bin/python scripts/fetch_model.py /opt/models
COPY --from=ffmpeg /usr/local/bin/ffmpeg /usr/local/bin/ffmpeg
COPY --from=ffmpeg /usr/share/licenses/ffmpeg/ /usr/share/licenses/ffmpeg/
RUN useradd --system --uid 65532 --no-create-home nonroot
ENV PATH=/opt/venv/bin:$PATH \
    CIPHERFRAME_FFMPEG_PATH=/usr/local/bin/ffmpeg \
    CIPHERFRAME_ML_MODEL_PATH=/opt/models/face_detection_yunet_2026may.onnx
USER nonroot
ENTRYPOINT ["cipherframe-ml"]
CMD ["mask-worker"]
