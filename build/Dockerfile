# cipherframe-server image: the api and edge roles (ADR 0008). No FFmpeg. The separate worker image
# with FFmpeg arrives with M3 (FFmpeg build and licensing is gate P8).
#
#   docker build -f build/Dockerfile --build-arg VERSION=v0.1.0 -t cipherframe-server .

FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/venkataPhanindraVutla/cipherframe/internal/version.Version=${VERSION}" \
    -o /out/cipherframe-server ./cmd/cipherframe-server

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/cipherframe-server /cipherframe-server
USER nonroot
ENTRYPOINT ["/cipherframe-server"]
