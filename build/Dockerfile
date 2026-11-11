# cipherframe-server image: the api and edge roles (ADR 0008). No FFmpeg. The separate worker image
# with FFmpeg arrives with M3 (FFmpeg build and licensing is gate P8).
#
#   docker build -f build/Dockerfile --build-arg VERSION=v0.1.0 -t cipherframe-server .

FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0 AS build
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
