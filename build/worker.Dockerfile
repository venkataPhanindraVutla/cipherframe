# cipherframe-worker image: the cipherframe-server binary plus a minimal, static FFmpeg and FFprobe
# (ADR 0008 two images, ADR 0024 FFmpeg build). Run it with --role=worker (the default command).
#
#   docker build -f build/worker.Dockerfile --build-arg VERSION=v0.1.0 -t cipherframe-worker .
#
# Design notes
# - FFmpeg and x264 are GPL; dav1d is BSD-2-Clause. They are separate programs that Cipherframe starts
#   as processes (invariant I1), never libraries. The licence texts and a written source offer
#   (SOURCE.md, generated from the pins below) are in /usr/share/licenses/ffmpeg/.
# - FFmpeg is linked fully statically (glibc included), so the final image can be distroless/static:
#   no libc, no shell, no package manager to attack. The build ran `ldd` to prove nothing is dynamic.
# - Every source download is pinned by SHA-256 and every base image by tag and digest. Debian
#   build tools come from a fixed snapshot.debian.org timestamp.
# - dav1d is here because FFmpeg's native "av1" decoder is hardware-accelerator-only: without
#   libdav1d (or libaom) AV1 uploads could be probed but never decoded.
# - Targets: the default (last) target is the worker image. `fixtures` is a test-only stage that
#   holds an FFmpeg with the lavfi test sources; it never ships (see internal/media/testmedia).
#   `tools` exports the binaries for CI (docker build --target tools --output type=local,dest=out).

ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
ARG GO_IMAGE=golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

# ---------------------------------------------------------------------------------------------
# Toolchain: Debian bookworm from a fixed snapshot.
FROM ${DEBIAN_IMAGE} AS toolchain
ARG DEBIAN_SNAPSHOT=20261101T000000Z
RUN rm -f /etc/apt/sources.list.d/* /etc/apt/sources.list \
    && echo "deb http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm main" > /etc/apt/sources.list \
    && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99snapshot \
    && echo 'Acquire::Retries "5";' >> /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        bzip2 ca-certificates gcc libc6-dev make meson nasm ninja-build pkg-config xz-utils \
    && rm -rf /var/lib/apt/lists/*
ENV PREFIX=/opt/deps

# ---------------------------------------------------------------------------------------------
# x264 (GPL-2.0-or-later): the `stable` branch at a fixed commit.
FROM toolchain AS x264
ARG X264_COMMIT=b35605ace3ddf7c1a5d67a2eb553f034aef41d55
ARG X264_SHA256=6eeb82934e69fd51e043bd8c5b0d152839638d1ce7aa4eea65a3fedcf83ff224
ADD --checksum=sha256:${X264_SHA256} \
    https://code.videolan.org/videolan/x264/-/archive/${X264_COMMIT}/x264-${X264_COMMIT}.tar.bz2 /src/x264.tar.bz2
RUN mkdir /src/x264 && tar -xjf /src/x264.tar.bz2 -C /src/x264 --strip-components=1
WORKDIR /src/x264
RUN ./configure --prefix=${PREFIX} --enable-static --enable-pic --bit-depth=8 \
        --disable-cli --disable-opencl --disable-avs --disable-swscale --disable-lavf \
        --disable-ffms --disable-gpac --disable-lsmash \
    && make -j"$(nproc)" && make install

# ---------------------------------------------------------------------------------------------
# dav1d (BSD-2-Clause): AV1 software decoder.
FROM toolchain AS dav1d
ARG DAV1D_VERSION=1.5.4
ARG DAV1D_SHA256=686616b7c69eb88d44459391ab25cac13b6647a3b288835c5784e71c1514a5c5
ADD --checksum=sha256:${DAV1D_SHA256} \
    https://downloads.videolan.org/pub/videolan/dav1d/${DAV1D_VERSION}/dav1d-${DAV1D_VERSION}.tar.xz /src/dav1d.tar.xz
RUN mkdir /src/dav1d && tar -xJf /src/dav1d.tar.xz -C /src/dav1d --strip-components=1
WORKDIR /src/dav1d
RUN meson setup build --prefix=${PREFIX} --libdir=lib --buildtype=release --default-library=static \
        -Denable_tools=false -Denable_examples=false -Denable_tests=false -Denable_docs=false \
    && ninja -C build install

# ---------------------------------------------------------------------------------------------
# FFmpeg source, verified once and shared by the two builds below.
FROM toolchain AS ffmpeg-src
ARG FFMPEG_VERSION=9.0.2
ARG FFMPEG_SHA256=8c3850283eb25fa026482078a04051e0be17347b09ef81a0849bec15a96e002e
# FFMPEG_URL can point at a mirror; the checksum is verified either way.
ARG FFMPEG_URL=https://ffmpeg.org/releases/ffmpeg-${FFMPEG_VERSION}.tar.xz
ADD --checksum=sha256:${FFMPEG_SHA256} ${FFMPEG_URL} /src/ffmpeg.tar.xz
RUN mkdir /src/ffmpeg && tar -xJf /src/ffmpeg.tar.xz -C /src/ffmpeg --strip-components=1

# ---------------------------------------------------------------------------------------------
# The shipped FFmpeg: only what ADR 0024 lists.
#   input   protocols file,pipe; demuxers mov (MP4/MOV), matroska (MKV/WebM)
#   decode  h264 hevc vp8 vp9 libdav1d(av1) aac opus mp3 (+ parsers)
#   encode  libx264, aac
#   output  muxers mp4 and hls (fMP4 segments); null (decode checks and tests)
#   filters scale format aresample null anull setsar fps split; transpose hflip vflip apply the display
#           matrix rotation (FFmpeg's autorotate inserts them); ffmpeg adds aformat/trim/etc itself.
# Not built: network protocols, devices, every other codec, container and filter, zlib/bzlib/iconv
# (so compressed MP4 headers and Matroska header compression are rejected).
FROM ffmpeg-src AS ffmpeg
COPY --from=x264 /opt/deps /opt/deps
COPY --from=dav1d /opt/deps /opt/deps
ENV PKG_CONFIG_PATH=/opt/deps/lib/pkgconfig
WORKDIR /src/ffmpeg
RUN ./configure \
        --prefix=/opt/ffmpeg \
        --pkg-config-flags=--static \
        --extra-cflags=-I/opt/deps/include \
        --extra-ldflags="-L/opt/deps/lib -static" \
        --disable-everything --disable-network --disable-autodetect --disable-doc --disable-debug \
        --disable-ffplay --disable-avdevice \
        --enable-gpl --enable-libx264 --enable-libdav1d \
        --enable-protocol=file,pipe \
        --enable-demuxer=mov,matroska \
        --enable-decoder=h264,hevc,vp8,vp9,libdav1d,aac,opus,mp3,mp3float \
        --enable-parser=h264,hevc,vp8,vp9,av1,aac,opus,mpegaudio \
        --enable-encoder=libx264,aac \
        --enable-muxer=mp4,hls,null \
        --enable-filter=scale,format,aresample,null,anull,setsar,fps,split,transpose,hflip,vflip \
    && make -j"$(nproc)" \
    && make install \
    && strip /opt/ffmpeg/bin/ffmpeg /opt/ffmpeg/bin/ffprobe \
    && (ldd /opt/ffmpeg/bin/ffmpeg 2>&1 | grep -q 'not a dynamic executable') \
    && (ldd /opt/ffmpeg/bin/ffprobe 2>&1 | grep -q 'not a dynamic executable') \
    && /opt/ffmpeg/bin/ffmpeg -hide_banner -buildconf > /opt/ffmpeg/buildconf.txt

# ---------------------------------------------------------------------------------------------
# Test-only FFmpeg: lavfi test sources to generate fixtures at test time (internal/media/testmedia),
# plus the h264/aac decoders and the ssim and psnr filters the pipeline test uses to measure quality.
# Those measuring filters live here and NEVER in the shipped build above.
# It lacks hls, libdav1d and most decoders on purpose, so it also serves as the "limited build"
# that CheckCapabilities must reject. It is never copied into the worker image.
FROM ffmpeg-src AS fixtures
COPY --from=x264 /opt/deps /opt/deps
ENV PKG_CONFIG_PATH=/opt/deps/lib/pkgconfig
WORKDIR /src/ffmpeg
RUN ./configure \
        --prefix=/opt/ffmpeg-fixtures \
        --pkg-config-flags=--static \
        --extra-cflags=-I/opt/deps/include \
        --extra-ldflags="-L/opt/deps/lib -static" \
        --disable-everything --disable-network --disable-autodetect --disable-doc --disable-debug \
        --disable-ffplay --disable-ffprobe \
        --enable-gpl --enable-libx264 --enable-avdevice \
        --enable-indev=lavfi \
        --enable-protocol=file,pipe \
        --enable-demuxer=mov \
        --enable-decoder=wrapped_avframe,pcm_s16le,pcm_f32le,pcm_f64le,rawvideo,h264,aac \
        --enable-parser=h264,aac \
        --enable-encoder=libx264,aac,wrapped_avframe \
        --enable-muxer=mp4,matroska,null \
        --enable-filter=testsrc2,sine,anullsrc,scale,format,aresample,null,anull,setsar,fps,ssim,psnr \
    && make -j"$(nproc)" \
    && make install \
    && strip /opt/ffmpeg-fixtures/bin/ffmpeg \
    && (ldd /opt/ffmpeg-fixtures/bin/ffmpeg 2>&1 | grep -q 'not a dynamic executable')

# ---------------------------------------------------------------------------------------------
# Licence texts and the written source offer.
FROM ffmpeg AS licenses
ARG FFMPEG_VERSION=9.0.2
ARG FFMPEG_SHA256=8c3850283eb25fa026482078a04051e0be17347b09ef81a0849bec15a96e002e
ARG X264_COMMIT=b35605ace3ddf7c1a5d67a2eb553f034aef41d55
ARG X264_SHA256=6eeb82934e69fd51e043bd8c5b0d152839638d1ce7aa4eea65a3fedcf83ff224
ARG DAV1D_VERSION=1.5.4
ARG DAV1D_SHA256=686616b7c69eb88d44459391ab25cac13b6647a3b288835c5784e71c1514a5c5
ARG DEBIAN_SNAPSHOT=20261101T000000Z
COPY --from=x264 /src/x264/COPYING /out/x264-COPYING
COPY --from=dav1d /src/dav1d/COPYING /out/dav1d-COPYING
COPY build/worker-SOURCE.md.in /tmp/SOURCE.md.in
RUN mkdir -p /out/licenses \
    && cp /src/ffmpeg/COPYING.GPLv2 /src/ffmpeg/COPYING.GPLv3 /src/ffmpeg/COPYING.LGPLv2.1 \
          /src/ffmpeg/COPYING.LGPLv3 /src/ffmpeg/LICENSE.md /src/ffmpeg/CREDITS /out/licenses/ \
    && cp /out/x264-COPYING /out/licenses/x264-COPYING.GPLv2 \
    && cp /out/dav1d-COPYING /out/licenses/dav1d-COPYING.BSD-2-Clause \
    && cp /usr/share/doc/libc6/copyright /out/licenses/glibc-copyright \
    && cp /usr/share/common-licenses/LGPL-2.1 /out/licenses/glibc-LGPL-2.1 \
    && LIBC_VERSION="$(dpkg-query -W -f='${Version}' libc6)" \
    && sed -e "s|@FFMPEG_VERSION@|${FFMPEG_VERSION}|g" -e "s|@FFMPEG_SHA256@|${FFMPEG_SHA256}|g" \
           -e "s|@X264_COMMIT@|${X264_COMMIT}|g" -e "s|@X264_SHA256@|${X264_SHA256}|g" \
           -e "s|@DAV1D_VERSION@|${DAV1D_VERSION}|g" -e "s|@DAV1D_SHA256@|${DAV1D_SHA256}|g" \
           -e "s|@DEBIAN_SNAPSHOT@|${DEBIAN_SNAPSHOT}|g" -e "s|@LIBC_VERSION@|${LIBC_VERSION}|g" \
           -e '/@BUILDCONF@/{r /opt/ffmpeg/buildconf.txt' -e 'd}' \
           /tmp/SOURCE.md.in > /out/licenses/SOURCE.md

# ---------------------------------------------------------------------------------------------
# The Cipherframe server binary.
FROM ${GO_IMAGE} AS server
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/venkataPhanindraVutla/cipherframe/internal/version.Version=${VERSION}" \
    -o /out/cipherframe-server ./cmd/cipherframe-server

# ---------------------------------------------------------------------------------------------
# CI: export the binaries (docker build --target tools --output type=local,dest=out).
FROM scratch AS tools
COPY --from=ffmpeg /opt/ffmpeg/bin/ffmpeg /opt/ffmpeg/bin/ffprobe /
COPY --from=fixtures /opt/ffmpeg-fixtures/bin/ffmpeg /ffmpeg-fixtures

# ---------------------------------------------------------------------------------------------
# The worker image (default target).
FROM ${RUNTIME_IMAGE} AS worker
COPY --from=ffmpeg /opt/ffmpeg/bin/ffmpeg /opt/ffmpeg/bin/ffprobe /usr/local/bin/
COPY --from=server /out/cipherframe-server /usr/local/bin/cipherframe-server
COPY --from=licenses /out/licenses/ /usr/share/licenses/ffmpeg/
ENV CIPHERFRAME_FFMPEG_PATH=/usr/local/bin/ffmpeg \
    CIPHERFRAME_FFPROBE_PATH=/usr/local/bin/ffprobe
USER nonroot
ENTRYPOINT ["/usr/local/bin/cipherframe-server"]
CMD ["--role=worker"]
