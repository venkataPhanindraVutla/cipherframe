# cipherframe-worker image: the cipherframe-server binary plus a minimal, static FFmpeg and FFprobe
# (ADR 0008 two images, ADR 0024 FFmpeg build). Run it with --role=worker (the default command).
#
#   docker build -f build/worker.Dockerfile --build-arg VERSION=v0.1.0 -t cipherframe-worker .
#
# Design notes
# - FFmpeg, x264 and x265 are GPL; dav1d is BSD-2-Clause; SVT-AV1 is BSD-3-Clause-Clear with the AOM
#   patent licence. They are separate programs that Cipherframe starts
#   as processes (invariant I1), never libraries. The licence texts and a written source offer
#   (SOURCE.md, generated from the pins below) are in /usr/share/licenses/ffmpeg/.
# - FFmpeg is linked fully statically (glibc included), so the final image can be distroless/static:
#   no libc, no shell, no package manager to attack. The build ran `ldd` to prove nothing is dynamic.
# - Every source download is pinned by SHA-256 and every base image by tag and digest. Debian
#   build tools come from a fixed snapshot.debian.org timestamp.
# - x265 (HEVC) and SVT-AV1 (AV1) are the software encoders of the optional extra codecs (ADR 0064,
#   ADR 0067). They are compiled in always, but the worker only uses them for tenants that turned a
#   codec on. x265 is built 8-bit only (every rendition is 8-bit 4:2:0).
# - dav1d is here because FFmpeg's native "av1" decoder is hardware-accelerator-only: without
#   libdav1d (or libaom) AV1 uploads could be probed but never decoded.
# - Targets: the default (last) target is the worker image. `fixtures` is a test-only stage that
#   holds an FFmpeg with the lavfi test sources; it never ships (see internal/media/testmedia).
#   `tools` exports the binaries for CI (docker build --target tools --output type=local,dest=out).
# - Hardware encoders (ADR 0063, ADR 0066) cannot live in a static FFmpeg: libva and the NVIDIA
#   driver load their drivers with dlopen, which a static glibc cannot do. They are a second image,
#   target `worker-hw`: the same server binary and a dynamically linked FFmpeg with h264_nvenc
#   (nv-codec-headers, MIT), h264_vaapi (libva, MIT) and h264_qsv (libvpl, MIT), on a Debian base
#   (trixie, which has libvpl and the Intel GPU runtime) that carries the runtime libraries. It adds
#   no --enable-nonfree. The default target stays the static, distroless worker. libvpl exists for
#   amd64 only in Debian, so build `worker-hw` for linux/amd64 (--platform linux/amd64).

ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
ARG GO_IMAGE=golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
# The hardware image is built on Debian trixie: bookworm has no libvpl and no Intel GPU runtime.
ARG DEBIAN_HW_IMAGE=debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

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
        bzip2 ca-certificates cmake curl g++ gcc libc6-dev make meson nasm ninja-build pkg-config xz-utils \
    && rm -rf /var/lib/apt/lists/*
# fetch URL SHA256 DEST: download with retries (a flaky TLS handshake is retried, not fatal), then
# verify the pinned checksum. The pins are in each RUN's text, so a cached layer is reused without
# touching the network; only a pin change downloads again.
RUN printf '%s\n' '#!/bin/sh' 'set -eu' \
        'curl -fsSL --proto =https --tlsv1.2 --retry 6 --retry-all-errors --retry-delay 10 --connect-timeout 30 --max-time 900 --create-dirs -o "$3" "$1"' \
        'echo "$2  $3" | sha256sum -c -' > /usr/local/bin/fetch \
    && chmod 0755 /usr/local/bin/fetch
ENV PREFIX=/opt/deps

# ---------------------------------------------------------------------------------------------
# x264 (GPL-2.0-or-later): the `stable` branch at a fixed commit.
FROM toolchain AS x264
ARG X264_COMMIT=b35605ace3ddf7c1a5d67a2eb553f034aef41d55
ARG X264_SHA256=6eeb82934e69fd51e043bd8c5b0d152839638d1ce7aa4eea65a3fedcf83ff224
RUN fetch https://code.videolan.org/videolan/x264/-/archive/${X264_COMMIT}/x264-${X264_COMMIT}.tar.bz2 \
        ${X264_SHA256} /src/x264.tar.bz2
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
RUN fetch https://downloads.videolan.org/pub/videolan/dav1d/${DAV1D_VERSION}/dav1d-${DAV1D_VERSION}.tar.xz \
        ${DAV1D_SHA256} /src/dav1d.tar.xz
RUN mkdir /src/dav1d && tar -xJf /src/dav1d.tar.xz -C /src/dav1d --strip-components=1
WORKDIR /src/dav1d
RUN meson setup build --prefix=${PREFIX} --libdir=lib --buildtype=release --default-library=static \
        -Denable_tools=false -Denable_examples=false -Denable_tests=false -Denable_docs=false \
    && ninja -C build install

# ---------------------------------------------------------------------------------------------
# x265 (GPL-2.0-or-later): the HEVC software encoder, 8-bit only, static, no command line tool.
FROM toolchain AS x265
ARG X265_VERSION=4.1
ARG X265_SHA256=a31699c6a89806b74b0151e5e6a7df65de4b49050482fe5ebf8a4379d7af8f29
RUN fetch https://download.videolan.org/pub/videolan/x265/x265_${X265_VERSION}.tar.gz \
        ${X265_SHA256} /src/x265.tar.gz
RUN mkdir /src/x265 && tar -xzf /src/x265.tar.gz -C /src/x265 --strip-components=1
WORKDIR /src/x265/build
RUN cmake ../source -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=${PREFIX} -DCMAKE_INSTALL_LIBDIR=lib \
        -DENABLE_SHARED=OFF -DENABLE_CLI=OFF -DENABLE_PIC=OFF -DENABLE_HDR10_PLUS=OFF \
    && ninja && ninja install \
    # Two repairs to the pkg-config file, which FFmpeg's configure ("x265 >= 2.6", then a static link test)
    # reads: a release tarball has no version control data, so the version comes out empty; and CMake lists
    # the shared libgcc_s among the libraries to link, which does not exist in a static link (libgcc is there).
    && sed -i -e "s/^Version:.*/Version: ${X265_VERSION}/" -e "/^Libs.private:/s/ -lgcc_s//g" ${PREFIX}/lib/pkgconfig/x265.pc

# ---------------------------------------------------------------------------------------------
# SVT-AV1 (BSD-3-Clause-Clear with the AOM patent licence): the AV1 software encoder, static, encoder only.
FROM toolchain AS svtav1
ARG SVTAV1_VERSION=3.1.2
ARG SVTAV1_SHA256=d0d73bfea42fdcc1222272bf2b0e2319e9df5574721298090c3d28315586ecb1
RUN fetch https://gitlab.com/AOMediaCodec/SVT-AV1/-/archive/v${SVTAV1_VERSION}/SVT-AV1-v${SVTAV1_VERSION}.tar.gz \
        ${SVTAV1_SHA256} /src/svtav1.tar.gz
RUN mkdir /src/svtav1 && tar -xzf /src/svtav1.tar.gz -C /src/svtav1 --strip-components=1
WORKDIR /src/svtav1/build
RUN cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=${PREFIX} -DCMAKE_INSTALL_LIBDIR=lib \
        -DBUILD_SHARED_LIBS=OFF -DBUILD_APPS=OFF -DBUILD_DEC=OFF -DBUILD_TESTING=OFF \
    && ninja && ninja install

# ---------------------------------------------------------------------------------------------
# x265 and SVT-AV1 again, for the hardware image. That FFmpeg is linked dynamically as a position-independent
# executable by trixie's gcc 14, which cannot use the two static libraries above: x265 is built without PIC
# there (its assembly then cannot go into a PIE) and SVT-AV1's archive holds LTO bytecode from gcc 12. So these
# are the same sources with PIC on and LTO off.
FROM toolchain AS x265-hw
ARG X265_VERSION=4.1
ARG X265_SHA256=a31699c6a89806b74b0151e5e6a7df65de4b49050482fe5ebf8a4379d7af8f29
RUN fetch https://download.videolan.org/pub/videolan/x265/x265_${X265_VERSION}.tar.gz \
        ${X265_SHA256} /src/x265.tar.gz
RUN mkdir /src/x265 && tar -xzf /src/x265.tar.gz -C /src/x265 --strip-components=1
WORKDIR /src/x265/build
RUN cmake ../source -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=${PREFIX} -DCMAKE_INSTALL_LIBDIR=lib \
        -DENABLE_SHARED=OFF -DENABLE_CLI=OFF -DENABLE_PIC=ON -DENABLE_HDR10_PLUS=OFF \
    && ninja && ninja install \
    && sed -i -e "s/^Version:.*/Version: ${X265_VERSION}/" -e "/^Libs.private:/s/ -lgcc_s//g" ${PREFIX}/lib/pkgconfig/x265.pc

FROM toolchain AS svtav1-hw
ARG SVTAV1_VERSION=3.1.2
ARG SVTAV1_SHA256=d0d73bfea42fdcc1222272bf2b0e2319e9df5574721298090c3d28315586ecb1
RUN fetch https://gitlab.com/AOMediaCodec/SVT-AV1/-/archive/v${SVTAV1_VERSION}/SVT-AV1-v${SVTAV1_VERSION}.tar.gz \
        ${SVTAV1_SHA256} /src/svtav1.tar.gz
RUN mkdir /src/svtav1 && tar -xzf /src/svtav1.tar.gz -C /src/svtav1 --strip-components=1
WORKDIR /src/svtav1/build
RUN cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=${PREFIX} -DCMAKE_INSTALL_LIBDIR=lib \
        -DBUILD_SHARED_LIBS=OFF -DBUILD_APPS=OFF -DBUILD_DEC=OFF -DBUILD_TESTING=OFF -DSVT_AV1_LTO=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    && ninja && ninja install

# ---------------------------------------------------------------------------------------------
# FFmpeg source, verified once and shared by the two builds below.
FROM toolchain AS ffmpeg-src
ARG FFMPEG_VERSION=9.0.2
ARG FFMPEG_SHA256=8c3850283eb25fa026482078a04051e0be17347b09ef81a0849bec15a96e002e
# FFMPEG_URL can point at an HTTPS mirror; the checksum is verified either way.
ARG FFMPEG_URL=https://ffmpeg.org/releases/ffmpeg-${FFMPEG_VERSION}.tar.xz
RUN fetch "${FFMPEG_URL}" ${FFMPEG_SHA256} /src/ffmpeg.tar.xz
RUN mkdir /src/ffmpeg && tar -xJf /src/ffmpeg.tar.xz -C /src/ffmpeg --strip-components=1

# ---------------------------------------------------------------------------------------------
# The shipped FFmpeg: only what ADR 0024 lists.
#   input   protocols file,pipe; demuxers mov (MP4/MOV), matroska (MKV/WebM), rawvideo (the face masker
#           pipes raw frames in, ADR 0036)
#   decode  h264 hevc vp8 vp9 libdav1d(av1) aac opus mp3 (+ parsers)
#   encode  libx264, libx265 (HEVC), libsvtav1 (AV1), aac; mjpeg (poster and sprite JPEGs, ADR 0046)
#   output  muxers mp4 and hls (fMP4 segments); null (decode checks and tests); image2 (JPEG files)
#   filters scale format aresample null anull setsar fps split trim setpts tile overlay colorchannelmixer (the brand logo,
#           ADR 0049: it arrives as raw RGBA pixels through the rawvideo demuxer, so no PNG decoder and no zlib are
#           built); transpose hflip vflip apply the display
#           matrix rotation (FFmpeg's autorotate inserts them); ffmpeg adds aformat/trim/etc itself.
# Not built: network protocols, devices, every other codec, container and filter, zlib/bzlib/iconv
# (so compressed MP4 headers and Matroska header compression are rejected).
# --disable-pic: with x265 and SVT-AV1 in, a position-independent static link on aarch64 overflows the 32 KiB
# range its libm.a's GOT-relative relocations reach ("relocation truncated to fit R_AARCH64_LD64_GOTPAGE_LO15").
# A static executable needs no PIC, so FFmpeg and x265 are built without it.
FROM ffmpeg-src AS ffmpeg
COPY --from=x264 /opt/deps /opt/deps
COPY --from=dav1d /opt/deps /opt/deps
COPY --from=x265 /opt/deps /opt/deps
COPY --from=svtav1 /opt/deps /opt/deps
ENV PKG_CONFIG_PATH=/opt/deps/lib/pkgconfig
WORKDIR /src/ffmpeg
RUN ./configure \
        --prefix=/opt/ffmpeg \
        --pkg-config-flags=--static \
        --extra-cflags=-I/opt/deps/include \
        --extra-ldflags="-L/opt/deps/lib -static" \
        --disable-everything --disable-network --disable-autodetect --disable-doc --disable-debug --disable-pic \
        --disable-ffplay --disable-avdevice \
        --enable-gpl --enable-libx264 --enable-libx265 --enable-libsvtav1 --enable-libdav1d \
        --enable-protocol=file,pipe \
        --enable-demuxer=mov,matroska,rawvideo \
        --enable-decoder=h264,hevc,vp8,vp9,libdav1d,aac,opus,mp3,mp3float,rawvideo \
        --enable-parser=h264,hevc,vp8,vp9,av1,aac,opus,mpegaudio \
        --enable-encoder=libx264,libx265,libsvtav1,aac,mjpeg \
        --enable-muxer=mp4,hls,null,image2 \
        --enable-filter=scale,format,aresample,null,anull,setsar,fps,split,transpose,hflip,vflip,trim,setpts,tile,overlay,colorchannelmixer \
    && make -j"$(nproc)" \
    && make install \
    && strip /opt/ffmpeg/bin/ffmpeg /opt/ffmpeg/bin/ffprobe \
    && (ldd /opt/ffmpeg/bin/ffmpeg 2>&1 | grep -q 'not a dynamic executable') \
    && (ldd /opt/ffmpeg/bin/ffprobe 2>&1 | grep -q 'not a dynamic executable') \
    && /opt/ffmpeg/bin/ffmpeg -hide_banner -buildconf > /opt/ffmpeg/buildconf.txt

# ---------------------------------------------------------------------------------------------
# Toolchain of the hardware image: Debian trixie from the same snapshot date, with the same fetch helper.
FROM ${DEBIAN_HW_IMAGE} AS toolchain-hw
ARG DEBIAN_SNAPSHOT=20261101T000000Z
RUN rm -f /etc/apt/sources.list.d/* /etc/apt/sources.list \
    && echo "deb http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ trixie main" > /etc/apt/sources.list \
    && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99snapshot \
    && echo 'Acquire::Retries "5";' >> /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates g++ gcc libc6-dev make nasm pkg-config xz-utils libva-dev libvpl-dev \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------------------------
# nv-codec-headers (MIT): the header-only NVENC interface. FFmpeg loads libnvidia-encode.so at run
# time (dlopen), so nothing from NVIDIA is linked or shipped. n12.2.72.0 needs driver 550.54 or newer.
FROM toolchain AS nvcodec
ARG NVCODEC_VERSION=n12.2.72.0
ARG NVCODEC_SHA256=dbeaec433d93b850714760282f1d0992b1254fc3b5a6cb7d76fc1340a1e47563
RUN fetch https://github.com/FFmpeg/nv-codec-headers/archive/refs/tags/${NVCODEC_VERSION}.tar.gz \
        ${NVCODEC_SHA256} /src/nvcodec.tar.gz
RUN mkdir /src/nvcodec && tar -xzf /src/nvcodec.tar.gz -C /src/nvcodec --strip-components=1
WORKDIR /src/nvcodec
RUN make install PREFIX=${PREFIX}

# ---------------------------------------------------------------------------------------------
# The hardware-capable FFmpeg: the build above plus the NVENC, VAAPI and QSV encoders of H.264, HEVC and
# AV1 (h264_*, hevc_*, av1_*) and the hwupload filter. Linked dynamically, against glibc, libva and libvpl
# only (x264, x265, SVT-AV1 and dav1d stay static, built in the bookworm stages; x265 is C++, so its
# static library takes libstdc++ along dynamically, as libvpl does). The readelf check below fails the build
# if any other shared library appears. libva and libvpl are the
# Debian trixie packages of the pinned snapshot (MIT).
FROM toolchain-hw AS ffmpeg-hw
COPY --from=ffmpeg-src /src/ffmpeg /src/ffmpeg
COPY --from=x264 /opt/deps /opt/deps
COPY --from=dav1d /opt/deps /opt/deps
COPY --from=x265-hw /opt/deps /opt/deps
COPY --from=svtav1-hw /opt/deps /opt/deps
COPY --from=nvcodec /opt/deps /opt/deps
ENV PKG_CONFIG_PATH=/opt/deps/lib/pkgconfig
WORKDIR /src/ffmpeg
# --pkg-config-flags=--static: x265 and SVT-AV1 are static libraries here, and the libraries they need (libstdc++,
# libm) are only in their pkg-config files' private lists.
RUN ./configure \
        --prefix=/opt/ffmpeg-hw \
        --pkg-config-flags=--static \
        --extra-cflags=-I/opt/deps/include \
        --extra-ldflags="-L/opt/deps/lib" \
        --disable-everything --disable-network --disable-autodetect --disable-doc --disable-debug \
        --disable-ffplay --disable-avdevice \
        --enable-gpl --enable-libx264 --enable-libx265 --enable-libsvtav1 --enable-libdav1d \
        --enable-ffnvcodec --enable-nvenc --enable-vaapi --enable-libvpl \
        --enable-protocol=file,pipe \
        --enable-demuxer=mov,matroska,rawvideo \
        --enable-decoder=h264,hevc,vp8,vp9,libdav1d,aac,opus,mp3,mp3float,rawvideo \
        --enable-parser=h264,hevc,vp8,vp9,av1,aac,opus,mpegaudio \
        --enable-encoder=libx264,libx265,libsvtav1,aac,mjpeg,h264_nvenc,h264_vaapi,h264_qsv,hevc_nvenc,hevc_vaapi,hevc_qsv,av1_nvenc,av1_vaapi,av1_qsv \
        --enable-muxer=mp4,hls,null,image2 \
        --enable-filter=scale,format,aresample,null,anull,setsar,fps,split,transpose,hflip,vflip,trim,setpts,tile,overlay,colorchannelmixer,hwupload \
    && make -j"$(nproc)" \
    && make install \
    && strip /opt/ffmpeg-hw/bin/ffmpeg /opt/ffmpeg-hw/bin/ffprobe \
    && /opt/ffmpeg-hw/bin/ffmpeg -hide_banner -buildconf > /opt/ffmpeg-hw/buildconf.txt

# The build's own checks, in a stage of their own so a failed check does not repeat the compile.
FROM ffmpeg-hw AS ffmpeg-hw-checked
RUN readelf -d /opt/ffmpeg-hw/bin/ffmpeg | sed -n 's/.*Shared library: \[\(.*\)\]/\1/p' | sort > /tmp/needed \
    && cat /tmp/needed \
    && ! grep -vE '^(ld-linux|libc\.so|libm\.so|libmvec\.so|libdl\.so|libpthread\.so|librt\.so|libva\.so|libva-drm\.so|libvpl\.so|libstdc\+\+\.so|libgcc_s\.so)' /tmp/needed \
    && /opt/ffmpeg-hw/bin/ffmpeg -hide_banner -encoders > /tmp/encoders \
    && for e in h264_nvenc h264_vaapi h264_qsv hevc_nvenc hevc_vaapi hevc_qsv av1_nvenc av1_vaapi av1_qsv libx264 libx265 libsvtav1 aac mjpeg; do grep -qw "$e" /tmp/encoders || { echo "missing encoder $e" >&2; exit 1; }; done \
    && /opt/ffmpeg-hw/bin/ffmpeg -hide_banner -filters | grep -qw hwupload

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
        --enable-filter=testsrc2,mandelbrot,sine,anullsrc,scale,format,aresample,null,anull,setsar,fps,ssim,psnr \
    && make -j"$(nproc)" \
    && make install \
    && strip /opt/ffmpeg-fixtures/bin/ffmpeg \
    && (ldd /opt/ffmpeg-fixtures/bin/ffmpeg 2>&1 | grep -q 'not a dynamic executable')

# ---------------------------------------------------------------------------------------------
# Measurement only (docs/codecs.md): libvmaf (BSD-2-Clause-Patent) and an FFmpeg that can decode what the
# worker writes and score it. It never ships; the build exports it with `--target measure`. The worker's
# own FFmpeg makes the renditions; this one, and its ffprobe (which can read the HLS output), only compare
# them with the source and read their keyframes.
FROM toolchain AS vmaf
# libvmaf embeds its models with xxd and silently builds without them when it is missing.
RUN apt-get update && apt-get install -y --no-install-recommends xxd && rm -rf /var/lib/apt/lists/*
ARG VMAF_VERSION=3.0.0
ARG VMAF_SHA256=7178c4833639e6b989ecae73131d02f70735fdb3fc2c7d84bc36c9c3461d93b1
RUN fetch https://github.com/Netflix/vmaf/archive/refs/tags/v${VMAF_VERSION}.tar.gz \
        ${VMAF_SHA256} /src/vmaf.tar.gz
RUN mkdir /src/vmaf && tar -xzf /src/vmaf.tar.gz -C /src/vmaf --strip-components=1
WORKDIR /src/vmaf/libvmaf
RUN meson setup build --prefix=${PREFIX} --libdir=lib --buildtype=release --default-library=static \
        -Denable_tests=false -Denable_docs=false -Dbuilt_in_models=true \
    && ninja -C build install \
    # libvmaf's SVM code is C++ but its pkg-config file does not say so, which a static link needs.
    && sed -i '/^Libs:/s/$/ -lstdc++/' ${PREFIX}/lib/pkgconfig/libvmaf.pc

FROM ffmpeg-src AS ffmpeg-measure
COPY --from=dav1d /opt/deps /opt/deps
COPY --from=vmaf /opt/deps /opt/deps
ENV PKG_CONFIG_PATH=/opt/deps/lib/pkgconfig
WORKDIR /src/ffmpeg
RUN ./configure \
        --prefix=/opt/ffmpeg-measure \
        --pkg-config-flags=--static \
        --extra-cflags=-I/opt/deps/include \
        --extra-ldflags="-L/opt/deps/lib -static" \
        --disable-everything --disable-network --disable-autodetect --disable-doc --disable-debug --disable-pic \
        --disable-ffplay --disable-avdevice \
        --enable-gpl --enable-libdav1d --enable-libvmaf \
        --enable-protocol=file,pipe \
        --enable-demuxer=mov,hls \
        --enable-decoder=h264,hevc,libdav1d \
        --enable-parser=h264,hevc,av1 \
        --enable-encoder=wrapped_avframe \
        --enable-muxer=null \
        --enable-filter=scale,format,setsar,setpts,null,libvmaf \
    && make -j"$(nproc)" \
    && make install \
    && strip /opt/ffmpeg-measure/bin/ffmpeg /opt/ffmpeg-measure/bin/ffprobe \
    && (ldd /opt/ffmpeg-measure/bin/ffmpeg 2>&1 | grep -q 'not a dynamic executable') \
    && (ldd /opt/ffmpeg-measure/bin/ffprobe 2>&1 | grep -q 'not a dynamic executable')

# ---------------------------------------------------------------------------------------------
# Licence texts and the written source offer.
FROM ffmpeg AS licenses
ARG FFMPEG_VERSION=9.0.2
ARG FFMPEG_SHA256=8c3850283eb25fa026482078a04051e0be17347b09ef81a0849bec15a96e002e
ARG X264_COMMIT=b35605ace3ddf7c1a5d67a2eb553f034aef41d55
ARG X264_SHA256=6eeb82934e69fd51e043bd8c5b0d152839638d1ce7aa4eea65a3fedcf83ff224
ARG DAV1D_VERSION=1.5.4
ARG DAV1D_SHA256=686616b7c69eb88d44459391ab25cac13b6647a3b288835c5784e71c1514a5c5
ARG X265_VERSION=4.1
ARG X265_SHA256=a31699c6a89806b74b0151e5e6a7df65de4b49050482fe5ebf8a4379d7af8f29
ARG SVTAV1_VERSION=3.1.2
ARG SVTAV1_SHA256=d0d73bfea42fdcc1222272bf2b0e2319e9df5574721298090c3d28315586ecb1
ARG DEBIAN_SNAPSHOT=20261101T000000Z
COPY --from=x264 /src/x264/COPYING /out/x264-COPYING
COPY --from=dav1d /src/dav1d/COPYING /out/dav1d-COPYING
COPY --from=x265 /src/x265/COPYING /out/x265-COPYING
COPY --from=svtav1 /src/svtav1/LICENSE.md /src/svtav1/PATENTS.md /out/
COPY build/worker-SOURCE.md.in /tmp/SOURCE.md.in
RUN mkdir -p /out/licenses \
    && cp /src/ffmpeg/COPYING.GPLv2 /src/ffmpeg/COPYING.GPLv3 /src/ffmpeg/COPYING.LGPLv2.1 \
          /src/ffmpeg/COPYING.LGPLv3 /src/ffmpeg/LICENSE.md /src/ffmpeg/CREDITS /out/licenses/ \
    && cp /out/x264-COPYING /out/licenses/x264-COPYING.GPLv2 \
    && cp /out/dav1d-COPYING /out/licenses/dav1d-COPYING.BSD-2-Clause \
    && cp /out/x265-COPYING /out/licenses/x265-COPYING.GPLv2 \
    && cp /out/LICENSE.md /out/licenses/svtav1-LICENSE.md \
    && cp /out/PATENTS.md /out/licenses/svtav1-PATENTS.md \
    && cp /usr/share/doc/libc6/copyright /out/licenses/glibc-copyright \
    && cp /usr/share/common-licenses/LGPL-2.1 /out/licenses/glibc-LGPL-2.1 \
    && LIBC_VERSION="$(dpkg-query -W -f='${Version}' libc6)" \
    && sed -e "s|@FFMPEG_VERSION@|${FFMPEG_VERSION}|g" -e "s|@FFMPEG_SHA256@|${FFMPEG_SHA256}|g" \
           -e "s|@X264_COMMIT@|${X264_COMMIT}|g" -e "s|@X264_SHA256@|${X264_SHA256}|g" \
           -e "s|@DAV1D_VERSION@|${DAV1D_VERSION}|g" -e "s|@DAV1D_SHA256@|${DAV1D_SHA256}|g" \
           -e "s|@X265_VERSION@|${X265_VERSION}|g" -e "s|@X265_SHA256@|${X265_SHA256}|g" \
           -e "s|@SVTAV1_VERSION@|${SVTAV1_VERSION}|g" -e "s|@SVTAV1_SHA256@|${SVTAV1_SHA256}|g" \
           -e "s|@DEBIAN_SNAPSHOT@|${DEBIAN_SNAPSHOT}|g" -e "s|@LIBC_VERSION@|${LIBC_VERSION}|g" \
           -e '/@BUILDCONF@/{r /opt/ffmpeg/buildconf.txt' -e 'd}' \
           /tmp/SOURCE.md.in > /out/licenses/SOURCE.md

# ---------------------------------------------------------------------------------------------
# Licence texts and the written source offer of the hardware image.
FROM ffmpeg-hw-checked AS licenses-hw
ARG FFMPEG_VERSION=9.0.2
ARG FFMPEG_SHA256=8c3850283eb25fa026482078a04051e0be17347b09ef81a0849bec15a96e002e
ARG X264_COMMIT=b35605ace3ddf7c1a5d67a2eb553f034aef41d55
ARG X264_SHA256=6eeb82934e69fd51e043bd8c5b0d152839638d1ce7aa4eea65a3fedcf83ff224
ARG DAV1D_VERSION=1.5.4
ARG DAV1D_SHA256=686616b7c69eb88d44459391ab25cac13b6647a3b288835c5784e71c1514a5c5
ARG NVCODEC_VERSION=n12.2.72.0
ARG NVCODEC_SHA256=dbeaec433d93b850714760282f1d0992b1254fc3b5a6cb7d76fc1340a1e47563
ARG X265_VERSION=4.1
ARG X265_SHA256=a31699c6a89806b74b0151e5e6a7df65de4b49050482fe5ebf8a4379d7af8f29
ARG SVTAV1_VERSION=3.1.2
ARG SVTAV1_SHA256=d0d73bfea42fdcc1222272bf2b0e2319e9df5574721298090c3d28315586ecb1
ARG DEBIAN_SNAPSHOT=20261101T000000Z
COPY --from=x264 /src/x264/COPYING /out/x264-COPYING
COPY --from=dav1d /src/dav1d/COPYING /out/dav1d-COPYING
COPY --from=x265 /src/x265/COPYING /out/x265-COPYING
COPY --from=svtav1 /src/svtav1/LICENSE.md /src/svtav1/PATENTS.md /out/
COPY --from=nvcodec /src/nvcodec/README /out/nvcodec-README
COPY build/worker-hw-SOURCE.md.in /tmp/SOURCE.md.in
RUN mkdir -p /out/licenses \
    && cp /src/ffmpeg/COPYING.GPLv2 /src/ffmpeg/COPYING.GPLv3 /src/ffmpeg/COPYING.LGPLv2.1 \
          /src/ffmpeg/COPYING.LGPLv3 /src/ffmpeg/LICENSE.md /src/ffmpeg/CREDITS /out/licenses/ \
    && cp /out/x264-COPYING /out/licenses/x264-COPYING.GPLv2 \
    && cp /out/dav1d-COPYING /out/licenses/dav1d-COPYING.BSD-2-Clause \
    && cp /out/x265-COPYING /out/licenses/x265-COPYING.GPLv2 \
    && cp /out/LICENSE.md /out/licenses/svtav1-LICENSE.md \
    && cp /out/PATENTS.md /out/licenses/svtav1-PATENTS.md \
    && cp /usr/share/doc/libva-dev/copyright /out/licenses/libva-copyright \
    && cp /usr/share/doc/libvpl-dev/copyright /out/licenses/libvpl-copyright \
    && LIBVA_VERSION="$(dpkg-query -W -f='${Version}' libva-dev)" \
    && LIBVPL_VERSION="$(dpkg-query -W -f='${Version}' libvpl-dev)" \
    && sed -e "s|@FFMPEG_VERSION@|${FFMPEG_VERSION}|g" -e "s|@FFMPEG_SHA256@|${FFMPEG_SHA256}|g" \
           -e "s|@X264_COMMIT@|${X264_COMMIT}|g" -e "s|@X264_SHA256@|${X264_SHA256}|g" \
           -e "s|@DAV1D_VERSION@|${DAV1D_VERSION}|g" -e "s|@DAV1D_SHA256@|${DAV1D_SHA256}|g" \
           -e "s|@X265_VERSION@|${X265_VERSION}|g" -e "s|@X265_SHA256@|${X265_SHA256}|g" \
           -e "s|@SVTAV1_VERSION@|${SVTAV1_VERSION}|g" -e "s|@SVTAV1_SHA256@|${SVTAV1_SHA256}|g" \
           -e "s|@NVCODEC_VERSION@|${NVCODEC_VERSION}|g" -e "s|@NVCODEC_SHA256@|${NVCODEC_SHA256}|g" \
           -e "s|@LIBVA_VERSION@|${LIBVA_VERSION}|g" -e "s|@LIBVPL_VERSION@|${LIBVPL_VERSION}|g" \
           -e "s|@DEBIAN_SNAPSHOT@|${DEBIAN_SNAPSHOT}|g" \
           -e '/@BUILDCONF@/{r /opt/ffmpeg-hw/buildconf.txt' -e 'd}' \
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
# Measurement: the scoring FFmpeg (docker build --target measure --output type=local,dest=out/measure).
FROM scratch AS measure
COPY --from=ffmpeg-measure /opt/ffmpeg-measure/bin/ffmpeg /ffmpeg-vmaf
COPY --from=ffmpeg-measure /opt/ffmpeg-measure/bin/ffprobe /ffprobe-vmaf

# ---------------------------------------------------------------------------------------------
# The hardware worker image (docker build --target worker-hw). Debian, not distroless: libva and the
# NVIDIA runtime load drivers with dlopen. Runtime pieces, all from the pinned snapshot:
#   libva2, libva-drm2  the VAAPI client
#   libvpl2, libmfx-gen1.2  the oneVPL dispatcher and its Intel GPU runtime (Quick Sync)
#   intel-media-va-driver   the Intel VAAPI driver; mesa-va-drivers  the AMD VAAPI driver
# This target is for linux/amd64: libvpl and the Intel packages are not built for arm64 in Debian.
# NVENC needs the host's NVIDIA driver and the NVIDIA container runtime, which mounts
# libnvidia-encode.so into the container; nothing from NVIDIA is in the image.
FROM ${DEBIAN_HW_IMAGE} AS worker-hw
ARG DEBIAN_SNAPSHOT=20261101T000000Z
RUN rm -f /etc/apt/sources.list.d/* /etc/apt/sources.list \
    && echo "deb http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ trixie main" > /etc/apt/sources.list \
    && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99snapshot \
    && echo 'Acquire::Retries "5";' >> /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get install -y --no-install-recommends libva2 libva-drm2 libvpl2 mesa-va-drivers \
        libmfx-gen1.2 intel-media-va-driver \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 65532 --no-create-home --shell /usr/sbin/nologin nonroot
COPY --from=ffmpeg-hw-checked /opt/ffmpeg-hw/bin/ffmpeg /opt/ffmpeg-hw/bin/ffprobe /usr/local/bin/
COPY --from=server /out/cipherframe-server /usr/local/bin/cipherframe-server
COPY --from=licenses-hw /out/licenses/ /usr/share/licenses/ffmpeg/
ENV CIPHERFRAME_FFMPEG_PATH=/usr/local/bin/ffmpeg \
    CIPHERFRAME_FFPROBE_PATH=/usr/local/bin/ffprobe \
    NVIDIA_DRIVER_CAPABILITIES=compute,video,utility
USER 65532
ENTRYPOINT ["/usr/local/bin/cipherframe-server"]
CMD ["--role=worker"]

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
