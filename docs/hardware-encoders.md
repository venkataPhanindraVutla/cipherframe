# Hardware encoders

By default the worker encodes every rendition with libx264 (ADR 0024). A worker on a machine with a
GPU or a media engine can encode with it instead: `CIPHERFRAME_WORKER_ENCODER` picks `nvenc`, `vaapi`,
`qsv` or `videotoolbox` (ADR 0063, ADR 0066). Only the encode moves to the hardware; decoding,
scaling, the face masker's output and the brand logo stay in software, and the filter graph is the
same for every encoder.

| Encoder | Hardware | FFmpeg encoder | Where it runs | Status |
| --- | --- | --- | --- | --- |
| `software` | any CPU | `libx264` | every image | default, measured by the existing tests |
| `videotoolbox` | Apple silicon and Intel Macs | `h264_videotoolbox` | a native worker on macOS with your own FFmpeg | **measured** on an Apple silicon Mac (below) |
| `nvenc` | NVIDIA GPUs | `h264_nvenc` | `worker-hw` image with the NVIDIA container runtime | **not verified on hardware** |
| `vaapi` | Intel and AMD GPUs on Linux | `h264_vaapi` | `worker-hw` image with `/dev/dri` | **not verified on hardware** |
| `qsv` | Intel Quick Sync | `h264_qsv` | `worker-hw` image with `/dev/dri` | **not verified on hardware** |

"Not verified" means the arguments are covered by unit tests, the image builds, and the startup test and
the fallback are tested with a fake FFmpeg, but nobody has run the encoder on a real device. Their quality
values (`-cq 23`, `-global_quality 23`) are libx264's CRF carried over, not tuned. Run the measurement
below on your hardware before you rely on them.

## What every encoder gets

One FFmpeg process makes the whole ladder (decode once, split, scale, encode per rung). For every encoder:

- a keyframe at the first frame at or after every multiple of 2 seconds (`-force_key_frames
  expr:gte(t,n_forced*2)`, `-g` equal to two seconds of frames) as an IDR frame, and the encoder's own
  switches against extra keyframes (scene-cut detection off), so every rung cuts its 6 second segments at
  the same frames (pitfall 4);
- the rung's `maxrate` and `bufsize` from the ladder;
- a constant-quality mode:

| Encoder | Arguments of a 720p rung (30 fps) |
| --- | --- |
| `software` | `-c:v libx264 -profile:v high -preset medium -crf 23 -maxrate 2500k -bufsize 5000k -g 60 -keyint_min 60 -sc_threshold 0 -x264-params open-gop=0 -forced-idr 1` |
| `nvenc` | `-c:v h264_nvenc -profile:v high -preset p5 -rc vbr -cq 23 -b:v 0 -maxrate 2500k -bufsize 5000k -no-scenecut 1 -forced-idr 1 -strict_gop 1 -g 60` |
| `vaapi` | `-c:v h264_vaapi -profile:v high -rc_mode QVBR -global_quality 23 -b:v 2500k -maxrate 2500k -bufsize 5000k -idr_interval 0 -g 60` |
| `qsv` | `-c:v h264_qsv -profile:v high -preset medium -global_quality 23 -look_ahead 0 -maxrate 2500k -bufsize 5000k -adaptive_i 0 -adaptive_b 0 -idr_interval 0 -forced_idr 1 -g 60` |
| `videotoolbox` | `-c:v h264_videotoolbox -profile:v high -q:v 60 -realtime 0 -allow_sw 0 -maxrate 2500k -bufsize 5000k -g 60` |

(each followed by `-force_key_frames expr:gte(t,n_forced*2) -fps_mode cfr`). VAAPI and QSV encode from device
memory, so the end of each rendition's filter chain is `format=nv12,hwupload` and the device is opened
before the input (`-init_hw_device vaapi=hw:<device> -filter_hw_device hw`; QSV derives from a VAAPI device on
the same render node). The code is `internal/media/encoder.go`; the golden tests are in `encoder_test.go`.

VideoToolbox has no scene-cut keyframes to turn off. Its `-q:v` scale runs the other way from CRF
(higher is better); `106 - 2*CRF` gives 60 at CRF 23. QVBR (VAAPI) is the constant-quality mode that still
honours a bitrate cap; a driver without it fails the test encode and the worker uses software. QSV's ICQ
(`-global_quality` without a bitrate) may ignore the cap on some runtimes.

## Startup test and fallback

- **At startup** the worker encodes ten blank frames with the selected encoder (the same arguments a
  rendition gets, to the null muxer). If that fails it logs one warning that names only the encoder, counts
  `cipherframe_encoder_fallbacks_total{encoder,stage="startup"}`, and uses libx264 for every job. The
  worker still starts. The shipped FFmpeg has no test-pattern source, so the test frames come from the
  `rawvideo` demuxer reading `/dev/zero`.
- **During a job**, if a hardware transcode fails (not a timeout or a cancel), the worker removes its
  output and runs the whole transcode again with libx264, counts `{stage="job"}`, and logs
  `hardware encode failed; retrying with software` with the encoder name. It is the whole transcode, not
  one rendition: one FFmpeg process makes every rendition, so a failure cannot be pinned to one. The job's
  log lines carry `encoder`, and the signed manifest records the encoder that made the output
  (`encoder.video_codec`, such as `h264_nvenc`; `encoder.preset` is set only for libx264).
- The metric `cipherframe_transcode_duration_seconds` has an `encoder` label (five values) so a dashboard
  can compare encoders.

## Setup

### The `worker-hw` image

The default worker image is static and cannot use a GPU: libva and the NVIDIA runtime load their drivers
with `dlopen`. Build the hardware image instead (linux/amd64; libvpl is not packaged for arm64):

```sh
docker build --platform linux/amd64 -f build/worker.Dockerfile --target worker-hw -t cipherframe-worker-hw .
docker run --rm --entrypoint /usr/local/bin/ffmpeg cipherframe-worker-hw -hide_banner -encoders | grep h264_
```

It carries a dynamically linked FFmpeg 9.0.2 with `h264_nvenc` (through `nv-codec-headers`, MIT, pinned by
checksum), `h264_vaapi` (libva, MIT) and `h264_qsv` (libvpl, MIT) and the `hwupload` filter, on Debian trixie
with the runtime libraries and the Intel and Mesa VAAPI drivers. It adds no `--enable-nonfree`, so it stays
GPL, like the default image; `/usr/share/licenses/ffmpeg/SOURCE.md` lists the sources. The build fails if the
binary needs a shared library beyond glibc, libva, libvpl and the C++ runtime libvpl brings. NVENC is loaded at run time: nothing from NVIDIA
is in the image.

### NVENC (not verified on hardware)

Needs an NVIDIA driver 550.54 or newer on the host (the pinned `nv-codec-headers` n12.2.72.0) and the
[NVIDIA container toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/), which mounts
`libnvidia-encode.so` into the container:

```sh
docker run --gpus all -e CIPHERFRAME_WORKER_ENCODER=nvenc ... cipherframe-worker-hw
```

The image sets `NVIDIA_DRIVER_CAPABILITIES=compute,video,utility`. Helm hint: request `nvidia.com/gpu: 1`
for the worker and set the encoder through the worker's environment values. Consumer GPUs limit the number of
simultaneous NVENC sessions, which bounds `CIPHERFRAME_WORKER_MEDIA_CONCURRENCY`.

### VAAPI and QSV (not verified on hardware)

Pass the render node into the container and let the worker's user open it:

```sh
docker run --device /dev/dri/renderD128 --group-add "$(stat -c %g /dev/dri/renderD128)" \
  -e CIPHERFRAME_WORKER_ENCODER=vaapi -e CIPHERFRAME_WORKER_HW_DEVICE=/dev/dri/renderD128 ... cipherframe-worker-hw
```

`qsv` is the same with `CIPHERFRAME_WORKER_ENCODER=qsv` on an Intel GPU (the image carries the oneVPL GPU
runtime `libmfx-gen`, which supports 11th generation and newer). `vaapi` uses `intel-media-va-driver` or
`mesa-va-drivers` (AMD). `CIPHERFRAME_WORKER_HW_DEVICE` must be a path under `/dev`. Helm hint: mount the host
path `/dev/dri` into the worker pod (a device plugin such as Intel's GPU plugin does the same with a resource
limit) and set the pod's `supplementalGroups` to the group of the render node.

### VideoToolbox (macOS, measured)

Docker on macOS cannot reach VideoToolbox. Run the worker natively on the Mac and point it at an FFmpeg that
has `h264_videotoolbox` (for example Homebrew's):

```sh
export CIPHERFRAME_FFMPEG_PATH=/opt/homebrew/bin/ffmpeg CIPHERFRAME_FFPROBE_PATH=/opt/homebrew/bin/ffprobe
export CIPHERFRAME_WORKER_ENCODER=videotoolbox
cipherframe-server --role=worker
```

The worker's startup check still requires that FFmpeg to have everything ADR 0024 lists (the capability
check), plus the encoder you select. Check the licence of the FFmpeg you supply: Homebrew's is GPL.

## Measurement

Method: `docs/encoder-results/2026-11-23/bench.go` (run with `go run`) builds the ladder with the worker's own
argument builder (`media.TranscodeArgs`), runs one FFmpeg process per encoder and fixture, one at a time, and
records bytes per rung, wall and CPU time of the process, VMAF of each rung against the source scaled to the
rung's size (default model, every third frame), and the keyframe check. Raw numbers:
`docs/encoder-results/2026-11-23/results.json`.

Setup and limits, stated plainly:

- **Machine and FFmpeg.** An Apple silicon Mac. The FFmpeg that had `h264_videotoolbox` and `libvmaf` was a
  6.0 static build from an `ffmpeg-static` package already on the machine (nothing was installed); it is
  built with `--enable-nonfree` and is a measurement tool only, not the project's FFmpeg 9.0.2. Newer FFmpeg
  versions may change VideoToolbox's behaviour.
- **Fixtures.** Two generated sources, 20 s, 1920x1080, 30 fps, with audio: `testsrc2` (the project's test
  pattern: flat colour, hard edges, easy to compress) and `mandelbrot` (continuous fine detail, hard to
  compress). Both are synthetic. They say how the encoders compare on easy and hard content, not what
  camera footage will give; re-run the bench on your own footage.
- **Load.** The machine was shared with other work, so wall times are noisy; CPU time is steadier. Each
  number is one run.
- **VMAF.** Compared at the rung's own size, so it isolates what the encoder lost, not the scaling. It
  scores the video only, and its model was trained for 1080p viewing, so small rungs read generously.

### Results (libx264 CRF 23 preset medium against VideoToolbox `-q:v 60`)

**testsrc2**

| Rung | libx264 kbps | VideoToolbox kbps | size ratio | libx264 VMAF | VideoToolbox VMAF |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1080p | 4743 | 3076 | 0.65 | 95.6 | 92.4 |
| 720p | 1650 | 1745 | 1.06 | 96.2 | 95.7 |
| 480p | 673 | 879 | 1.31 | 96.6 | 96.6 |
| 360p | 403 | 529 | 1.31 | 97.2 | 97.7 |
| 240p | 231 | 312 | 1.35 | 96.8 | 97.2 |

Whole ladder in one FFmpeg process: libx264 9.9 s wall and 53.1 s CPU; VideoToolbox 6.7 s wall and 9.4 s CPU.

**mandelbrot**

| Rung | libx264 kbps | VideoToolbox kbps | size ratio | libx264 VMAF | VideoToolbox VMAF |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1080p | 4696 | 3076 | 0.66 | 82.4 | 65.6 |
| 720p | 2596 | 1745 | 0.67 | 89.8 | 80.8 |
| 480p | 1213 | 878 | 0.72 | 91.6 | 82.6 |
| 360p | 732 | 545 | 0.74 | 92.2 | 82.3 |
| 240p | 383 | 312 | 0.82 | 92.9 | 82.2 |

Whole ladder: libx264 17.5 s wall and 101.7 s CPU; VideoToolbox 6.7 s wall and 16.8 s CPU.

What it shows:

- **Speed.** About 5 to 6 times less CPU time and 1.5 to 2.6 times less wall time for the ladder. The wall
  gain is smaller than the CPU gain because decode, scale and the single process's pacing stay in software.
- **Quality and size.** On easy content VideoToolbox at `-q:v 60` is within about one VMAF point of libx264
  at 720p and below, at 30 to 35 per cent more bytes on the lower rungs. On hard content it falls behind
  (8 to 17 VMAF points at equal or fewer bytes): the rung's `maxrate` cap binds, and VideoToolbox uses only
  about 70 per cent of a cap (3076 kbps under a 4500 kbps cap, 1745 under 2500), where libx264 fills it.
  The 1080p rung is the weakest on both fixtures. Raising `-q:v` does not help once the cap binds.
- **How `-q:v 60` was chosen.** A sweep on 8 s of 720p without caps: libx264 CRF 23 gave 1566 kbps and VMAF
  95.6 on `testsrc2` and 3147 kbps and 90.1 on `mandelbrot`; `-q:v` 50, 60 and 70 gave 911, 1941 and 3615 kbps
  (VMAF 93.2, 96.1, 97.6) and 2224, 4528 and 7990 kbps (VMAF 84.0, 90.9, 94.9). 60 matches libx264's quality
  at a larger size, so it is the default.
- **Keyframes.** On both fixtures the keyframes of the five VideoToolbox renditions are identical and exactly
  2 seconds apart (after the encoder's start delay of 21 ms, libx264's is 66 ms), and the segment durations
  of all rungs agree (`media.CheckAligned`). The `media`-tagged test `TestKeyframesAlignedAcrossRenditions`
  checks the same for the selected encoder:

```sh
CIPHERFRAME_TEST_FFMPEG=... CIPHERFRAME_TEST_FFPROBE=... CIPHERFRAME_TEST_FFMPEG_FIXTURES=... \
CIPHERFRAME_TEST_ENCODER=videotoolbox go test -tags media -run TestKeyframesAlignedAcrossRenditions ./internal/media
```

It skips when the encoder cannot run its test encode (set `CIPHERFRAME_TEST_HW_DEVICE` for VAAPI and QSV).
It passed here for `software` and `videotoolbox` with the 6.0 FFmpeg above.

### Run it on your hardware

```sh
go run docs/encoder-results/2026-11-23/bench.go -ffmpeg F -ffprobe P -work /abs/scratch -out results.json \
  -encoders software,nvenc
```

The FFmpeg needs `libvmaf` and the encoders. Compare size and VMAF per rung, adjust `qualityFor` in
`internal/media/encoder.go` if the hardware's quality at the starting value is far from libx264's, and send
the numbers back so this page can mark the encoder as verified.
