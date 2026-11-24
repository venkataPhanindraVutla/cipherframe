# HEVC and AV1 renditions

By default every asset is encoded in H.264 only. A tenant can add **HEVC** and **AV1** renditions with the
`extra_codecs` setting (M10-3, [ADR 0064](adr/0064-hevc-and-av1-renditions.md) for the decision,
[ADR 0067](adr/0067-hevc-av1-implementation.md) for the details). Each extra codec adds a full ladder of
renditions to the same master playlist; H.264 always keeps its full ladder, so every player has something it
can decode. The setting is off until someone turns it on, and nothing here changes anything for a tenant that
does not.

## Setup

**The worker.** The `cipherframe-worker` and `cipherframe-worker-hw` images carry libx265 (HEVC) and SVT-AV1 (AV1),
and `worker-hw` also the NVENC, VAAPI and QSV encoders of both codecs
([hardware-encoders.md](hardware-encoders.md)). Check an image or your own FFmpeg:

```sh
docker run --rm --entrypoint /usr/local/bin/ffmpeg cipherframe-worker -hide_banner -encoders | grep -E 'libx265|libsvtav1'
```

A worker logs `extra codecs this worker can encode` at startup and then tells the database every minute (the
`worker_capabilities` table, one row per worker process). If you run your own FFmpeg without these encoders the
worker still starts and makes H.264 only; it just does not report the codec.

**The setting.** `PUT /v1/playback-settings` replaces every setting, so send the current ones with `extra_codecs`
changed (the API key is read from the environment, never typed on the command line):

```sh
export CIPHERFRAME_API_KEY=...        # an admin key
curl -fsS -H "Authorization: Bearer $CIPHERFRAME_API_KEY" "$API/v1/playback-settings" \
  | jq 'del(.updated_at) | .extra_codecs = ["hevc", "av1"]' \
  | curl -fsS -X PUT -H "Authorization: Bearer $CIPHERFRAME_API_KEY" -H 'Content-Type: application/json' -d @- "$API/v1/playback-settings"
```

The call is refused with `invalid_request` and a field error on `extra_codecs[0]` (and so on) when no worker seen
in the last 5 minutes reports that codec. A codec that is already on is not checked again.

**Which assets.** Only uploads created after the setting changes: the setting is copied onto the asset when it is
created, and existing assets are not re-encoded. `GET /v1/assets/{id}` shows `extra_codecs.requested` (what the
asset asked for) and, once it is `ready`, `extra_codecs.failed` (the codecs it did not get, each with a reason:
`encoder_unavailable`, `transcode_failed`, `transcode_timeout` or `output_invalid`). A failed codec never fails
the asset: it is `ready` and playable in H.264, and `cipherframe_extra_codec_failures_total` counts the failure.

## What a viewer gets

One master playlist lists every variant, H.264 first, then HEVC, then AV1, each with an accurate `CODECS`
attribute read from the encoded stream (`avc1.64001f`, `hvc1.1.6.L120.90`, `av01.0.08M.08`, then `mp4a.40.2`).
Renditions of an extra codec are named `720p_hevc` and `720p_av1` beside H.264's `720p`. There is no codec
setting in the API or the player: the player (hls.js, Safari's native HLS) drops the variants the browser cannot
decode and plays one it can. Segments are CMAF/fMP4 encrypted with AES-128 like H.264's; HEVC uses the `hvc1`
sample entry (Apple players need it) and AV1 `av01`.

### Player support

What a browser decodes depends on its version, the operating system and the hardware, and changes; this table is
what to expect, not a promise. A player that cannot decode a codec simply plays another one from the same master.

| Player | H.264 | HEVC | AV1 |
| --- | --- | --- | --- |
| Chrome, Edge (hls.js) | yes | when the OS or GPU decodes it | yes (software decoder, hardware where present) |
| Firefox (hls.js) | yes | when the OS or GPU decodes it | yes |
| Safari, iOS (native HLS or hls.js) | yes | yes | recent Apple hardware only |
| Android (Chrome, ExoPlayer) | yes | most devices | recent devices, or a software decoder |
| Chromium in CI (the player's end-to-end test) | yes | not assumed | yes |

hls.js picks among the codecs a browser can decode by its own rules (it prefers the best codec the device can play
smoothly, which is why a browser that decodes AV1 may start on it); the reference player does not influence it.

## Storage and throughput

Measured with the worker's own FFmpeg on two 20 s, 1080p, 30 fps sources (the whole five-rung ladder at the
rungs' size limits; the 1080p rung is the source's own height). The extra codec's ladder next to H.264's:

**testsrc2**

| Rung | H.264 kbps | VMAF | HEVC kbps | VMAF | size vs H.264 | AV1 kbps | VMAF | size vs H.264 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1080p | 4745 | 95.6 | 2842 | 91.4 | 0.60 | 3248 | 93.0 | 0.68 |
| 720p | 1652 | 96.3 | 1392 | 95.7 | 0.84 | 1328 | 95.7 | 0.80 |
| 480p | 675 | 96.6 | 495 | 95.9 | 0.73 | 486 | 96.9 | 0.72 |
| 360p | 405 | 97.3 | 310 | 96.9 | 0.77 | 293 | 97.3 | 0.72 |
| 240p | 233 | 97.0 | 187 | 96.4 | 0.80 | 204 | 97.5 | 0.87 |

- h264: 19.3 MB for the ladder (1.00x H.264), wall 16.6 s, CPU 65.9 s (1.0x H.264 wall)
- hevc: 13.1 MB for the ladder (0.68x H.264), wall 35.3 s, CPU 140.5 s (2.1x H.264 wall)
- av1: 13.9 MB for the ladder (0.72x H.264), wall 24.3 s, CPU 93.5 s (1.5x H.264 wall)

**mandelbrot**

| Rung | H.264 kbps | VMAF | HEVC kbps | VMAF | size vs H.264 | AV1 kbps | VMAF | size vs H.264 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1080p | 4698 | 77.0 | 2847 | 72.0 | 0.61 | 3202 | 72.5 | 0.68 |
| 720p | 2598 | 87.3 | 1596 | 84.4 | 0.61 | 985 | 82.3 | 0.38 |
| 480p | 1222 | 90.1 | 743 | 88.9 | 0.61 | 501 | 89.2 | 0.41 |
| 360p | 735 | 91.3 | 432 | 90.2 | 0.59 | 307 | 91.7 | 0.42 |
| 240p | 385 | 92.3 | 249 | 91.1 | 0.65 | 193 | 93.0 | 0.50 |

- h264: 24.1 MB for the ladder (1.00x H.264), wall 32.5 s, CPU 129.5 s (1.0x H.264 wall)
- hevc: 14.7 MB for the ladder (0.61x H.264), wall 43.7 s, CPU 174.2 s (1.3x H.264 wall)
- av1: 13.0 MB for the ladder (0.54x H.264), wall 37.7 s, CPU 146.4 s (1.2x H.264 wall)

What it comes to:

- **Storage.** An HEVC ladder is 0.61 to 0.68 of the H.264 ladder's bytes and an AV1 ladder 0.54 to 0.72.
  Turning both on takes a tenant's rendition storage to about **2.2 to 2.4 times** what H.264 alone needed (the
  source, the poster and the sprite sheet are unchanged and not counted here). Each codec on its own adds
  about 55 to 70 per cent of the H.264 ladder. The ratios depend on the footage: the harder the picture, the
  more the caps and the CRF save.
- **Transcode time.** The codecs are separate FFmpeg runs one after another, so a job's time is the sum. On the
  4-CPU container above, a 20 s source took 17 s (easy) to 33 s (hard) for H.264, 35 to 44 s more for HEVC and 24
  to 38 s more for AV1: **about 4.6 times (easy) and 3.5 times (hard)** the H.264-only job when both are on. The
  HEVC run alone takes 1.3 to 2.1 times as long as the H.264 run and the AV1 run 1.2 to 1.5 times. In CPU time
  per second of source video that is 3.3 to 6.5 s for H.264, 7.0 to 8.7 s for HEVC and 4.7 to 7.3 s for AV1; a
  worker that keeps up with uploads on H.264 needs about three and a half to four and a half times the CPU to
  keep up with both codecs, and the media concurrency (`CIPHERFRAME_WORKER_MEDIA_CONCURRENCY`) and the
  transcode timeout (each run has its own) are the knobs.
- **Quality.** With the starting points below (HEVC CRF 26, AV1 CRF 35, caps 0.6 of H.264's) the extra codecs are
  within 0.7 VMAF points of H.264's CRF 23 at 720p and below on the easy source, and within 1.2 on the hard
  source below 720p, for 15 to 60 per cent fewer bits. The tall rungs are the weak spot: 1080p loses 2.6 to 4.2
  points on the easy source and about 5 on the hard one, because the cap (2700 kbps against H.264's 4500)
  binds, and the 720p rung of the hard source loses 2.9 (HEVC) and 5.0 (AV1; SVT-AV1's capped-CRF mode lands
  well under its cap). If you need parity on very detailed footage, lower `CIPHERFRAME_WORKER_CRF_HEVC` or
  `CIPHERFRAME_WORKER_CRF_AV1` (and raise the caps in `internal/media/ladder.go`) and measure again.

### How the settings were chosen

One 720p rung of the first 8 s of each source, no bitrate cap, libx264 CRF 23 preset `medium` as the reference
(`codecs-sweep.json`):

**testsrc2**

| Codec | Setting | kbps | VMAF | Wall s | CPU s |
| --- | --- | ---: | ---: | ---: | ---: |
| h264 | crf 23 preset medium | 1651 | 96.3 | 1.6 | 6.2 |
| hevc | crf 22 preset medium | 2557 | 97.3 | 3.7 | 14.6 |
| hevc | crf 24 preset medium | 1949 | 96.7 | 3.5 | 13.7 |
| hevc | crf 26 preset medium | 1406 | 95.7 | 3.3 | 12.8 |
| hevc | crf 28 preset medium | 982 | 94.4 | 3.0 | 11.9 |
| hevc | crf 26 preset fast | 1367 | 95.4 | 3.0 | 12.0 |
| hevc | crf 26 preset slow | 1460 | 97.1 | 6.7 | 26.5 |
| av1 | crf 30 preset 8 | 2315 | 97.0 | 2.0 | 7.4 |
| av1 | crf 33 preset 8 | 1638 | 96.3 | 1.8 | 6.7 |
| av1 | crf 35 preset 8 | 1347 | 95.8 | 1.7 | 6.6 |
| av1 | crf 38 preset 8 | 964 | 95.1 | 1.7 | 6.5 |
| av1 | crf 35 preset 6 | 1131 | 96.2 | 3.5 | 13.6 |
| av1 | crf 35 preset 10 | 1199 | 95.1 | 1.2 | 4.6 |
| av1 | crf 35 preset 12 | 1199 | 95.1 | 1.2 | 4.5 |

**mandelbrot**

| Codec | Setting | kbps | VMAF | Wall s | CPU s |
| --- | --- | ---: | ---: | ---: | ---: |
| h264 | crf 23 preset medium | 3265 | 90.7 | 4.3 | 17.0 |
| hevc | crf 22 preset medium | 3238 | 91.7 | 6.1 | 24.2 |
| hevc | crf 24 preset medium | 2231 | 89.2 | 5.4 | 21.4 |
| hevc | crf 26 preset medium | 1566 | 86.8 | 4.8 | 18.9 |
| hevc | crf 28 preset medium | 1146 | 84.6 | 4.6 | 18.1 |
| hevc | crf 26 preset fast | 1484 | 87.1 | 5.7 | 22.6 |
| hevc | crf 26 preset slow | 1901 | 89.3 | 10.7 | 42.5 |
| av1 | crf 30 preset 8 | 3843 | 92.3 | 3.9 | 15.1 |
| av1 | crf 33 preset 8 | 2686 | 90.4 | 3.8 | 14.5 |
| av1 | crf 35 preset 8 | 2114 | 89.2 | 3.9 | 14.8 |
| av1 | crf 38 preset 8 | 1491 | 87.6 | 3.7 | 14.4 |
| av1 | crf 35 preset 6 | 1750 | 90.0 | 6.8 | 26.2 |
| av1 | crf 35 preset 10 | 1773 | 86.4 | 2.6 | 9.9 |
| av1 | crf 35 preset 12 | 1773 | 86.4 | 2.7 | 10.4 |

- **HEVC.** At CRF 26 x265 spends 15 per cent fewer bits than x264 on the easy source for 0.6 VMAF less, and 52 per
  cent fewer for 3.9 less on the hard one; the VMAF parity point is CRF 25 on the easy source and CRF 22 to 23 on
  the hard one. CRF 26 keeps the bits down and is where the settings start. The preset `medium` costs 1.1 to 2.1
  times x264 medium's CPU time; `slow` doubles that again for 1.4 to 2.5 VMAF at 4 to 20 per cent more bits, and
  `fast` saves nothing worth having here, so `medium` stays.
- **AV1.** SVT-AV1 preset 8 at CRF 33 matches x264's VMAF at the same size on the easy source and saves 17 per cent
  on the hard one; CRF 35 gives up 0.5 and 1.2 VMAF for another 18 to 21 per cent. The preset is the throughput
  decision: preset 8 uses about the CPU time of x264 medium and less than x265 medium; preset 6 doubles it for about
  16 per cent fewer bits and 0.4 to 0.8 VMAF more; presets 10 and 12 are about 30 per cent cheaper than 8 but 0.7 to
  2.8 VMAF worse at the same CRF (10 and 12 gave the same output here). So CRF 35 and preset 8.
- **Caps.** The 720p rung at the codec's CRF over caps of 0.6 to 1.0 of H.264's 2500 kbps (`codecs-caps.json`):

| Fixture | Codec | Cap of the 720p rung (kbps, share of H.264's) | kbps | VMAF |
| --- | --- | --- | ---: | ---: |
| testsrc2 | h264 | cap 2500 (1.0) | 1651 | 96.3 |
| testsrc2 | hevc | cap 1500 (0.60) | 1406 | 95.7 |
| testsrc2 | hevc | cap 1750 (0.70) | 1406 | 95.7 |
| testsrc2 | hevc | cap 2000 (0.80) | 1406 | 95.7 |
| testsrc2 | hevc | cap 2500 (1.00) | 1406 | 95.7 |
| testsrc2 | av1 | cap 1250 (0.50) | 1246 | 95.5 |
| testsrc2 | av1 | cap 1500 (0.60) | 1325 | 95.7 |
| testsrc2 | av1 | cap 1750 (0.70) | 1347 | 95.8 |
| testsrc2 | av1 | cap 2000 (0.80) | 1347 | 95.8 |
| testsrc2 | av1 | cap 2500 (1.00) | 1347 | 95.8 |
| mandelbrot | h264 | cap 2500 (1.0) | 2773 | 89.5 |
| mandelbrot | hevc | cap 1500 (0.60) | 1566 | 86.8 |
| mandelbrot | hevc | cap 1750 (0.70) | 1566 | 86.8 |
| mandelbrot | hevc | cap 2000 (0.80) | 1566 | 86.8 |
| mandelbrot | hevc | cap 2500 (1.00) | 1566 | 86.8 |
| mandelbrot | av1 | cap 1250 (0.50) | 923 | 84.1 |
| mandelbrot | av1 | cap 1500 (0.60) | 1095 | 85.4 |
| mandelbrot | av1 | cap 1750 (0.70) | 1244 | 86.5 |
| mandelbrot | av1 | cap 2000 (0.80) | 1421 | 87.2 |
| mandelbrot | av1 | cap 2500 (1.00) | 1784 | 88.4 |

  HEVC's size is set by its CRF on both sources (1406 and 1566 kbps, under every cap), so its cap of 0.6 costs
  nothing and only bounds peaks. SVT-AV1 stays under its cap, and well under on hard content (923 kbps under a
  cap of 1250), so the 0.5 first tried for AV1 cost 1.3 VMAF points more than 0.6 on the hard source for a 6 per cent
  saving on the easy one: both codecs use 0.6 of H.264's cap in every rung (2700, 1500, 720, 420 and 210 kbps).
- **Keyframes and timestamps.** On both sources the keyframes of every rendition of every codec are exactly 2
  seconds apart and fall at the same times as H.264's, and the segments match H.264's in number and duration
  (`media.CheckAligned`). Without the start offset the worker gives the extra codecs, AV1's first picture is at
  0.021 s and H.264's at 0.067 s (the reordering delay); with it (the benchmark applies it like the worker) they
  match. Audio segment starts of different codecs can differ by up to three AAC frames (ADR 0067).

## Measurement

Method: `docs/encoder-results/2026-11-23/codecs-bench.go` builds each ladder with the worker's own argument
builder (`media.LadderFor` and `media.TranscodeArgs`), runs one FFmpeg process per codec and fixture, one at a
time, and records bytes per rung, wall and CPU time of the process, VMAF of each rung against the source scaled to
the rung's size (default model, every third frame), and whether the keyframes are identical on every rendition and
the segments match H.264's. Raw numbers: `docs/encoder-results/2026-11-23/codecs.json` (the ladders) and
`codecs-sweep.json` (the CRF and preset sweep) and `codecs-caps.json` (the cap experiment; `-mode sweep` and
`-mode caps`). The sweep and the cap runs were made before the benchmark started the extra codecs at H.264's first
picture like the worker does, which changes no size or score, only the keyframe remark in those two files. To repeat it:

```sh
docker build -f build/worker.Dockerfile --target tools   --output type=local,dest=out/tools .
docker build -f build/worker.Dockerfile --target measure --output type=local,dest=out/measure .
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o out/codecs-bench docs/encoder-results/2026-11-23/codecs-bench.go
docker run --rm --cpus=4 -v $PWD/out:/work -v $PWD/out/tools:/tools:ro -v $PWD/out/measure:/measure:ro debian:bookworm-slim \
  /work/codecs-bench -mode ladder -ffmpeg /tools/ffmpeg -ffprobe /tools/ffprobe -fixtures-ffmpeg /tools/ffmpeg-fixtures \
  -vmaf-ffmpeg /measure/ffmpeg-vmaf -vmaf-ffprobe /measure/ffprobe-vmaf -work /work/w -out /work/codecs.json
```

Setup and limits, stated plainly:

- **Machine.** An Apple silicon Mac running Docker Desktop, the worker's own FFmpeg 9.0.2 (static, linux/arm64,
  libx264, libx265 4.1, SVT-AV1 3.1.2) in a container limited to 4 CPUs. The machine had other work on it, so wall
  times are noisy; CPU time is steadier. Each number is one run. An x86 server will differ: SVT-AV1 and x265 have
  more tuned assembly there, and the ratios between codecs shift.
- **Fixtures.** Two generated sources, 20 s, 1920x1080, 30 fps, with audio: `testsrc2` (the project's test
  pattern: flat colour, hard edges, easy to compress) and `mandelbrot` (continuous fine detail, hard to compress).
  Both are synthetic. They say how the codecs compare on easy and hard content, not what camera footage will
  give; repeat the benchmark on your own footage before you size anything.
- **VMAF** compares at the rung's own size, so it isolates what the encoder lost, not the scaling. It scores the
  video only, and its model was trained for 1080p viewing, so small rungs read generously.
- **Hardware encoders** were not measured (this machine has none of them under Docker).


## Licensing

- **HEVC.** libx265 is GPL-2.0-or-later, consistent with the GPL FFmpeg the worker image already builds (ADR 0024).
  The patents on HEVC are not covered by that licence: licensing them, like H.264's, is the operator's concern, as
  the image's `SOURCE.md` says. The renditions are only made for tenants that turn the codec on.
- **AV1.** SVT-AV1 is BSD-3-Clause-Clear with the Alliance for Open Media patent licence (`svtav1-PATENTS.md` in
  `/usr/share/licenses/ffmpeg/`), a royalty-free grant for implementations of the AV1 specification.
- **The image.** Still no `--enable-nonfree`, still GPL, still separate processes started by the Cipherframe server
  (invariant I1). `/usr/share/licenses/ffmpeg/SOURCE.md` lists the x265 and SVT-AV1 sources and their SHA-256 pins.

## What this does not do

- It does not re-encode assets that already exist when a codec is turned on.
- It has no per-upload or per-playback codec choice and no player setting.
- x265 is built 8-bit only: there are no 10-bit or HDR HEVC renditions (every rendition is 8-bit 4:2:0 anyway).
- The hardware HEVC and AV1 encoders (`hevc_nvenc`, `av1_vaapi`, `av1_qsv` and the rest) are enabled in `worker-hw`
  but were not run on hardware.
- Audio segments of different codecs can start up to three AAC frames (64 ms) apart; video presentation times
  match across all codecs (ADR 0067).
- Turning a codec on multiplies the work of every later upload; size the workers for it.
