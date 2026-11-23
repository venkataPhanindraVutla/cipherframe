# Load tests

Method, numbers and caveats for the M9-4 load tests ([ADR 0061](adr/0061-load-test-method.md)). Every
figure here was measured on one laptop, with the load generator on the same machine, and each
configuration was run once. Read them as a statement of the design's shape, not a capacity
promise: size a real deployment from your own run of the same tool.

The raw results are in [`load-results/2026-11-22/`](load-results/2026-11-22/): per-step summary CSVs,
a sampled raw CSV per run (every failure and one successful request in fifty), the container CPU
samples taken during each run and the console log of each run.

## What was measured

- **Playback:** how many real-time viewers one edge can serve with its CPU limited to 1 or 2 vCPUs,
  in `proxy` delivery (edge streams every segment) and in `presigned` delivery (edge serves
  playlists and the key, storage serves segments).
- **Transcode:** seconds of media the worker turns into a ready asset per wall-clock second, with
  its CPU limited to 1 or 2 vCPUs.

## Environment

| Item | Value |
| --- | --- |
| Machine | Apple M2, 8 cores (4 performance, 4 efficiency), 16 GB, macOS 26.6.2 |
| Docker | Docker Desktop 4.41.2, engine 28.1.1, Linux 6.10.14 (linuxkit) aarch64 VM with 8 CPUs and 8 GB |
| Stack | `deploy/compose/compose.yaml` at this commit: Postgres 18.6, SeaweedFS 4.53 (one process: master, volume, filer, S3), `cipherframe-server --role=api,edge`, `cipherframe-worker` (FFmpeg) |
| Other load | The laptop was in ordinary use during the runs. The 1-minute load average sampled in `resources-*.csv` was 2.6 to 9. A separate project's compose stack (`cfdemo-*`) and unrelated `app_*` containers were running but idle (each under 1 % CPU in `docker stats`) |
| Cipherframe settings | Defaults (ADR 0028) except the tenant `delivery` setting, which the tool sets for each run. Tokens in headers, no JWT, no callback, no quotas |

**CPU limits.** The edge and the API run in one process in the development stack, so the limit is on
that container: `docker update --cpus 1 cfload-server-1` (then `2`). The API's share of the work is a
session create at the start of a viewer and one heartbeat a minute, a few percent of the total. For
transcode, `docker update --cpus N` on the worker container. The load generator, Postgres and
SeaweedFS are not limited.

**Clip.** A 60 second 1280x720, 25 fps `testsrc2` pattern with a 440 Hz tone, H.264 and AAC, 21.7 MB,
made by the test-only FFmpeg of `build/worker.Dockerfile --target fixtures`:

```sh
docker build -f build/worker.Dockerfile --target fixtures -t cfload-fixtures .
docker run --rm -v "$PWD:/out" --entrypoint /opt/ffmpeg-fixtures/bin/ffmpeg cfload-fixtures \
  -hide_banner -loglevel error -f lavfi -i testsrc2=size=1280x720:rate=25 \
  -f lavfi -i sine=frequency=440:sample_rate=48000 -t 60 -c:v libx264 -pix_fmt yuv420p -c:a aac \
  -shortest testsrc60.mp4
```

**Ladder produced.** 240p, 360p, 480p and 720p, 6 second segments, AES-128 CBC. The viewers play the
**720p** rendition: segments of 1.9 to 2.1 MB, about 2.7 Mbit/s per viewer (`--rendition 720p`).

**Viewer behaviour** (ADR 0061): create a session, fetch the master playlist, the 720p media
playlist, the key and the init segment, then one segment every 6 seconds (a random phase per
viewer), a heartbeat every 60 seconds (the advertised interval), the clip played again in the same
session when it ends. Latency is the time to the last byte.

**Ramp and thresholds.** Viewers are added in steps (the first step's size and the increment are in
the table below), each step has 5 seconds not measured and 15 seconds measured. A step fails, and
the ramp stops, when segment p99 latency is over **1 s** or more than **1 %** of requests fail. The
number reported is the last step that passed.

**Where the generator runs.** Inside the compose network, in a container that shares the network
namespace of the SeaweedFS container, so `server:8081` resolves and the presigned URLs
(`localhost:8333`) point at storage. It does not go through Docker Desktop's published ports. A first
attempt through `127.0.0.1:8081` stopped at 400 to 450 viewers with the server container at about
20 % CPU, which is the port forwarding's limit and not the edge's
(`*-hostport-*` files; kept for the record, not used in the tables).

## Reproduce

```sh
docker compose -p cfload -f deploy/compose/compose.yaml --profile worker up -d --build server worker
K=$(docker compose -p cfload -f deploy/compose/compose.yaml --profile worker run --rm -T --no-deps \
      server admin bootstrap --tenant-name load --client-name load | tail -1)
umask 077; printf '%s' "$K" > apikey
go build -o cfl ./cmd/cipherframe && go build -o cfload ./cmd/cipherframe-load
CIPHERFRAME_SERVER=http://127.0.0.1:8080 ./cfl upload testsrc60.mp4 --wait --api-key-file apikey   # prints ast_...

docker update --cpus 1 cfload-server-1                     # or 2
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o cfload-linux ./cmd/cipherframe-load
docker run --rm --ulimit nofile=65536:65536 --network container:cfload-seaweedfs-1 \
  --entrypoint /w/cfload-linux -v "$PWD:/w:ro" -v "$PWD/out:/out" cfload-server:dev play \
  --api http://server:8080 --edge http://server:8081 --asset ast_... --delivery proxy --rendition 720p \
  --api-key-file /w/apikey --start 1000 --step 500 --max 8000 --step-duration 15s --settle 5s \
  --raw-sample 50 --raw /out/raw.csv --summary /out/summary.csv

docker update --cpus 1 cfload-worker-1                     # or 2
CIPHERFRAME_SERVER=http://127.0.0.1:8080 ./cfload transcode --file testsrc60.mp4 --media-seconds 60 \
  --jobs 3 --api-key-file apikey --raw out/raw-transcode.csv --summary out/summary-transcode.csv
```

(The compose project was named `cfload` and its images were retagged `cfload-*:dev` with an override
file so that other stacks on the machine were untouched; with the stock names, replace `cfload` by
`cipherframe` throughout.) `docker compose down -v` removes the stack.

## Results: playback, 720p, real-time viewers

Ramp: 1000 viewers first, then +500 per step, to at most 8000 (`--speed 1`). A "pass" means the
thresholds above held.

| Delivery | Edge CPU | Highest passing step | First failing step | Segment p50 / p95 / p99 at the highest pass | Sessions per vCPU |
| --- | --- | --- | --- | --- | --- |
| proxy | 1 vCPU | 4000 | 4500 (p99 10.5 s) | 3.0 / 6.5 / 13.6 ms | 4000 |
| proxy | 2 vCPU | 6500 | 7000 (p99 8.0 s) | 3.8 / 11.3 / 21.0 ms | 3250 |
| presigned | 1 vCPU | 8000 (ceiling not found) | none | 4.4 / 80.6 / 182 ms | at least 8000 |
| presigned | 2 vCPU | 7000 | 8000 (p99 17.5 s) | 3.4 / 184.8 / 321.7 ms | not CPU-bound |

How to read the table:

- **proxy** is limited by the edge's CPU. The edge process reached about 100 % of one vCPU (the 90th
  percentile of `server_cpu_pct`) in the 1 vCPU run just before it failed, and the failing step
  collapsed within one step (p99 of seconds), which is what saturation looks like. At 4000 sessions
  that is about 10.8 Gbit/s of segment traffic through one vCPU; the figure is high because the
  traffic stays inside one machine and nothing is encrypted in transit (the stack is plain HTTP).
- The 2 vCPU proxy run did not double the 1 vCPU run (6500 against 4000). In that run SeaweedFS
  and the load generator also used several cores of the same 8-core VM (`resources-play-proxy-2vcpu.csv`),
  so the second vCPU of the edge was not the only thing that mattered. One run per configuration cannot
  separate that from run-to-run noise.
- **presigned** moves the segment bytes off the edge: the edge's CPU stayed under about 30 % in the
  1 vCPU run (`resources-play-presigned-1vcpu.csv`). The limit it met is storage and the VM: SeaweedFS
  used 2 to 4 cores and the generator 1 to 1.5 cores. The 1 vCPU run passed 8000 and the 2 vCPU run
  failed at 8000, with the same code and the opposite order of the CPU limits, so the edge CPU limit
  is not what decided it; the difference is the noise of a shared laptop (load average 4.7 against
  7.1). **Read the presigned row as "somewhere around 7000 to 8000 on this machine, set by storage
  and the VM", not as a per-vCPU figure for the edge.** A run with `--speed 4` (four times the
  segment rate per viewer, 2000 viewers, `*-speed4-*`) failed its first step (p99 1.8 s), consistent
  with a storage ceiling of the order of 8000 real-time viewers.
- Errors were 0 in every measured step of every run. Heartbeats and key requests are in the
  summary CSVs per step; their latencies stayed in single-digit milliseconds until the failing step.

Per-step numbers: `summary-play-*.csv` (columns `step, viewers, kind, requests, errors, req_per_s,
p50_ms, p95_ms, p99_ms`, one row per request kind and one `all` row per step).

A finer run before these (50-viewer steps, 15 s on and 5 s off, 1 vCPU, proxy, same stack) stayed
below 30 ms p99 up to its last step, 850 viewers, when it was stopped by hand
(`log-fine-proxy-1vcpu.txt`); it shows the shape below the knee and nothing more.

## Results: transcode

Three uploads of the 60 second clip, one at a time (`--jobs 3 --concurrency 1`), timed from the
commit response to the first poll that saw `ready` (polled every 250 ms). The worker container's CPU
was limited with `docker update --cpus`. Throughput is media seconds finished per wall-clock second
over the whole run, uploads and the deletes that clean up included.

| Worker CPU | Commit to ready (p50 / max of 3) | Throughput | Per vCPU |
| --- | --- | --- | --- |
| 1 vCPU | 133.6 s / 156.5 s | 0.43 media s per wall s | 0.43 |
| 2 vCPU | 47.5 s / 52.8 s | 1.22 media s per wall s | 0.61 |

That is, one vCPU transcodes a minute of 720p video into the four-rendition ladder in about 2.2
minutes (slower than real time), and two vCPUs in about 0.8 minutes. The second vCPU gave more than
double the throughput; this run does not say why (the worker's earlier delete jobs, FFmpeg's thread
count and noise from the shared laptop are candidates), and the three jobs of the first row took
126 s, 134 s and 156 s. Treat the per-vCPU column as rough and plan from your own run.

Per-job numbers: `summary-transcode-*.csv` and `raw-transcode-*.csv` (one `upload` and one
`transcode` row per job; the viewer column is the job counter).

## What these numbers do not tell you

- **They are laptop numbers.** An Apple M2 under Docker Desktop is not a cloud vCPU. A "vCPU" here is
  a CPU quota (`--cpus`) on a VM with 8 CPUs, so performance cores are cheap and the quota is a share
  of time, not a pinned core. Multiply nothing: run the tool on your hardware.
- **The load generator shares the machine.** It used up to about 1.5 cores in the larger runs, and
  SeaweedFS up to 4 or more, in the same VM as the edge. A separate generator host and a separate
  storage service would move the knee in both directions.
- **Docker Desktop's VM and its network** add overhead and noise. The generator avoids the published
  ports, which would have capped the result at a few hundred viewers (see above), but the traffic still
  crosses the VM's bridge.
- **Plain HTTP, no TLS, no CDN, no reverse proxy** between the viewer and the edge. TLS termination
  costs CPU somewhere in a real deployment.
- **`presigned` measures something different from `proxy`.** It measures the object store and the VM,
  because the segment bytes no longer pass through the edge. Its number says how well storage
  serves, not what the edge can do; the edge's own cost in that mode (playlist rewriting with a
  signature per segment, the key, heartbeats) is small compared with the segment bytes and was not
  isolated.
- **One run per configuration**, steps of 500 viewers: the knee is known to within one step, and a
  repeat can differ by more than that (the two presigned rows show it).
- **Viewers loop one 60 second clip** and re-fetch the media playlist at each loop, but not the key.
  Real viewers watch different parts of different assets, so a real deployment misses storage and
  OS caches more often than this test did.
- **Heartbeats are one a minute per viewer**, as advertised; the 15 second measured steps contain few
  of them. Their cost is in the summaries (`heartbeat` rows) and was small.
- **Sessions are not the same as bandwidth.** The 720p rendition is about 2.7 Mbit/s; viewers on
  240p cost a tenth of the bytes. Your mix decides.
- **Transcode** used one 60 second synthetic clip. Real footage, other codecs, the face masker and
  concurrent jobs change the rate.
