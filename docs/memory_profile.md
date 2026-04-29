# Memory profile and right-sizing

How the Fly machines are sized, and how to reproduce the measurements.

## Observed peaks (production, end of April 2026)

Running on Fly.io, single machine per app, primary region `cdg`. Peaks taken
from the Fly Prometheus endpoint over a 48 h window of normal CT firehose
traffic.

| App | VM size | RSS peak | RSS % of VM | Notes |
|---|---|---|---|---|
| `phishing-radar-certstream` (Go, certstream-server-go) | 256 MB | 197 MB | 77 % | Tight. Tuning via `GOMEMLIMIT` only; `GOGC` left at default. |
| `phishing-radar-producer` (Python + confluent-kafka) | 256 MB | 118 MB | 46 % | Comfortable. |
| `phishing-radar-detector` (PyFlink MiniCluster + Python UDFs) | 1024 MB | not yet measured post-migration | n/a | JVM heap caps at ~512 MB; Python worker ~250 MB; rest is native + headroom. |
| `phishing-radar-sink` (Python + duckdb + confluent-kafka) | 512 MB | 230 MB | 45 % | Bumped from 256 MB after early OOMs at first Kafka fetch. |
| `phishing-radar-kestra` (JVM, Kestra standalone) | 1024 MB | 645 MB | 63 % | `JAVA_OPTS` caps the JVM at 768 MB. |

**Why no `MALLOC_ARENA_MAX`.** A previous attempt to lower the producer / sink
heap by setting `MALLOC_ARENA_MAX=2` collapsed `confluent-kafka` throughput
from ~1500 to ~6 events/min: `librdkafka` runs its IO loop in a background C
thread, and capping glibc allocator arenas at 2 serialised every allocation
across the Python main thread and that C thread. The current fly.tomls do
not set it.

## Reproducing the measurements

`memray` is in the `dev` extras. Run any Python service under it locally
against the docker-compose Redpanda + certstream-server-go and let it run
for at least 5 minutes so steady state is reached:

```bash
just up                                        # local Redpanda + certstream
uv run memray run -o memray.bin -m streaming.producer.certstream_producer
# stop with Ctrl-C after ~5 min
uv run memray summary memray.bin
uv run memray flamegraph memray.bin            # opens an HTML flamegraph
```

Replace the `-m` target to profile a different service:

| Service | `uv run memray run -m ...` |
|---|---|
| Producer | `streaming.producer.certstream_producer` |
| Detector (no-Java fallback) | `streaming.flink.python_detector` |
| Sink | `streaming.sink.kafka_to_md` |
| Batch ingester | `batch.ingest_cisa_kev` (or any other) |

For the Go `certstream-server-go` we rely on Fly's Prometheus
`fly_instance_memory_*` metrics rather than memray. The Go runtime's
`GOMEMLIMIT` is the relevant tuning knob; the upstream Docker image
respects it.

## Sizing rationale

- **256 MB is the floor.** Anything smaller leaves no headroom for librdkafka
  fetch buffers, transient JSON parsing spikes, or the startup
  `uv sync --frozen` step on cold image rebuild.
- **Go services with a tight `GOMEMLIMIT`** (`certstream-server-go`) scale
  with CPU pressure rather than RSS, so the right knob is the soft cap, not
  the VM size; we leave the VM at 256 MB and the Go runtime decides when to
  GC harder.
- **The sink keeps DuckDB connection state.** A single MotherDuck connection
  caches schema metadata; adding 50 MB of Python heap on top puts the
  steady-state at ~140 MB. The first Kafka fetch can briefly spike past
  300 MB while a dense batch is being decoded, hence 512 MB.
- **Kestra is JVM-bound.** `JAVA_OPTS` already caps the heap at 768 MB; the
  remainder of the 1024 MB VM is metaspace, native, off-heap state. Lowering
  the cap below 768 MB caused workflow GC churn on the daily batch flow.
