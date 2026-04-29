# Phishing Radar

Real-time phishing infrastructure detector. Watches the Certificate Transparency firehose, flags impersonation attempts as they happen, and correlates with active malware intelligence to give each detection operational context.

Capstone for the DataTalksClub [Data Engineering Zoomcamp 2026](https://github.com/DataTalksClub/data-engineering-zoomcamp).

## The story

Every phishing site needs a TLS certificate. Modern browsers mark non-HTTPS sites as unsafe, so attackers routinely request a certificate for their lookalike domain from Let's Encrypt or any other public CA. Those certificates are published to Certificate Transparency logs within seconds of issuance.

If you tail that firehose, you see the scam infrastructure while it is being built, before the first phishing email lands in anyone's inbox. Phishing Radar tails it for you.

**Two questions this project answers:**

1. Which brands are being impersonated right now?
2. Of all the suspicious certificates appearing in the feed, which ones are hosted on infrastructure we already know is bad (active botnet C2, hijacked IP space, vendors with unpatched CVEs being exploited)?

## Architecture

```mermaid
flowchart LR
    subgraph src[Public sources]
        CT[Certificate Transparency logs]
        KEV[CISA KEV]
        FEO[abuse.ch Feodo Tracker]
        SPAM[Spamhaus DROP/EDROP]
        MITRE[MITRE ATT&CK]
        MM[MaxMind GeoLite2]
    end

    subgraph fly[Fly.io apps always-on]
        CS[certstream-server-go]
        PROD[Python producer]
        DET[Python detector<br/>typosquatting + 1 min windows]
        SINK[Kafka to MotherDuck sink]
        KES[Kestra orchestrator]
    end

    subgraph cloud[Managed services]
        RP[(Redpanda Cloud<br/>Kafka broker)]
        MD[(MotherDuck<br/>DuckDB warehouse)]
        ST[Streamlit Cloud]
    end

    CT --> CS
    CS -->|WebSocket| PROD
    PROD -->|certstream_events| RP
    RP --> DET
    DET -->|suspicious_certs<br/>cert_stats_1min| RP
    RP --> SINK
    SINK --> MD

    KEV --> KES
    FEO --> KES
    SPAM --> KES
    MITRE --> KES
    MM --> KES
    KES -->|dlt + dbt| MD

    MD --> ST
```

## Stack

| Layer | Tool | Where it runs |
|---|---|---|
| Stream broker | Redpanda Cloud (serverless) | AWS eu-central-1 |
| Stream processing | Python (Kafka consumer + producer with 1-min tumbling windows) | Fly.io |
| PyFlink reference job | `apache-flink` Table API | shipped in `streaming/flink/phishing_detector.py`; Python detector is the working twin |
| Batch ingestion | `dlt` | Fly.io (Kestra tasks) |
| Orchestration | Kestra | Fly.io |
| Warehouse | MotherDuck (DuckDB SaaS) | AWS eu-central-1 |
| Transformations | dbt (`dbt-duckdb`) | Fly.io (Kestra tasks) |
| Dashboard | Streamlit | Streamlit Cloud |
| IaC / deploys | `fly.toml` + GitHub Actions | n/a |
| Language | Python 3.11 (+ `uv`, `ruff`) | n/a |

## Data sources

| Source | Type | Cadence | Auth |
|---|---|---|---|
| Certificate Transparency logs (via [certstream-server-go](https://github.com/d-Rickyy-b/certstream-server-go)) | WebSocket | ~200 certs/s | None |
| CISA KEV catalogue | JSON dump | daily | None |
| abuse.ch Feodo Tracker | JSON dump | minutes | None |
| abuse.ch ThreatFox | JSON export | minutes | None |
| Spamhaus DROP / EDROP | TXT | daily | None |
| MITRE ATT&CK (Enterprise) | STIX 2 JSON | monthly | None |
| MaxMind GeoLite2 (CSV) | CSV zip | weekly | Free registration |

## Cloud footprint

| Service | Tier | Role |
|---|---|---|
| Fly.io | 5 machines (4x shared-cpu-1x@256MB + 1x@768MB for Kestra) | Always-on producer, detector, sink, CT stream aggregator, Kestra |
| Redpanda Cloud | Serverless free cluster | Kafka broker + 3 topics |
| MotherDuck | Free tier (10 GB) | Warehouse |
| Streamlit Cloud | Free tier | Dashboard hosting |

Expected monthly cost: around 10 EUR (Kestra VM) plus 4 x ~2 EUR for the small always-on machines. Everything else is on free tiers.

## Latency, throughput and backpressure

The README calls the pipeline "real-time". This section spells out what that means in numbers and where the limits sit.

**End-to-end latency**, from a CA publishing a certificate to it appearing in the dashboard:

| Hop | Typical | Worst case |
|---|---|---|
| CT log entry to `certstream-server-go` | ms | seconds |
| `certstream-server-go` to producer WebSocket | ms | seconds (reconnect window: up to 60 s) |
| Producer batch (`linger.ms=50`, `acks=all`) | 50 to 200 ms | seconds (broker slow) |
| Broker to detector consumer poll | ms | seconds |
| Detector tumbling window emit | up to 60 s | up to 60 s (window granularity) |
| Sink poll + flush (`BATCH_SIZE=500`, `FLUSH_SECONDS=10`) | 1 to 10 s | 10 s (idle flush) |
| Streamlit cache TTL (live tier) | 0 to 60 s | 60 s |

Median observed latency in production: about 60 s. Floor is the detector window plus the sink flush, so anything below 30 s is not achievable without redesign.

**Throughput observed**:

- CT firehose: ~200 certs/s sustained, peaks to ~500 certs/s.
- Producer to Kafka: ~1 to 2 MB/s after zstd compression, far below broker capacity.
- Detector: ~5,000 to 20,000 certs/window evaluated, ~1,000 to 1,500 suspicious certs/min emitted at peak hours.
- Sink to MotherDuck: 50 to 200 inserts/s during normal operation; drained 100k+ message backlogs at 1,500 rows/s.

**Backpressure**:

- Producer side: librdkafka holds an in-process queue (`queue.buffering.max.messages` default 100k). When the broker is slow, `produce()` blocks the asyncio task that reads the WebSocket. The upstream `certstream-server-go` then either buffers or drops on its end; we do not control that.
- Sink side: the consumer poll has a 1 s timeout, the buffer is bounded by `SINK_BATCH_SIZE` (default 500) and flushes are time-bounded by `SINK_FLUSH_SECONDS` (default 10). If MotherDuck is slow, the consumer naturally lags behind its committed offset; offsets advance only after a successful flush, so at-least-once delivery survives a sink crash mid-batch (the next run replays).

**No circuit breaker.** The detector does not shed load when input rate exceeds the rate it can fingerprint and emit. We rely on the bounded per-window state and on Kafka acting as the disk-backed buffer ahead of the consumer. If the detector falls permanently behind, the topic retains messages up to the cluster retention (24 h on the Redpanda Cloud serverless plan) and the dashboard freshness alert fires (`dbt source freshness`).

**Known stress points** (already on the work list):

- Sink consumer freeze: the consumer occasionally stops polling without crashing the process. The auto-restart health check ([`A13`](#known-limitations)) detects no flushes for N minutes and exits, letting Fly restart the machine.
- Multi-topic fair-share: a single Kafka consumer subscribed to three topics is not strictly fair-share across topics in librdkafka. With a multi-million-row certstream backlog, `suspicious_certs` can lag. Mitigation: `fetch.max.partition.bytes` tuning, or split into per-topic consumers.

## Data warehouse notes (for reviewers)

> [!NOTE]
> The course rubric asks for "tables partitioned and clustered in a way that
> makes sense for the upstream queries (with explanation)". MotherDuck (DuckDB)
> doesn't expose BigQuery-style `PARTITION BY` / `CLUSTER BY` clauses, so this
> section explains the equivalent story.

- **Storage format.** DuckDB persists tables as columnar blocks with zone maps
  and dictionary encoding per column. That's the native "clustering":
  predicate pushdown uses min/max stats at the block level, so filters on
  `seen_at_ts`, `country`, `malware_family`, `vendor`, `issuer_cn`, `date_added`
  (the columns the dashboard actually filters by) skip blocks the same way a
  BigQuery clustered table skips micropartitions.
- **Size matters.** The marts are tiny. `mart_dashboard_kpis` is one row,
  `mart_dashboard_c2_by_country` is 22 rows, `mart_dashboard_kev_vendors` is
  20 rows, etc. Partitioning a 20-row table buys nothing. The biggest table is
  `geoip_city_blocks` at ~3.7M rows, which is already range-partitioned
  implicitly by CIDR (the IP-range join in `stg_geoip_city` uses a `between`
  filter against the `start_int`/`end_int` columns; DuckDB's zone maps make
  this linear scan effectively a range scan).
- **Materialisation strategy.** Every dashboard query reads from
  `table`-materialised marts (persisted) rather than views, so the reads don't
  recompute on every page refresh. See `dbt/models/marts/mart_dashboard_*.sql`
  for the pre-aggregated layer.
- **What we'd do at 100x scale.** If the `raw_suspicious_certs` table grew to
  hundreds of millions of rows, we would partition the raw landing table by
  `date(received_at)` (DuckDB supports this via multi-file storage / Hive
  partitioning for Parquet), and cluster the per-brand mart by `(brand, day)`.
  At our current working set (~4k suspicious certs/day) the marts fit in a few
  KB and any partitioning would be ceremony.

## Running it locally

### What you need

**Tooling** (one-time install):

| Tool | Install | Why |
|---|---|---|
| Python 3.11+ | your OS package manager or [pyenv/mise](https://github.com/jdx/mise) | runtime for every Python service |
| [`uv`](https://docs.astral.sh/uv/) | `curl -LsSf https://astral.sh/uv/install.sh \| sh` (or `brew install uv`) | Python deps + virtualenv |
| Docker (+ Compose v2) | [Docker Desktop](https://docs.docker.com/get-docker/) | local Redpanda, certstream-server-go, Kestra |
| [`just`](https://github.com/casey/just) | `brew install just` / `cargo install just` / `scoop install just` | cross-OS task runner |

**Credentials** (free-tier, copy into `.env` after `cp .env.example .env`):

| Variable | Where to get it | Required for |
|---|---|---|
| `MOTHERDUCK_TOKEN` | free account at <https://motherduck.com/> | any step that writes to or reads from MotherDuck (sink, dbt, dashboard) |
| `MAXMIND_LICENSE_KEY` (+ `MAXMIND_ACCOUNT_ID`) | free registration at <https://www.maxmind.com/en/geolite2/signup> | `batch/ingest_maxmind.py` only (rest of the pipeline runs fine without it; the C2 map just falls back to country-level) |
| `KAFKA_BOOTSTRAP`, `KAFKA_SASL_*` | free serverless cluster at <https://redpanda.com/> | optional: only needed if you want to reach a cloud broker. For local work, leave the SASL vars empty and the producer/sink talk to the local Redpanda Docker container at `localhost:9092` |
| `FLY_ACCESS_TOKEN`, `FLY_ORG` | <https://fly.io/> (needs a payment method, but free credit covers the small machines used here) | deploys only; not needed to run locally |

Nothing else is required. CISA KEV, abuse.ch Feodo, abuse.ch ThreatFox, Spamhaus and MITRE ATT&CK feeds are all anonymous (no API keys) and pulled directly over HTTPS.

> [!NOTE]
> **Reproducibility.** `pyproject.toml` declares dependencies with `>=` floors so the project can pick up patch releases. The exact, deterministic dependency tree lives in `uv.lock` (committed to the repo). `just setup` runs `uv sync --frozen` under the hood, which reuses the lockfile verbatim and never resolves new versions silently. Refresh the lock with `uv lock --upgrade` only when you intend to bump.

### Bring everything up

```bash
cp .env.example .env        # fill MOTHERDUCK_TOKEN, optionally MAXMIND_LICENSE_KEY
just setup                   # install Python deps with uv
just up                      # docker-compose starts Redpanda + certstream-server-go locally
just producer &              # CertStream -> Kafka producer
just detect &                # typosquatting detector
just sink &                  # Kafka -> MotherDuck
just batch                   # one-shot ingestion of CISA KEV, Feodo, Spamhaus, MITRE, MaxMind
just dbt-run                 # transformations
just dashboard               # Streamlit at localhost:8501
```

Local consoles:

- Redpanda console: http://localhost:8082
- CertStream server: http://localhost:8090
- Streamlit dashboard: http://localhost:8501

## Deploy to cloud

```bash
flyctl apps create phishing-radar-certstream
flyctl apps create phishing-radar-producer
flyctl apps create phishing-radar-detector
flyctl apps create phishing-radar-sink
flyctl apps create phishing-radar-kestra

# Secrets (replace values)
flyctl secrets set --app phishing-radar-producer KAFKA_BOOTSTRAP=... KAFKA_SASL_MECHANISM=SCRAM-SHA-256 KAFKA_SASL_USERNAME=... KAFKA_SASL_PASSWORD=...
flyctl secrets set --app phishing-radar-detector KAFKA_BOOTSTRAP=... KAFKA_SASL_MECHANISM=SCRAM-SHA-256 KAFKA_SASL_USERNAME=... KAFKA_SASL_PASSWORD=...
flyctl secrets set --app phishing-radar-sink     KAFKA_BOOTSTRAP=... KAFKA_SASL_MECHANISM=SCRAM-SHA-256 KAFKA_SASL_USERNAME=... KAFKA_SASL_PASSWORD=... MOTHERDUCK_TOKEN=...
flyctl secrets set --app phishing-radar-kestra   KAFKA_BOOTSTRAP=... KAFKA_SASL_MECHANISM=SCRAM-SHA-256 KAFKA_SASL_USERNAME=... KAFKA_SASL_PASSWORD=... MOTHERDUCK_TOKEN=... MAXMIND_LICENSE_KEY=...

# Deploy
flyctl deploy --config deploy/certstream/fly.toml --app phishing-radar-certstream --ha=false
flyctl deploy --config deploy/producer/fly.toml   --app phishing-radar-producer   --dockerfile Dockerfile --ha=false
flyctl deploy --config deploy/detector/fly.toml   --app phishing-radar-detector   --dockerfile Dockerfile --ha=false
flyctl deploy --config deploy/sink/fly.toml       --app phishing-radar-sink       --dockerfile Dockerfile --ha=false
flyctl volumes create kestra_data --region cdg --size 1 --app phishing-radar-kestra
flyctl deploy --config deploy/kestra/fly.toml     --app phishing-radar-kestra     --ha=false
```

The `.github/workflows/deploy.yml` GitHub Action redeploys the four services on every push to `main`, but the workflow targets the `production` GitHub environment. Configure that environment under repo *Settings → Environments → production* with at least one required reviewer (yourself). Pushes will queue the deploy and wait for an explicit approval click before any `flyctl deploy` runs, so a typo on main cannot silently redeploy four apps in seconds.

## Dashboard

Hosted: **<https://phishing-radar.streamlit.app>** (after you connect Streamlit Cloud to the GitHub repo and set the `MOTHERDUCK_TOKEN` secret).

Single page with a global filter bar (date range, brand, issuing CA, live refresh toggle) and five tabs:

1. **Overview**: top impersonated brands in the selected window, active C2s by malware family (hover a bar for a one-line context tooltip).
2. **Live phishing stream**: hourly volume of flagged certs with the current partial hour flagged, top issuing CAs, latest 50 certificates. Toggling "Live refresh" wraps the tab body in a `st.fragment(run_every="30s")` so it re-queries MotherDuck every half minute without touching the rest of the page.
3. **Threat landscape**: KEV monthly additions (current month rendered translucent so it isn't compared against complete months), Spamhaus DROP/EDROP buckets, KEV vendors with a ransomware-ratio colour scale, active C2s by hosting country.
4. **Map**: a `scatter_geo` world map with one dot per country where we see a C2. Dot size is active C2 count, colour is the count gradient, tooltip includes the dominant malware family and a one-liner description.
5. **Stack**: pipeline, batch and data-source reference panels.

Every widget reads from pre-aggregated marts (`mart_dashboard_kpis`, `mart_dashboard_suspicious_hourly`, `mart_dashboard_top_issuers`, `mart_dashboard_kev_vendors`, `mart_dashboard_kev_monthly`, `mart_dashboard_c2_by_country`) so the page stays fast even as the raw tables grow.

## Repository layout

```
.
├── batch/                    # dlt pipelines (one module per source)
├── dashboard/                # Streamlit app
├── dbt/                      # dbt project (duckdb adapter, MotherDuck target)
├── deploy/                   # fly.toml per Fly app
├── kestra/flows/             # Kestra flow definitions (YAML)
├── streaming/
│   ├── producer/             # CertStream -> Kafka
│   ├── flink/                # detection logic + PyFlink reference job + Python twin
│   └── sink/                 # Kafka -> MotherDuck
├── tests/                    # pytest suite
├── Dockerfile                # single image for all Python services
├── docker-compose.yml        # Redpanda + certstream-server-go + Kestra for local dev
├── justfile                  # cross-OS task runner
├── pyproject.toml
└── README.md
```

## Tests and quality

- `pytest` covers the typosquatting detector (19 assertions: homoglyph, Cyrillic look-alikes, Damerau-Levenshtein including transpositions, Jaro-Winkler prefix cases, legitimate domains, edge cases).
- `ruff check` in CI.
- `dbt test` runs 13 schema tests plus 1 singular test (IP format sanity).
- Detector design note: `docs/detection_alternatives.md` explains why we moved from Levenshtein to Damerau-Levenshtein + Jaro-Winkler and why MinHash was considered then dropped for this workload.
- CI workflow at `.github/workflows/ci.yml`.

## Known limitations

These are intentional trade-offs, not bugs. The portfolio version of the project keeps the architecture honest about what it does and does not guarantee.

- **At-least-once delivery, not exactly-once.** The Kafka producer is configured with `acks=all` and idempotence, but the sink commits Kafka offsets after a MotherDuck flush. If the sink is killed between flush and commit, the next run replays the last batch and dedup happens at the mart layer (`select distinct ...`). Acceptable for analytics use; not safe for billing.
- **Detection latency floor.** The detector uses 1-minute tumbling windows to keep state bounded and emit deterministic stats. In practice a suspicious cert appears in the dashboard 60 to 120 seconds after the CA published it. That is "near real-time"; it is not sub-second.
- **CT firehose loss.** We rely on `certstream-server-go` as the upstream WebSocket aggregator. If the producer disconnects (keepalive timeout, transient network), events emitted during the gap are not replayed. Reconnect logic is in place; replay is not.
- **Single-instance services.** Each Fly app runs one machine. No leader election, no HA. Recovery depends on Fly's restart policy and on the auto-restart health check that detects consumer freezes. A region outage takes the pipeline down until a manual fly redeploy.
- **Brand allowlist is the detection scope.** The detector only flags impersonation against brands declared in the configuration (`STREAMING_BRAND_LIST_PATH`). Adding a brand requires editing the YAML and a redeploy. Anything outside the list is invisible to this pipeline by design.
- **GeoLite2 accuracy.** GeoLite2-City is free, not commercial-grade. Some IPs only resolve to country level; city resolution is imprecise. The dashboard map jitters identical lat/lon by ±0.3° to keep co-located markers visible, which is honest about the source's resolution.
- **Detector horizontal scaling.** The current detector is single-process. The PyFlink job in `streaming/flink/phishing_detector.py` is the path to multi-task parallelism, but the deployed instance is the single Python twin sized for the firehose we observe.
- **Streamlit cache vs. live data.** TTLs are tiered to match the cadence of each source: streaming-derived widgets (KPIs, suspicious-cert slices) cache for 60 s, slower-moving aggregates (KEV, Spamhaus, C2) cache for 5 minutes, and filter dropdowns cache for 10 minutes. The "live stream" tab adds an `st.fragment(run_every="30s")` on top so it re-queries every half minute when toggled. KPI values can therefore lag the detector by up to one cache window.

## License

MIT.
