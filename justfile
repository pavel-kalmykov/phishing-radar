# Phishing Radar - cross-platform task runner.
# Install `just`: https://github.com/casey/just#installation
#   macOS:   brew install just
#   Windows: winget install Casey.Just  (or scoop install just)
#   Linux:   cargo install just          (or your package manager)

set dotenv-load := true

default:
    @just --list

# Install Python dependencies with uv (reproducible: uses uv.lock verbatim)
setup:
    uv sync --all-extras --frozen

# Start Redpanda, certstream-server-go and Kestra locally
up:
    docker compose up -d

# Start full local stack: infra + sink against local DuckDB.
# Requires nothing but Docker and uv; no cloud accounts needed.
up-local:
    docker compose up -d
    @echo "Infra running (Redpanda, certstream, Kestra)."
    @echo "Run the pipeline with DATABASE_URL=data/local.duckdb:"
    @echo "  DATABASE_URL=data/local.duckdb just producer"
    @echo "  DATABASE_URL=data/local.duckdb just detect"
    @echo "  DATABASE_URL=data/local.duckdb just sink"
    @echo "  DATABASE_URL=data/local.duckdb just dashboard"
    @echo "After the sink lands data, run dbt:"
    @echo "  DATABASE_URL=data/local.duckdb just dbt-run-local"

# One-command local stack: infra + batch ingestions + dbt + streaming pipeline + dashboard.
# Runs batch first (so KPIs, map, and C2 charts have data), then starts the streaming
# lane and dashboard. All data lands in data/local.duckdb.
up-local-all:
    @echo "=== Starting infra ==="
    docker compose up -d
    @echo "=== Waiting for Redpanda ==="
    @until docker compose ps redpanda 2>/dev/null | grep -q healthy; do sleep 2; done
    @echo "=== Running batch ingestions ==="
    @DATABASE_URL=data/local.duckdb HTTPS_PROXY= HTTP_PROXY= https_proxy= http_proxy= uv run python -m batch.run_all
    @echo "=== Running dbt ==="
    cd dbt && DATABASE_URL=../data/local.duckdb DBT_TARGET=local uv run dbt run --profiles-dir .
    @echo "=== Starting streaming pipeline ==="
    @DATABASE_URL=data/local.duckdb nohup uv run python -m streaming.producer.certstream_producer > /tmp/phishing-radar-producer.log 2>&1 &
    @DATABASE_URL=data/local.duckdb nohup uv run python -m streaming.flink.python_detector > /tmp/phishing-radar-detector.log 2>&1 &
    @echo "=== Starting sink + dashboard (same process, DuckDB single-writer constraint) ==="
    @DATABASE_URL=data/local.duckdb nohup uv run python -m streaming.local_runner > /tmp/phishing-radar-runner.log 2>&1 &
    @sleep 5
    @echo ""
    @echo "All done. Dashboard at http://localhost:8501"
    @echo "Logs: /tmp/phishing-radar-*.log"
    @echo ""
    @echo "Stop everything:"
    @echo "  pkill -f 'streaming.local_runner'; pkill -f 'streaming.producer'; pkill -f 'python_detector'; docker compose down"

# Stop local infra
down:
    docker compose down

# Run CertStream -> Kafka producer
producer:
    uv run python -m streaming.producer.certstream_producer

# Run typosquatting detector. Real PyFlink job (MiniCluster); needs JDK 17+
# and a one-off `uv pip install 'apache-flink>=1.20.0,<1.21.0'` because the
# wheel cannot be locked alongside the rest of the project (see pyproject
# comment: pyarrow conflict with dlt).
#
#     brew install openjdk@17
#     export JAVA_HOME=$(brew --prefix openjdk@17)/libexec/openjdk.jdk/Contents/Home
#     uv pip install 'apache-flink>=1.20.0,<1.21.0'
detect:
    uv run python -m streaming.flink.phishing_detector

# No-Java fallback for quick local iteration on the detection logic. Same
# input, same output, plain Python loop with confluent-kafka. Not what gets
# deployed.
detect-no-java:
    uv run python -m streaming.flink.python_detector

# Run Kafka -> MotherDuck sink
sink:
    uv run python -m streaming.sink.kafka_to_md

# Run pipeline volume monitor (observability plane, independent from sink)
monitor:
    uv run python -m streaming.observability.pipeline_monitor

# Run every batch ingestion once (CISA KEV, Feodo, ThreatFox, Spamhaus, MITRE, MaxMind)
batch:
    HTTPS_PROXY= HTTP_PROXY= https_proxy= http_proxy= uv run python -m batch.run_all

# dbt commands run inside dbt/ with the bundled profiles.yml.
# Default target is dev (MotherDuck); set DBT_TARGET=local or use the
# -local variants below for a DuckDB file on disk.
dbt-run:
    cd dbt && uv run dbt run --profiles-dir .

dbt-test:
    cd dbt && uv run dbt test --profiles-dir .

dbt-deps:
    cd dbt && uv run dbt deps --profiles-dir .

# Run dbt source freshness checks (warns when ingestion is stale)
dbt-freshness:
    cd dbt && uv run dbt source freshness --profiles-dir .

# Local DuckDB variants (target=local, reads DATABASE_URL or defaults to data/local.duckdb)
dbt-run-local:
    cd dbt && DBT_TARGET=local uv run dbt run --profiles-dir .

dbt-test-local:
    cd dbt && DBT_TARGET=local uv run dbt test --profiles-dir .

dbt-freshness-local:
    cd dbt && DBT_TARGET=local uv run dbt source freshness --profiles-dir .

# Launch the Streamlit dashboard on localhost:8501
dashboard:
    uv run streamlit run dashboard/app.py

# Run pytest suite
test:
    uv run pytest -v

# Memory profiling with memray. Each recipe writes memray-<service>.bin;
# open with `uv run memray flamegraph memray-<service>.bin`.
profile-producer:
    uv run memray run -o memray-producer.bin -m streaming.producer.certstream_producer

profile-detector:
    uv run memray run -o memray-detector.bin -m streaming.flink.python_detector

profile-sink:
    uv run memray run -o memray-sink.bin -m streaming.sink.kafka_to_md

# Lint and format check
lint:
    uv run ruff check .
    uv run ruff format --check .

# Apply formatting
format:
    uv run ruff format .

# Remove local caches
clean:
    rm -rf .pytest_cache .ruff_cache .mypy_cache dbt/target dbt/logs
