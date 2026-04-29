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

# Run every batch ingestion once (CISA KEV, Feodo, Spamhaus, MITRE, MaxMind)
batch:
    uv run python -m batch.run_all

# dbt commands run inside dbt/ with the bundled profiles.yml
dbt-run:
    cd dbt && uv run dbt run --profiles-dir .

dbt-test:
    cd dbt && uv run dbt test --profiles-dir .

dbt-deps:
    cd dbt && uv run dbt deps --profiles-dir .

# Run dbt source freshness checks (warns when ingestion is stale)
dbt-freshness:
    cd dbt && uv run dbt source freshness --profiles-dir .

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
