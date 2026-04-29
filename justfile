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

# Run typosquatting detector (Python equivalent of the PyFlink job)
detect:
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

# Launch the Streamlit dashboard on localhost:8501
dashboard:
    uv run streamlit run dashboard/app.py

# Run pytest suite
test:
    uv run pytest -v

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
