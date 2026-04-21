.PHONY: help setup up down producer flink batch dbt-run dbt-test dashboard test lint clean

help:
	@echo "Phishing Radar - available targets:"
	@echo "  setup      Install python deps with uv"
	@echo "  up         Start Redpanda and Kestra"
	@echo "  down       Stop infra"
	@echo "  producer   Run CertStream producer (local)"
	@echo "  flink      Run PyFlink detection job (local)"
	@echo "  batch      Run all batch ingestions once"
	@echo "  dbt-run    Run dbt models"
	@echo "  dbt-test   Run dbt tests"
	@echo "  dashboard  Run Streamlit dashboard"
	@echo "  test       Run pytest"
	@echo "  lint       Run ruff"

setup:
	uv sync

up:
	docker compose up -d

down:
	docker compose down

producer:
	uv run python -m streaming.producer.certstream_producer

flink:
	uv run python -m streaming.flink.phishing_detector

batch:
	uv run python -m batch.run_all

dbt-run:
	cd dbt && uv run dbt run

dbt-test:
	cd dbt && uv run dbt test

dashboard:
	uv run streamlit run dashboard/app.py

test:
	uv run pytest -v

lint:
	uv run ruff check .
	uv run ruff format --check .

format:
	uv run ruff format .

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache dbt/target dbt/logs
