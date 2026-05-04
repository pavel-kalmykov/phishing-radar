"""Shared plumbing for pipeline services that write to DuckDB or consume from Kafka.

Extracted so that kafka_to_md.py (data plane) and pipeline_monitor.py
(observability plane) don't duplicate connection, consumer, or schema
setup logic.
"""

from __future__ import annotations

import logging
import os
import random
import time
from pathlib import Path

import duckdb
from confluent_kafka import Consumer

log = logging.getLogger("pipeline-common")

# DuckDB allows only one writer process at a time on the same file.
# The sink and the monitor are separate processes — when they both try
# to write at the same time, one gets an IOException about the lock.
# Retry with exponential backoff rides out the brief lock windows.
_LOCK_RETRY_MAX = 10
_LOCK_RETRY_BASE_SEC = 0.1

# ---------------------------------------------------------------------------
# Kafka
# ---------------------------------------------------------------------------
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
KAFKA_SASL_MECH = os.getenv("KAFKA_SASL_MECHANISM") or None
KAFKA_SASL_USER = os.getenv("KAFKA_SASL_USERNAME") or None
KAFKA_SASL_PASS = os.getenv("KAFKA_SASL_PASSWORD") or None

CERTSTREAM_TOPIC = os.getenv("CERTSTREAM_TOPIC", "certstream_events")


def build_consumer(group_id: str) -> Consumer:
    config: dict[str, str] = {
        "bootstrap.servers": KAFKA_BOOTSTRAP,
        "group.id": group_id,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": "true",
    }
    if KAFKA_SASL_MECH:
        config["security.protocol"] = "SASL_SSL"
        config["sasl.mechanism"] = KAFKA_SASL_MECH
        config["sasl.username"] = KAFKA_SASL_USER or ""
        config["sasl.password"] = KAFKA_SASL_PASS or ""
    return Consumer(config)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL")
MD_CATALOG = os.getenv("MD_CATALOG", "phishing_radar")
MD_DATABASE = os.getenv("MD_DATABASE", "main")
MOTHERDUCK_TOKEN = os.getenv("MOTHERDUCK_TOKEN")

if not DATABASE_URL and not MOTHERDUCK_TOKEN:
    raise RuntimeError("Either DATABASE_URL or MOTHERDUCK_TOKEN must be set")


def _is_lock_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "lock" in msg or "conflicting" in msg


def connect_db() -> duckdb.DuckDBPyConnection:
    if DATABASE_URL:
        if "://" not in DATABASE_URL and not DATABASE_URL.startswith("md:"):
            Path(DATABASE_URL).parent.mkdir(parents=True, exist_ok=True)
        for attempt in range(_LOCK_RETRY_MAX):
            try:
                return duckdb.connect(DATABASE_URL)
            except duckdb.IOException as e:
                if _is_lock_error(e) and attempt < _LOCK_RETRY_MAX - 1:
                    wait = (_LOCK_RETRY_BASE_SEC * (2**attempt)) + random.uniform(0, 0.1)
                    log.warning("DuckDB connect lock conflict, retrying in %.1fs (attempt %d/%d)", wait, attempt + 1, _LOCK_RETRY_MAX)
                    time.sleep(wait)
                else:
                    raise
    return duckdb.connect(f"md:{MD_CATALOG}?motherduck_token={MOTHERDUCK_TOKEN}")


def execute_with_retry(
    conn: duckdb.DuckDBPyConnection,
    sql: str,
    params: list | None = None,
) -> duckdb.DuckDBPyRelation:
    """Execute a single INSERT/DELETE/UPDATE with retry on DuckDB lock contention.

    Use this for writes from the pipeline_monitor process (which races with
    the sink process). For bulk inserts, use executemany_with_retry.
    """
    for attempt in range(_LOCK_RETRY_MAX):
        try:
            return conn.execute(sql, params) if params else conn.execute(sql)
        except duckdb.IOException as e:
            if _is_lock_error(e) and attempt < _LOCK_RETRY_MAX - 1:
                wait = (_LOCK_RETRY_BASE_SEC * (2**attempt)) + random.uniform(0, 0.1)
                log.warning("DuckDB write lock conflict, retrying in %.1fs (attempt %d/%d)", wait, attempt + 1, _LOCK_RETRY_MAX)
                time.sleep(wait)
            else:
                raise


def executemany_with_retry(
    conn: duckdb.DuckDBPyConnection,
    sql: str,
    params: list,
) -> duckdb.DuckDBPyRelation:
    """Execute a batched INSERT with retry on DuckDB lock contention."""
    for attempt in range(_LOCK_RETRY_MAX):
        try:
            return conn.executemany(sql, params)
        except duckdb.IOException as e:
            if _is_lock_error(e) and attempt < _LOCK_RETRY_MAX - 1:
                wait = (_LOCK_RETRY_BASE_SEC * (2**attempt)) + random.uniform(0, 0.1)
                log.warning("DuckDB executemany lock conflict, retrying in %.1fs (attempt %d/%d)", wait, attempt + 1, _LOCK_RETRY_MAX)
                time.sleep(wait)
            else:
                raise


# ---------------------------------------------------------------------------
# Pipeline observability table — shared schema between sink and monitor
# ---------------------------------------------------------------------------
PIPELINE_EVENTS_TABLE = "raw_pipeline_events"


def ensure_pipeline_events_table(conn: duckdb.DuckDBPyConnection) -> None:
    execute_with_retry(conn, f"""
        CREATE TABLE IF NOT EXISTS {PIPELINE_EVENTS_TABLE} (
            event_at TIMESTAMPTZ NOT NULL,
            source VARCHAR NOT NULL,
            event_type VARCHAR NOT NULL,
            payload JSON NOT NULL
        )
    """)
