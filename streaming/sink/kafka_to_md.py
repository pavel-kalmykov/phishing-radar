"""Kafka topics -> MotherDuck.

Consumes the three streaming topics emitted by our pipeline and lands them
to their corresponding raw tables in the MotherDuck database:

- `certstream_events`  -> `raw_certstream_events`
- `suspicious_certs`   -> `raw_suspicious_certs`
- `cert_stats_1min`    -> `raw_cert_stats_1min`

Each raw table has three columns: `received_at`, `key`, `payload` (JSON).
dbt owns the parsing, so the sink stays cheap and schema-evolution friendly.

Uses DuckDB's `INSERT INTO ... VALUES (?, ?, ?::JSON)` via batched `executemany`.
MotherDuck is reached through a DuckDB connection with the `md:` path prefix;
no object storage is needed.

Run:
    uv run python -m streaming.sink.kafka_to_md
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
import time
from datetime import UTC, datetime

import duckdb
from confluent_kafka import Consumer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("kafka-to-md")

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
KAFKA_SASL_MECH = os.getenv("KAFKA_SASL_MECHANISM") or None
KAFKA_SASL_USER = os.getenv("KAFKA_SASL_USERNAME") or None
KAFKA_SASL_PASS = os.getenv("KAFKA_SASL_PASSWORD") or None

MD_CATALOG = os.getenv("MD_CATALOG", "phishing_radar")
MD_DATABASE = os.getenv("MD_DATABASE", "main")
MOTHERDUCK_TOKEN = os.environ["MOTHERDUCK_TOKEN"]

TOPIC_TO_TABLE = {
    os.getenv("CERTSTREAM_TOPIC", "certstream_events"): "raw_certstream_events",
    os.getenv("SUSPICIOUS_TOPIC", "suspicious_certs"): "raw_suspicious_certs",
    os.getenv("STATS_TOPIC", "cert_stats_1min"): "raw_cert_stats_1min",
}

BATCH_SIZE = int(os.getenv("SINK_BATCH_SIZE", "500"))
FLUSH_SECONDS = float(os.getenv("SINK_FLUSH_SECONDS", "10"))
# Watchdog: if the main loop has not advanced in this many seconds we
# os._exit and let Fly's restart policy bring up a fresh machine. We have
# observed librdkafka consumers frozen with the process otherwise healthy
# (RAM steady, no crash, no logs); the watchdog turns that silent failure
# into a deterministic restart.
FREEZE_THRESHOLD_SECONDS = float(os.getenv("SINK_FREEZE_THRESHOLD_SECONDS", "600"))
WATCHDOG_INTERVAL_SECONDS = 30.0


def _connect() -> duckdb.DuckDBPyConnection:
    conn_str = f"md:{MD_CATALOG}?motherduck_token={MOTHERDUCK_TOKEN}"
    return duckdb.connect(conn_str)


def _ensure_tables(conn: duckdb.DuckDBPyConnection) -> None:
    for table in set(TOPIC_TO_TABLE.values()):
        conn.execute(f"""
            CREATE TABLE IF NOT EXISTS {table} (
                received_at TIMESTAMP NOT NULL,
                key VARCHAR,
                payload JSON NOT NULL
            )
        """)


def _build_consumer() -> Consumer:
    config: dict[str, str] = {
        "bootstrap.servers": KAFKA_BOOTSTRAP,
        "group.id": "phishing-radar-md-sink",
        "auto.offset.reset": "earliest",
        "enable.auto.commit": "true",
    }
    if KAFKA_SASL_MECH:
        config["security.protocol"] = "SASL_SSL"
        config["sasl.mechanism"] = KAFKA_SASL_MECH
        config["sasl.username"] = KAFKA_SASL_USER or ""
        config["sasl.password"] = KAFKA_SASL_PASS or ""
    return Consumer(config)


def main() -> int:
    conn = _connect()
    _ensure_tables(conn)

    consumer = _build_consumer()
    consumer.subscribe(list(TOPIC_TO_TABLE))

    buffers: dict[str, list[tuple[str, str | None, str]]] = {t: [] for t in set(TOPIC_TO_TABLE.values())}
    last_flush = time.monotonic()
    total_inserted = 0
    stop = False

    # Heartbeat updated by the main loop on every iteration. The watchdog
    # thread reads it to decide whether the loop is alive.
    last_progress_at = time.monotonic()

    def shutdown(*_: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    def watchdog() -> None:
        """Daemon thread. If the main loop hasn't advanced in
        FREEZE_THRESHOLD_SECONDS, exit hard so Fly restarts the machine."""
        while not stop:
            time.sleep(WATCHDOG_INTERVAL_SECONDS)
            stalled_for = time.monotonic() - last_progress_at
            if stalled_for > FREEZE_THRESHOLD_SECONDS:
                log.error(
                    "watchdog: no main-loop progress for %.0fs (threshold=%.0fs); exiting for restart",
                    stalled_for,
                    FREEZE_THRESHOLD_SECONDS,
                )
                # _exit bypasses atexit hooks and finally blocks. We want a
                # fast, deterministic exit; whatever was holding the loop
                # might also block normal shutdown.
                os._exit(1)

    threading.Thread(target=watchdog, daemon=True, name="sink-watchdog").start()

    def flush() -> None:
        nonlocal total_inserted
        for table_name, rows in buffers.items():
            if not rows:
                continue
            conn.executemany(
                f"INSERT INTO {table_name} (received_at, key, payload) VALUES (?, ?, ?::JSON)",
                rows,
            )
            total_inserted += len(rows)
            rows.clear()

    try:
        while not stop:
            msg = consumer.poll(1.0)
            last_progress_at = time.monotonic()  # poll returned, loop is alive
            if msg is None:
                if time.monotonic() - last_flush >= FLUSH_SECONDS:
                    flush()
                    last_flush = time.monotonic()
                    log.info("idle flush; total_inserted=%d", total_inserted)
                continue
            if msg.error():
                log.warning("consumer error: %s", msg.error())
                continue

            table = TOPIC_TO_TABLE.get(msg.topic())
            if not table:
                continue

            try:
                payload_str = msg.value().decode()
                json.loads(payload_str)  # validate JSON
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                log.warning("bad message on %s: %s", msg.topic(), e)
                continue

            buffers[table].append(
                (
                    datetime.now(UTC).isoformat(),
                    msg.key().decode() if msg.key() else None,
                    payload_str,
                )
            )

            total_pending = sum(len(b) for b in buffers.values())
            if total_pending >= BATCH_SIZE or time.monotonic() - last_flush >= FLUSH_SECONDS:
                flush()
                last_flush = time.monotonic()
                log.info("flushed; total_inserted=%d", total_inserted)
    finally:
        flush()
        consumer.close()
        conn.close()
        log.info("shutdown; total_inserted=%d", total_inserted)

    return 0


if __name__ == "__main__":
    sys.exit(main())
