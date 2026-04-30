"""Kafka topics -> MotherDuck.

Consumes the two output streams emitted by the detector and lands each one
to its corresponding raw table in the MotherDuck database:

- `suspicious_certs`   -> `raw_suspicious_certs`
- `cert_stats_1min`    -> `raw_cert_stats_1min`

Each topic is served by its own Consumer + DuckDB connection in its own
thread. The previous design subscribed a single Consumer to all topics
and rotated through them via `fetch.max.bytes` tuning, which is the kind
of fair-share-by-tuning that breaks the moment one topic's volume jumps;
the per-topic thread split makes the fair share a property of the design
instead of a runtime knob.

The upstream `certstream_events` topic is intentionally NOT sunk into
MotherDuck. Every cert in the firehose passes through the detector which
either flags it (-> suspicious_certs) or aggregates it (-> cert_stats_1min);
no model nor dashboard widget reads the raw firehose, so writing it to
the warehouse is pure cost (compute + storage). Auditability stays at
the Kafka layer (24 h retention).

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
    os.getenv("SUSPICIOUS_TOPIC", "suspicious_certs"): "raw_suspicious_certs",
    os.getenv("STATS_TOPIC", "cert_stats_1min"): "raw_cert_stats_1min",
}

BATCH_SIZE = int(os.getenv("SINK_BATCH_SIZE", "500"))
FLUSH_SECONDS = float(os.getenv("SINK_FLUSH_SECONDS", "10"))
# Watchdog: if any worker thread has not advanced in this many seconds we
# os._exit and let Fly's restart policy bring up a fresh machine. We have
# observed librdkafka consumers frozen with the process otherwise healthy
# (RAM steady, no crash, no logs); the watchdog turns that silent failure
# into a deterministic restart.
FREEZE_THRESHOLD_SECONDS = float(os.getenv("SINK_FREEZE_THRESHOLD_SECONDS", "600"))
WATCHDOG_INTERVAL_SECONDS = 30.0

CONSUMER_GROUP_PREFIX = "phishing-radar-md-sink"


def _connect() -> duckdb.DuckDBPyConnection:
    conn_str = f"md:{MD_CATALOG}?motherduck_token={MOTHERDUCK_TOKEN}"
    return duckdb.connect(conn_str)


def _ensure_table(conn: duckdb.DuckDBPyConnection, table: str) -> None:
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS {table} (
            received_at TIMESTAMP NOT NULL,
            key VARCHAR,
            payload JSON NOT NULL
        )
    """)


def _build_consumer(group_id: str) -> Consumer:
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


class TopicWorker(threading.Thread):
    """One Kafka consumer + one DuckDB connection per topic.

    Each worker owns its poll/flush cadence so a slow topic cannot stall a
    fast one. Offsets are tracked in independent consumer groups
    (`{prefix}-{topic}`) so re-balancing one topic does not affect the others.
    """

    def __init__(self, topic: str, table: str, stop: threading.Event) -> None:
        super().__init__(daemon=True, name=f"sink-{topic}")
        self.topic = topic
        self.table = table
        self.stop = stop
        self.last_progress_at = time.monotonic()
        self.last_flush = time.monotonic()
        self.total_inserted = 0
        self._buffer: list[tuple[str, str | None, str]] = []
        self._consumer = _build_consumer(group_id=f"{CONSUMER_GROUP_PREFIX}-{topic}")
        self._consumer.subscribe([topic])
        self._conn = _connect()
        _ensure_table(self._conn, table)

    def run(self) -> None:
        log.info("[%s] worker started", self.topic)
        try:
            while not self.stop.is_set():
                msg = self._consumer.poll(1.0)
                self.last_progress_at = time.monotonic()
                if msg is None:
                    if time.monotonic() - self.last_flush >= FLUSH_SECONDS:
                        self._flush(idle=True)
                    continue
                if msg.error():
                    log.warning("[%s] consumer error: %s", self.topic, msg.error())
                    continue
                try:
                    payload_str = msg.value().decode()
                    json.loads(payload_str)  # validate JSON
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    log.warning("[%s] bad message: %s", self.topic, e)
                    continue
                self._buffer.append(
                    (
                        datetime.now(UTC).isoformat(),
                        msg.key().decode() if msg.key() else None,
                        payload_str,
                    )
                )
                if len(self._buffer) >= BATCH_SIZE or time.monotonic() - self.last_flush >= FLUSH_SECONDS:
                    self._flush()
        finally:
            self._flush()
            self._consumer.close()
            self._conn.close()
            log.info("[%s] worker stopped total_inserted=%d", self.topic, self.total_inserted)

    def _flush(self, idle: bool = False) -> None:
        if self._buffer:
            self._conn.executemany(
                f"INSERT INTO {self.table} (received_at, key, payload) VALUES (?, ?, ?::JSON)",
                self._buffer,
            )
            n = len(self._buffer)
            self.total_inserted += n
            self._buffer.clear()
            log.info("[%s] flushed n=%d total_inserted=%d", self.topic, n, self.total_inserted)
        elif idle:
            log.info("[%s] idle flush total_inserted=%d", self.topic, self.total_inserted)
        self.last_flush = time.monotonic()


def _watchdog(workers: list[TopicWorker], stop: threading.Event) -> None:
    """Daemon thread. If any worker hasn't advanced in
    FREEZE_THRESHOLD_SECONDS, exit hard so Fly restarts the machine."""
    while not stop.is_set():
        time.sleep(WATCHDOG_INTERVAL_SECONDS)
        now = time.monotonic()
        for w in workers:
            stalled_for = now - w.last_progress_at
            if stalled_for > FREEZE_THRESHOLD_SECONDS:
                log.error(
                    "watchdog: worker %s stalled for %.0fs (threshold=%.0fs); exiting for restart",
                    w.topic,
                    stalled_for,
                    FREEZE_THRESHOLD_SECONDS,
                )
                # _exit bypasses atexit hooks and finally blocks. We want a
                # fast, deterministic exit; whatever was holding the worker
                # might also block normal shutdown.
                os._exit(1)


def main() -> int:
    stop = threading.Event()

    def shutdown(*_: object) -> None:
        stop.set()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    workers = [TopicWorker(topic, table, stop) for topic, table in TOPIC_TO_TABLE.items()]
    for w in workers:
        w.start()

    threading.Thread(target=_watchdog, args=(workers, stop), daemon=True, name="sink-watchdog").start()

    # Block the main thread until SIGINT/SIGTERM. Worker threads do all
    # the actual work; the main thread is just here to own the process and
    # catch signals.
    while not stop.is_set():
        time.sleep(1)

    log.info("shutdown signal received, waiting for workers")
    for w in workers:
        w.join(timeout=15)
    log.info("all workers stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
