"""Kafka topics -> database.

Consumes the two output streams emitted by the detector and lands each one
to its corresponding raw table in the database:

- `suspicious_certs`   -> `raw_suspicious_certs`
- `cert_stats_1min`    -> `raw_cert_stats_1min`

Each topic is served by its own Consumer + DuckDB connection in its own
thread. The previous design subscribed a single Consumer to all topics
and rotated through them via `fetch.max.bytes` tuning, which is the kind
of fair-share-by-tuning that breaks the moment one topic's volume jumps;
the per-topic thread split makes the fair share a property of the design
instead of a runtime knob.

The upstream `certstream_events` topic is intentionally NOT sunk.
Every cert in the firehose passes through the detector which
either flags it (-> suspicious_certs) or aggregates it (-> cert_stats_1min);
no model nor dashboard widget reads the raw firehose, so writing it to
the warehouse is pure cost (compute + storage). Auditability stays at
the Kafka layer (24 h retention).

Each raw table has three columns: `received_at`, `key`, `payload` (JSON).
dbt owns the parsing, so the sink stays cheap and schema-evolution friendly.

Idempotency: unique indexes on the payload column combined with `INSERT OR IGNORE`
make the sink safe to run in parallel against the same database (e.g. cloud +
local stack simultaneously). Two sinks consuming the same Kafka message receive
byte-identical JSON, so the unique constraint on payload naturally deduplicates.

Retention: set `SINK_RETENTION` to a DuckDB INTERVAL string (e.g. '400 days',
'6 months', '1 year') to periodically delete rows older than the threshold.
Default is empty (no cleanup). Validated at startup via DuckDB's INTERVAL parser.

Connection: set `DATABASE_URL` to any DuckDB-compatible string (local path,
`md:` for MotherDuck, `s3://` for object storage). If `DATABASE_URL` is
not set, falls back to `MOTHERDUCK_TOKEN` + `MD_CATALOG` for backwards
compatibility with the cloud deployment.

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

from streaming.sink._common import (
    PIPELINE_EVENTS_TABLE,
    KAFKA_BOOTSTRAP,
    KAFKA_SASL_MECH,
    KAFKA_SASL_USER,
    KAFKA_SASL_PASS,
    DATABASE_URL,
    MD_CATALOG,
    MD_DATABASE,
    MOTHERDUCK_TOKEN,
    connect_db,
    build_consumer,
    ensure_pipeline_events_table,
    executemany_with_retry,
    execute_with_retry,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("kafka-to-md")

TOPIC_TO_TABLE = {
    os.getenv("SUSPICIOUS_TOPIC", "suspicious_certs"): "raw_suspicious_certs",
    os.getenv("STATS_TOPIC", "cert_stats_1min"): "raw_cert_stats_1min",
}

TABLE_UNIQUE_INDEXES: dict[str, str] = {
    "raw_suspicious_certs": (
        "CREATE UNIQUE INDEX IF NOT EXISTS udx_suspicious_payload "
        "ON raw_suspicious_certs (payload)"
    ),
    "raw_cert_stats_1min": (
        "CREATE UNIQUE INDEX IF NOT EXISTS udx_stats_payload "
        "ON raw_cert_stats_1min (payload)"
    ),
}

BATCH_SIZE = int(os.getenv("SINK_BATCH_SIZE", "500"))
FLUSH_SECONDS = float(os.getenv("SINK_FLUSH_SECONDS", "10"))
SINK_RETENTION = os.getenv("SINK_RETENTION", "")
SINK_CLEANUP_INTERVAL_SECONDS = float(os.getenv("SINK_CLEANUP_INTERVAL_SECONDS", "3600"))

if SINK_RETENTION:
    try:
        duckdb.execute(f"SELECT INTERVAL '{SINK_RETENTION}'")
    except duckdb.Error as e:
        raise ValueError(
            f"SINK_RETENTION='{SINK_RETENTION}' is not a valid DuckDB INTERVAL. "
            f"Valid examples: '30 days', '6 months', '1 year', '12 hours'. "
            f"DuckDB error: {e}"
        ) from e
# Watchdog: if any worker thread has not advanced in this many seconds we
# os._exit and let Fly's restart policy bring up a fresh machine. We have
# observed librdkafka consumers frozen with the process otherwise healthy
# (RAM steady, no crash, no logs); the watchdog turns that silent failure
# into a deterministic restart.
FREEZE_THRESHOLD_SECONDS = float(os.getenv("SINK_FREEZE_THRESHOLD_SECONDS", "600"))
WATCHDOG_INTERVAL_SECONDS = 30.0

CONSUMER_GROUP_PREFIX = "phishing-radar-md-sink"
SINK_HEARTBEAT_INTERVAL_SECONDS = float(os.getenv("SINK_HEARTBEAT_INTERVAL_SECONDS", "60"))


def _ensure_table(conn: duckdb.DuckDBPyConnection, table: str) -> None:
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS {table} (
            received_at TIMESTAMPTZ NOT NULL,
            key VARCHAR,
            payload JSON NOT NULL
        )
    """)
    if table in TABLE_UNIQUE_INDEXES:
        conn.execute(TABLE_UNIQUE_INDEXES[table])


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
        self.last_cleanup = time.monotonic()
        self.last_heartbeat = time.monotonic()
        self.total_inserted = 0
        self._buffer: list[tuple[str, str | None, str]] = []
        self._consumer = build_consumer(group_id=f"{CONSUMER_GROUP_PREFIX}-{topic}")
        self._consumer.subscribe([topic])
        self._conn = connect_db()
        _ensure_table(self._conn, table)

    def run(self) -> None:
        log.info("[%s] worker started", self.topic)
        try:
            while not self.stop.is_set():
                msg = self._consumer.poll(1.0)
                self.last_progress_at = time.monotonic()
                if msg is None:
                    pass
                elif msg.error():
                    log.warning("[%s] consumer error: %s", self.topic, msg.error())
                else:
                    try:
                        payload_str = msg.value().decode()
                        json.loads(payload_str)  # validate JSON
                    except (json.JSONDecodeError, UnicodeDecodeError) as e:
                        log.warning("[%s] bad message: %s", self.topic, e)
                    else:
                        self._buffer.append(
                            (
                                datetime.now(UTC).isoformat(),
                                msg.key().decode() if msg.key() else None,
                                payload_str,
                            )
                        )
                # Periodic tasks — run regardless of poll outcome so that
                # a worker processing a continuous stream (e.g. suspicious_certs
                # catching up on backlog) still flushes, heartbeats and cleans up.
                if len(self._buffer) >= BATCH_SIZE or time.monotonic() - self.last_flush >= FLUSH_SECONDS:
                    self._flush()
                if time.monotonic() - self.last_heartbeat >= SINK_HEARTBEAT_INTERVAL_SECONDS:
                    self._heartbeat()
                if SINK_RETENTION and time.monotonic() - self.last_cleanup >= SINK_CLEANUP_INTERVAL_SECONDS:
                    self._cleanup()
        finally:
            self._flush()
            self._consumer.close()
            self._conn.close()
            log.info("[%s] worker stopped total_inserted=%d", self.topic, self.total_inserted)

    def _flush(self) -> None:
        if self._buffer:
            executemany_with_retry(
                self._conn,
                f"INSERT OR IGNORE INTO {self.table} (received_at, key, payload) VALUES (?, ?, ?::JSON)",
                self._buffer,
            )
            n = len(self._buffer)
            self.total_inserted += n
            self._buffer.clear()
            log.info("[%s] flushed n=%d total_inserted=%d", self.topic, n, self.total_inserted)
        self.last_flush = time.monotonic()

    def _cleanup(self) -> None:
        threshold = f"NOW() - INTERVAL '{SINK_RETENTION}'"
        count = self._conn.execute(
            f"SELECT COUNT(*) FROM {self.table} WHERE received_at < {threshold}"
        ).fetchone()[0]
        if count > 0:
            execute_with_retry(self._conn, f"DELETE FROM {self.table} WHERE received_at < {threshold}")
            log.info("[%s] cleanup: deleted %d rows older than '%s'", self.topic, count, SINK_RETENTION)
        self.last_cleanup = time.monotonic()

    def _heartbeat(self) -> None:
        execute_with_retry(
            self._conn,
            f"INSERT INTO {PIPELINE_EVENTS_TABLE} VALUES (?, ?, 'heartbeat', ?::JSON)",
            [
                datetime.now(UTC).isoformat(),
                f"sink_worker_{self.topic}",
                json.dumps({"total_inserted": self.total_inserted}),
            ],
        )
        self.last_heartbeat = time.monotonic()


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
                try:
                    conn = connect_db()
                    execute_with_retry(
                        conn,
                        f"INSERT INTO {PIPELINE_EVENTS_TABLE} VALUES (NOW(), 'watchdog', 'freeze', ?::JSON)",
                        [json.dumps({"stalled_sec": int(stalled_for), "worker": w.topic})],
                    )
                    conn.close()
                except Exception:
                    pass
                os._exit(1)


def main() -> int:
    stop = threading.Event()

    def shutdown(*_: object) -> None:
        stop.set()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    conn = connect_db()
    ensure_pipeline_events_table(conn)
    conn.close()

    workers = [TopicWorker(topic, table, stop) for topic, table in TOPIC_TO_TABLE.items()]
    for w in workers:
        w.start()

    threading.Thread(target=_watchdog, args=(workers, stop), daemon=True, name="sink-watchdog").start()

    # Local DuckDB cannot have a separate pipeline_monitor process writing
    # to the same file (DuckDB is single-writer). When DATABASE_URL is set
    # we embed the volume counter inside the sink process so all writes share
    # the same lock. Cloud deployments use the standalone pipeline_monitor.
    vol_counter = None
    if DATABASE_URL and os.getenv("SINK_EMBED_VOLUME_COUNTER", "1") != "0":
        from streaming.observability.pipeline_monitor import VolumeCounter, CERTSTREAM_TOPIC as MONITOR_TOPIC

        vol_counter = VolumeCounter(MONITOR_TOPIC, stop)
        vol_counter.start()
        log.info("embedded volume counter started (local mode)")

    # Block the main thread until SIGINT/SIGTERM. Worker threads do all
    # the actual work; the main thread is just here to own the process and
    # catch signals.
    while not stop.is_set():
        time.sleep(1)

    log.info("shutdown signal received, waiting for workers")
    for w in workers:
        w.join(timeout=15)
    if vol_counter:
        vol_counter.join(timeout=15)
    log.info("all workers stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
