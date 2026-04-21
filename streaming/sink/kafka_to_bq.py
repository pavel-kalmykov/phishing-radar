"""Kafka topics -> BigQuery streaming inserts.

Consumes the three streaming topics emitted by our pipeline and lands them
to their corresponding raw tables in BigQuery:

- `certstream_events`  -> `raw_certstream_events`
- `suspicious_certs`   -> `raw_suspicious_certs`
- `cert_stats_1min`    -> `raw_cert_stats_1min`

Tables are created on first run with a liberal schema (one JSON payload column
plus a received_at timestamp) so dbt owns the parsing. This keeps the sink
cheap and schema-evolution friendly.

Run:
    uv run python -m streaming.sink.kafka_to_bq
"""
from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
from datetime import UTC, datetime

from confluent_kafka import Consumer
from google.cloud import bigquery

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("kafka-to-bq")

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
PROJECT = os.getenv("GCP_PROJECT_ID", "phishing-radar-putopavel")
DATASET = os.getenv("BQ_DATASET", "phishing_radar")

TOPIC_TO_TABLE = {
    os.getenv("CERTSTREAM_TOPIC", "certstream_events"): "raw_certstream_events",
    os.getenv("SUSPICIOUS_TOPIC", "suspicious_certs"): "raw_suspicious_certs",
    os.getenv("STATS_TOPIC", "cert_stats_1min"): "raw_cert_stats_1min",
}

BATCH_SIZE = int(os.getenv("SINK_BATCH_SIZE", "500"))
FLUSH_SECONDS = float(os.getenv("SINK_FLUSH_SECONDS", "10"))


def ensure_table(client: bigquery.Client, table_name: str) -> None:
    """Create the raw table with (received_at, payload JSON) if missing."""
    table_id = f"{PROJECT}.{DATASET}.{table_name}"
    try:
        client.get_table(table_id)
        return
    except Exception:
        pass

    schema = [
        bigquery.SchemaField("received_at", "TIMESTAMP", mode="REQUIRED"),
        bigquery.SchemaField("key", "STRING", mode="NULLABLE"),
        bigquery.SchemaField("payload", "JSON", mode="REQUIRED"),
    ]
    table = bigquery.Table(table_id, schema=schema)
    table.time_partitioning = bigquery.TimePartitioning(
        type_=bigquery.TimePartitioningType.DAY,
        field="received_at",
    )
    client.create_table(table)
    log.info("created %s", table_id)


def main() -> int:
    bq_client = bigquery.Client(project=PROJECT)
    for table in set(TOPIC_TO_TABLE.values()):
        ensure_table(bq_client, table)

    consumer = Consumer({
        "bootstrap.servers": KAFKA_BOOTSTRAP,
        "group.id": "phishing-radar-bq-sink",
        "auto.offset.reset": "earliest",
        "enable.auto.commit": True,
    })
    consumer.subscribe(list(TOPIC_TO_TABLE))

    buffers: dict[str, list[dict]] = {t: [] for t in set(TOPIC_TO_TABLE.values())}
    last_flush = time.monotonic()
    total_inserted = 0
    stop = False

    def shutdown(*_: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    def flush() -> None:
        nonlocal total_inserted
        for table_name, rows in buffers.items():
            if not rows:
                continue
            table_id = f"{PROJECT}.{DATASET}.{table_name}"
            errors = bq_client.insert_rows_json(table_id, rows)
            if errors:
                log.error("insert_rows_json errors for %s: %s", table_id, errors)
            else:
                total_inserted += len(rows)
            rows.clear()

    try:
        while not stop:
            msg = consumer.poll(1.0)
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
                payload = json.loads(msg.value().decode())
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                log.warning("bad message on %s: %s", msg.topic(), e)
                continue

            buffers[table].append({
                "received_at": datetime.now(UTC).isoformat(),
                "key": msg.key().decode() if msg.key() else None,
                "payload": json.dumps(payload),
            })

            total_pending = sum(len(b) for b in buffers.values())
            if total_pending >= BATCH_SIZE or time.monotonic() - last_flush >= FLUSH_SECONDS:
                flush()
                last_flush = time.monotonic()
                log.info("flushed; total_inserted=%d", total_inserted)
    finally:
        flush()
        consumer.close()
        log.info("shutdown; total_inserted=%d", total_inserted)

    return 0


if __name__ == "__main__":
    sys.exit(main())
