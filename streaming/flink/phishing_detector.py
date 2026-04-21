"""PyFlink streaming job: phishing typosquatting detection + windowed aggregates.

Reads `certstream_events` from Kafka, runs the typosquatting heuristic on each
domain, and produces two output streams:

- `suspicious_certs`: one row per flagged domain (detection details + cert context)
- `cert_stats_1min`: per-minute tumbling-window aggregates (total certs, suspicious
  count, top issuer CA)

Both outputs land in Kafka. A separate sink (BigQuery Write API via dlt, or an
external table over GCS) is responsible for persisting them to the warehouse.

Run:
    uv run python -m streaming.flink.phishing_detector
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime

from pyflink.common import Time, Types, WatermarkStrategy
from pyflink.common.serialization import SimpleStringSchema
from pyflink.datastream import StreamExecutionEnvironment
from pyflink.datastream.connectors.kafka import (
    KafkaOffsetsInitializer,
    KafkaRecordSerializationSchema,
    KafkaSink,
    KafkaSource,
)
from pyflink.datastream.window import TumblingEventTimeWindows

from streaming.flink.detectors import detect

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("phishing-detector")

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
CERTSTREAM_TOPIC = os.getenv("CERTSTREAM_TOPIC", "certstream_events")
SUSPICIOUS_TOPIC = os.getenv("SUSPICIOUS_TOPIC", "suspicious_certs")
STATS_TOPIC = os.getenv("STATS_TOPIC", "cert_stats_1min")


def enrich_with_detection(raw_json: str) -> str | None:
    """Take a certstream_events record, run detection, emit JSON for suspicious ones only."""
    try:
        event = json.loads(raw_json)
    except json.JSONDecodeError:
        return None

    domains = event.get("all_domains") or []
    if not domains:
        return None

    hits = []
    for dom in domains:
        det = detect(dom)
        if det:
            hits.append({
                "domain": dom,
                "brand": det.brand,
                "category": det.category,
                "reason": det.reason,
                "score": det.score,
            })

    if not hits:
        return None

    primary = event.get("primary_domain", "")
    out = {
        "seen_at": event.get("seen_at"),
        "primary_domain": primary,
        "issuer_cn": event.get("issuer_cn"),
        "issuer_o": event.get("issuer_o"),
        "not_before": event.get("not_before"),
        "not_after": event.get("not_after"),
        "fingerprint": event.get("fingerprint"),
        "detections": hits,
        "max_score": max(h["score"] for h in hits),
    }
    return json.dumps(out)


def parse_for_stats(raw_json: str) -> tuple[str, int, int] | None:
    """Return (issuer_cn, suspicious_flag, 1) for windowed aggregation."""
    try:
        event = json.loads(raw_json)
    except json.JSONDecodeError:
        return None

    issuer = event.get("issuer_cn") or "(unknown)"

    flagged = 0
    for dom in event.get("all_domains") or []:
        if detect(dom):
            flagged = 1
            break

    return (issuer, flagged, 1)


def build_pipeline() -> StreamExecutionEnvironment:
    env = StreamExecutionEnvironment.get_execution_environment()
    env.set_parallelism(1)  # small job, single slot is fine
    env.enable_checkpointing(60_000)  # 1 min checkpoints

    # --- Source: certstream_events ---
    source = (
        KafkaSource.builder()
        .set_bootstrap_servers(KAFKA_BOOTSTRAP)
        .set_topics(CERTSTREAM_TOPIC)
        .set_group_id("phishing-detector")
        .set_starting_offsets(KafkaOffsetsInitializer.latest())
        .set_value_only_deserializer(SimpleStringSchema())
        .build()
    )

    raw = env.from_source(
        source,
        WatermarkStrategy.for_monotonous_timestamps(),
        "certstream-source",
    )

    # --- Branch 1: suspicious-cert sink ---
    suspicious = (
        raw.map(enrich_with_detection, output_type=Types.STRING())
        .filter(lambda x: x is not None)
    )

    suspicious_sink = (
        KafkaSink.builder()
        .set_bootstrap_servers(KAFKA_BOOTSTRAP)
        .set_record_serializer(
            KafkaRecordSerializationSchema.builder()
            .set_topic(SUSPICIOUS_TOPIC)
            .set_value_serialization_schema(SimpleStringSchema())
            .build()
        )
        .build()
    )
    suspicious.sink_to(suspicious_sink)

    # --- Branch 2: per-minute aggregates grouped by issuer CA ---
    stats_stream = (
        raw.map(parse_for_stats, output_type=Types.TUPLE([Types.STRING(), Types.INT(), Types.INT()]))
        .filter(lambda t: t is not None)
        .key_by(lambda t: t[0])
        .window(TumblingEventTimeWindows.of(Time.minutes(1)))
        .reduce(lambda a, b: (a[0], a[1] + b[1], a[2] + b[2]))
        .map(
            lambda t: json.dumps({
                "window_end": datetime.utcnow().isoformat(),
                "issuer_cn": t[0],
                "suspicious_count": t[1],
                "total_count": t[2],
            }),
            output_type=Types.STRING(),
        )
    )

    stats_sink = (
        KafkaSink.builder()
        .set_bootstrap_servers(KAFKA_BOOTSTRAP)
        .set_record_serializer(
            KafkaRecordSerializationSchema.builder()
            .set_topic(STATS_TOPIC)
            .set_value_serialization_schema(SimpleStringSchema())
            .build()
        )
        .build()
    )
    stats_stream.sink_to(stats_sink)

    return env


def main() -> None:
    env = build_pipeline()
    log.info("starting Flink job: %s -> {%s, %s}", CERTSTREAM_TOPIC, SUSPICIOUS_TOPIC, STATS_TOPIC)
    env.execute("phishing-radar-detector")


if __name__ == "__main__":
    main()
