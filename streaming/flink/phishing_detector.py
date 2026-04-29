# mypy: disable-error-code=import-not-found
"""PyFlink streaming job: phishing typosquatting detection + windowed aggregates.

Reads `certstream_events` from Kafka, runs the typosquatting heuristic on each
domain, and produces two output streams:

- `suspicious_certs`: one row per cert that matches at least one brand
- `cert_stats_1min`: per-minute tumbling-window aggregates (suspicious count,
  total count, top issuer CA)

Both outputs land in Kafka. The downstream sink (`streaming.sink.kafka_to_md`)
is responsible for landing them into MotherDuck.

The `pyflink` wheel is not in the dev `uv.lock` (its transitive
`pyarrow<12` cap conflicts with dlt's `pyarrow>=18`), so the file-level
mypy directive above suppresses import-not-found on the pyflink imports.
The wheel is pip-installed inside `Dockerfile.detector` at image build time.

Run locally (requires JDK 17+ and a manual `pip install apache-flink`):

    uv run python -m streaming.flink.phishing_detector
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterator
from datetime import UTC, datetime

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

# PyFlink's pip wheel ships only the runtime; the Kafka connector is a
# separate fat-jar that Dockerfile.detector downloads to /app/jars at build
# time. Override via FLINK_CONNECTOR_JARS_DIR for local dev.
FLINK_JARS_DIR = os.getenv("FLINK_CONNECTOR_JARS_DIR", "/app/jars")


def _enrich_with_detection(raw_json: str) -> str | None:
    """Run typosquatting detection on a certstream event. Returns a JSON string
    when the cert matches at least one brand, else None."""
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
            hits.append(
                {
                    "domain": dom,
                    "brand": det.brand,
                    "category": det.category,
                    "reason": det.reason,
                    "score": det.score,
                }
            )

    if not hits:
        return None

    out = {
        "seen_at": event.get("seen_at"),
        "primary_domain": event.get("primary_domain", ""),
        "issuer_cn": event.get("issuer_cn"),
        "issuer_o": event.get("issuer_o"),
        "not_before": event.get("not_before"),
        "not_after": event.get("not_after"),
        "fingerprint": event.get("fingerprint"),
        "detections": hits,
        "max_score": max(h["score"] for h in hits),
    }
    return json.dumps(out)


def enrich_flat_map(raw_json: str) -> Iterator[str]:
    """flat_map adapter: yield 0 or 1 enriched JSON strings.

    Uses flat_map (not map + filter) so PyFlink's output_type stays a strict
    STRING and we never have to serialise a None.
    """
    result = _enrich_with_detection(raw_json)
    if result is not None:
        yield result


def stats_flat_map(raw_json: str) -> Iterator[tuple[str, int, int]]:
    """flat_map adapter for the per-minute aggregate branch. Emits
    (issuer_cn, suspicious_flag, 1) per parseable event."""
    try:
        event = json.loads(raw_json)
    except json.JSONDecodeError:
        return

    issuer = event.get("issuer_cn") or "(unknown)"

    flagged = 0
    for dom in event.get("all_domains") or []:
        if detect(dom):
            flagged = 1
            break

    yield (issuer, flagged, 1)


def stats_to_json(t: tuple[str, int, int]) -> str:
    return json.dumps(
        {
            "window_end": datetime.now(UTC).isoformat(),
            "issuer_cn": t[0],
            "suspicious_count": t[1],
            "total_count": t[2],
        }
    )


def build_pipeline() -> StreamExecutionEnvironment:
    env = StreamExecutionEnvironment.get_execution_environment()
    env.set_parallelism(1)  # single-slot MiniCluster on Fly; matches the firehose rate
    env.enable_checkpointing(60_000)  # 1 min checkpoints

    # Register the Kafka connector fat-jar(s) on the JVM classpath. Without
    # this, KafkaSource.builder() raises 'Could not found the Java class'.
    from pathlib import Path

    jar_dir = Path(FLINK_JARS_DIR)
    if jar_dir.exists():
        jar_uris = [f"file://{p}" for p in jar_dir.glob("*.jar")]
        if jar_uris:
            env.add_jars(*jar_uris)
            log.info("loaded %d connector jar(s) from %s", len(jar_uris), jar_dir)
        else:
            log.warning("FLINK_CONNECTOR_JARS_DIR=%s exists but has no jars", jar_dir)
    else:
        log.warning("FLINK_CONNECTOR_JARS_DIR=%s does not exist", jar_dir)

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
    suspicious = raw.flat_map(enrich_flat_map, output_type=Types.STRING())
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
        raw.flat_map(stats_flat_map, output_type=Types.TUPLE([Types.STRING(), Types.INT(), Types.INT()]))
        .key_by(lambda t: t[0])
        .window(TumblingEventTimeWindows.of(Time.minutes(1)))
        .reduce(lambda a, b: (a[0], a[1] + b[1], a[2] + b[2]))
        .map(stats_to_json, output_type=Types.STRING())
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
    log.info(
        "starting Flink job: %s -> {%s, %s}",
        CERTSTREAM_TOPIC,
        SUSPICIOUS_TOPIC,
        STATS_TOPIC,
    )
    env.execute("phishing-radar-detector")


if __name__ == "__main__":
    main()
