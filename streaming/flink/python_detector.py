"""Pure-Python streaming detector, functionally equivalent to the PyFlink job.

Same input (certstream_events topic), same detection (streaming.flink.detectors.detect),
same outputs (suspicious_certs + cert_stats_1min topics), but implemented with
plain confluent-kafka so it runs anywhere without a Flink cluster.

The PyFlink job in `phishing_detector.py` is the production-grade version with
checkpointing, exactly-once delivery and native windowing. This one is the
"demo friendly" sibling: identical business logic, easier to run locally, and
what we point `make flink` at for quick iteration.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
from collections import defaultdict

from confluent_kafka import Consumer, Producer

from streaming.flink.detectors import detect

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("python-detector")

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
IN_TOPIC = os.getenv("CERTSTREAM_TOPIC", "certstream_events")
OUT_SUSPICIOUS = os.getenv("SUSPICIOUS_TOPIC", "suspicious_certs")
OUT_STATS = os.getenv("STATS_TOPIC", "cert_stats_1min")
WINDOW_SECONDS = 60


def enrich(event: dict) -> dict | None:
    domains = event.get("all_domains") or []
    if not domains:
        return None
    hits = []
    for d in domains:
        det = detect(d)
        if det:
            hits.append(
                {
                    "domain": d,
                    "brand": det.brand,
                    "category": det.category,
                    "reason": det.reason,
                    "score": det.score,
                }
            )
    if not hits:
        return None
    return {
        "seen_at": event.get("seen_at"),
        "primary_domain": event.get("primary_domain"),
        "issuer_cn": event.get("issuer_cn"),
        "issuer_o": event.get("issuer_o"),
        "not_before": event.get("not_before"),
        "not_after": event.get("not_after"),
        "fingerprint": event.get("fingerprint"),
        "detections": hits,
        "max_score": max(h["score"] for h in hits),
    }


def _sasl_config() -> dict[str, str]:
    mech = os.getenv("KAFKA_SASL_MECHANISM")
    if not mech:
        return {}
    return {
        "security.protocol": "SASL_SSL",
        "sasl.mechanism": mech,
        "sasl.username": os.getenv("KAFKA_SASL_USERNAME", ""),
        "sasl.password": os.getenv("KAFKA_SASL_PASSWORD", ""),
    }


def main() -> int:
    consumer = Consumer(
        {
            "bootstrap.servers": KAFKA_BOOTSTRAP,
            "group.id": "phishing-radar-python-detector",
            "auto.offset.reset": "earliest",
            "enable.auto.commit": True,
            **_sasl_config(),
        }
    )
    producer = Producer(
        {
            "bootstrap.servers": KAFKA_BOOTSTRAP,
            "compression.type": "zstd",
            **_sasl_config(),
        }
    )
    consumer.subscribe([IN_TOPIC])

    # Tumbling window: (window_start_unix // WINDOW_SECONDS) -> { issuer_cn -> (sus, total) }
    windows: dict[int, dict[str, list[int]]] = defaultdict(lambda: defaultdict(lambda: [0, 0]))

    stop = False

    def shutdown(*_: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    emitted_suspicious = 0
    emitted_stats = 0

    def flush_closed_windows() -> None:
        nonlocal emitted_stats
        now_bucket = int(time.time()) // WINDOW_SECONDS
        for bucket in list(windows):
            if bucket >= now_bucket:
                continue  # still open
            for issuer, (sus, total) in windows[bucket].items():
                record = {
                    "window_end": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime((bucket + 1) * WINDOW_SECONDS)),
                    "issuer_cn": issuer,
                    "suspicious_count": sus,
                    "total_count": total,
                }
                producer.produce(OUT_STATS, value=json.dumps(record).encode())
                emitted_stats += 1
            del windows[bucket]

    last_stats_log = time.time()

    try:
        while not stop:
            msg = consumer.poll(1.0)
            flush_closed_windows()
            if time.time() - last_stats_log > 30:
                log.info(
                    "emitted_suspicious=%d emitted_stats=%d open_windows=%d",
                    emitted_suspicious,
                    emitted_stats,
                    len(windows),
                )
                last_stats_log = time.time()
            if msg is None or msg.error():
                continue
            try:
                event = json.loads(msg.value().decode())
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue

            issuer = event.get("issuer_cn") or "(unknown)"
            bucket = int(time.time()) // WINDOW_SECONDS

            enriched = enrich(event)
            if enriched:
                producer.produce(
                    OUT_SUSPICIOUS,
                    key=(enriched.get("primary_domain") or "").encode(),
                    value=json.dumps(enriched).encode(),
                )
                emitted_suspicious += 1
                windows[bucket][issuer][0] += 1  # suspicious
            windows[bucket][issuer][1] += 1  # total

            producer.poll(0)
    finally:
        flush_closed_windows()
        producer.flush(10)
        consumer.close()
        log.info("shutdown emitted_suspicious=%d emitted_stats=%d", emitted_suspicious, emitted_stats)

    return 0


if __name__ == "__main__":
    sys.exit(main())
