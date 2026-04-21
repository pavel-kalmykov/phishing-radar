"""CertStream WebSocket -> Redpanda producer.

Connects to the CertStream firehose (wss://certstream.calidog.io/) and publishes
every certificate event to a Kafka topic. Flattens the nested payload into a
single record per certificate so downstream consumers don't have to care about
the CertStream message shape.

Designed to be a long-running process. Auto-reconnects on websocket drops.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import signal
import ssl
import sys
from datetime import UTC, datetime
from typing import Any

import certifi
import websockets
from confluent_kafka import Producer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("certstream-producer")


CERTSTREAM_URL = os.getenv("CERTSTREAM_URL", "ws://localhost:8090/full-stream")
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
CERTSTREAM_TOPIC = os.getenv("CERTSTREAM_TOPIC", "certstream_events")


def flatten_event(event: dict[str, Any]) -> dict[str, Any] | None:
    """CertStream messages arrive with type 'heartbeat' or 'certificate_update'.
    Keep only the latter and flatten to a stable schema."""
    if event.get("message_type") != "certificate_update":
        return None

    data = event.get("data", {})
    leaf = data.get("leaf_cert", {}) or {}
    subject = leaf.get("subject", {}) or {}
    issuer = leaf.get("issuer", {}) or {}
    extensions = leaf.get("extensions", {}) or {}

    all_domains = data.get("all_domains") or leaf.get("all_domains") or []
    primary_domain = all_domains[0] if all_domains else subject.get("CN", "")

    return {
        "seen_at": datetime.now(UTC).isoformat(),
        "cert_index": data.get("cert_index"),
        "update_type": data.get("update_type"),
        "source": (data.get("source") or {}).get("url"),
        "primary_domain": primary_domain,
        "all_domains": all_domains,
        "domain_count": len(all_domains),
        "not_before": _ts_to_iso(leaf.get("not_before")),
        "not_after": _ts_to_iso(leaf.get("not_after")),
        "serial_number": leaf.get("serial_number"),
        "fingerprint": leaf.get("fingerprint"),
        "signature_algorithm": leaf.get("signature_algorithm"),
        "subject_cn": subject.get("CN"),
        "subject_o": subject.get("O"),
        "subject_c": subject.get("C"),
        "issuer_cn": issuer.get("CN"),
        "issuer_o": issuer.get("O"),
        "issuer_c": issuer.get("C"),
        "san_count": (
            extensions.get("subjectAltName", "").count("DNS:")
            if isinstance(extensions.get("subjectAltName"), str) else 0
        ),
    }


def _ts_to_iso(ts: float | int | None) -> str | None:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts), UTC).isoformat()
    except (ValueError, OSError):
        return None


class CertStreamProducer:
    def __init__(self, bootstrap: str = KAFKA_BOOTSTRAP, topic: str = CERTSTREAM_TOPIC):
        self.topic = topic
        config: dict[str, Any] = {
            "bootstrap.servers": bootstrap,
            "linger.ms": 50,
            "batch.size": 65536,
            "compression.type": "zstd",
            "acks": "all",
        }
        sasl_mech = os.getenv("KAFKA_SASL_MECHANISM")
        if sasl_mech:
            config["security.protocol"] = "SASL_SSL"
            config["sasl.mechanism"] = sasl_mech
            config["sasl.username"] = os.getenv("KAFKA_SASL_USERNAME", "")
            config["sasl.password"] = os.getenv("KAFKA_SASL_PASSWORD", "")
        self.producer = Producer(config)
        self._stop = asyncio.Event()
        self._sent = 0
        self._skipped = 0

    def _delivery_report(self, err: Any, msg: Any) -> None:
        if err is not None:
            log.warning("delivery failed: %s", err)

    async def _poll_loop(self) -> None:
        """Drive librdkafka callbacks from asyncio so delivery reports fire."""
        while not self._stop.is_set():
            self.producer.poll(0)
            await asyncio.sleep(0.5)

    async def _stats_loop(self) -> None:
        while not self._stop.is_set():
            await asyncio.sleep(30)
            log.info("sent=%d skipped=%d", self._sent, self._skipped)

    async def _consume(self) -> None:
        backoff = 1
        # Build an SSL context that trusts an explicit CA bundle if provided (e.g. a
        # corporate MITM proxy CA). Falls back to certifi otherwise.
        ca_file = os.getenv("SSL_CERT_FILE") or os.getenv("CERTSTREAM_CA_FILE") or certifi.where()
        ssl_ctx = ssl.create_default_context(cafile=ca_file)

        while not self._stop.is_set():
            try:
                log.info("connecting to %s (ca=%s)", CERTSTREAM_URL, ca_file)
                async with websockets.connect(
                    CERTSTREAM_URL,
                    ssl=ssl_ctx if CERTSTREAM_URL.startswith("wss://") else None,
                    open_timeout=20,
                    ping_interval=20,
                    ping_timeout=20,
                    max_size=None,
                ) as ws:
                    log.info("connected, streaming events")
                    backoff = 1
                    async for raw in ws:
                        if self._stop.is_set():
                            break
                        try:
                            event = json.loads(raw)
                        except json.JSONDecodeError:
                            self._skipped += 1
                            continue

                        flat = flatten_event(event)
                        if flat is None:
                            self._skipped += 1
                            continue

                        key = (flat.get("primary_domain") or "").encode()
                        self.producer.produce(
                            self.topic,
                            key=key,
                            value=json.dumps(flat).encode(),
                            on_delivery=self._delivery_report,
                        )
                        self._sent += 1
            except Exception as e:
                log.warning("websocket error: %s; reconnecting in %ds", e, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self._stop.set)
        try:
            await asyncio.gather(
                self._consume(),
                self._poll_loop(),
                self._stats_loop(),
            )
        finally:
            log.info("flushing producer; sent=%d skipped=%d", self._sent, self._skipped)
            self.producer.flush(10)


def main() -> int:
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(CertStreamProducer().run())
    return 0


if __name__ == "__main__":
    sys.exit(main())
