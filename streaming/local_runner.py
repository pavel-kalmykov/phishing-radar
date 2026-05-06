"""Local runner: sink + dashboard in the same process.

DuckDB on macOS does not allow a second process to open a connection
while another process holds a read-write connection. To run the full
local stack (streaming pipeline + dashboard) simultaneously, the sink
workers and the Streamlit server must share the same process.

Usage:
    DATABASE_URL=data/local.duckdb uv run python -m streaming.local_runner
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
import time

from streaming.sink._common import (
    DATABASE_URL,
    PIPELINE_EVENTS_TABLE,
    build_consumer,
    connect_db,
    ensure_pipeline_events_table,
    execute_with_retry,
)
from streaming.sink.kafka_to_md import TOPIC_TO_TABLE, TopicWorker, _watchdog

log = logging.getLogger("local-runner")

DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "8501"))
PIPELINE_OBS_TOPIC = os.getenv("PIPELINE_OBS_TOPIC", "pipeline_observability")
PIPELINE_OBS_GROUP = "phishing-radar-md-sink-pipeline-obs"


class PipelineObsConsumer(threading.Thread):
    """Consumes producer_volume events from Kafka and writes them to
    raw_pipeline_events so the producer never touches DuckDB directly."""

    def __init__(self, stop: threading.Event) -> None:
        super().__init__(daemon=True, name="pipeline-obs-consumer")
        self.stop = stop

    def run(self) -> None:
        consumer = build_consumer(group_id=PIPELINE_OBS_GROUP)
        consumer.subscribe([PIPELINE_OBS_TOPIC])
        conn = connect_db()
        log.info("pipeline-obs consumer started on %s", PIPELINE_OBS_TOPIC)
        try:
            while not self.stop.is_set():
                msg = consumer.poll(1.0)
                if msg is None:
                    continue
                if msg.error():
                    log.warning("pipeline-obs consumer error: %s", msg.error())
                    continue
                try:
                    payload = json.loads(msg.value().decode())
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    log.warning("pipeline-obs bad message: %s", e)
                    continue
                execute_with_retry(
                    conn,
                    f"INSERT INTO {PIPELINE_EVENTS_TABLE} VALUES ("
                    "  CAST(? AS TIMESTAMPTZ), ?, ?, ?::JSON"
                    ")",
                    [
                        payload.get("event_at", time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())),
                        payload.get("source", "certstream_producer"),
                        payload.get("event_type", "producer_volume"),
                        json.dumps({"ws_cert_count": payload.get("ws_cert_count", 0)}),
                    ],
                )
        finally:
            consumer.close()
            conn.close()
            log.info("pipeline-obs consumer stopped")


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    if not DATABASE_URL:
        log.error("DATABASE_URL must be set for local runner")
        return 1

    os.environ["LOCAL_RUNNER"] = "1"

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
    log.info("sink workers started: %s", list(TOPIC_TO_TABLE.keys()))

    threading.Thread(
        target=_watchdog, args=(workers, stop), daemon=True, name="sink-watchdog"
    ).start()

    obs_consumer = PipelineObsConsumer(stop)
    obs_consumer.start()
    log.info("pipeline obs consumer started")

    _dashboard_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "dashboard")
    )
    sys.path.insert(0, _dashboard_dir)

    import pandas  # noqa: F401  force full pandas init before Streamlit touches plotly
    import streamlit.web.bootstrap

    log.info("starting Streamlit dashboard on port %d", DASHBOARD_PORT)
    streamlit.web.bootstrap.run(
        os.path.join(_dashboard_dir, "app.py"),
        is_hello=False,
        args=["--server.headless", "true", "--server.port", str(DASHBOARD_PORT)],
        flag_options={},
    )

    stop.set()
    for w in workers:
        w.join(timeout=15)
    log.info("shutdown complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
