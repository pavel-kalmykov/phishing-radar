"""Local runner: sink + dashboard in the same process.

DuckDB on macOS does not allow a second process to open a connection
while another process holds a read-write connection. To run the full
local stack (streaming pipeline + dashboard) simultaneously, the sink
workers and the Streamlit server must share the same process.

Usage:
    DATABASE_URL=data/local.duckdb uv run python -m streaming.local_runner
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading

from streaming.sink._common import (
    CERTSTREAM_TOPIC,
    DATABASE_URL,
    connect_db,
    ensure_pipeline_events_table,
)
from streaming.sink.kafka_to_md import TOPIC_TO_TABLE, TopicWorker, _watchdog
from streaming.observability.pipeline_monitor import VolumeCounter

log = logging.getLogger("local-runner")

DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "8501"))


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    if not DATABASE_URL:
        log.error("DATABASE_URL must be set for local runner")
        return 1

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

    vol_counter = VolumeCounter(CERTSTREAM_TOPIC, stop)
    vol_counter.start()
    log.info("volume counter started")

    _dashboard_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "dashboard")
    )
    sys.path.insert(0, _dashboard_dir)

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
    vol_counter.join(timeout=15)
    log.info("shutdown complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
