"""Volume counter for pipeline observability.

Consumes `certstream_events` and counts how many certificates flow through
the firehose per minute. Each minute it writes a `volume` event to
`raw_pipeline_events` so that `mart_pipeline_health` can compare the raw
count against what the detector produced (SUM of cert_stats_1min.count).

Runs as a separate process from the sink so that a sink crash does not
blind the observability plane.

Run:
    uv run python -m streaming.observability.pipeline_monitor
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

from streaming.sink._common import (
    CERTSTREAM_TOPIC,
    PIPELINE_EVENTS_TABLE,
    connect_db,
    build_consumer,
    ensure_pipeline_events_table,
    execute_with_retry,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("pipeline-monitor")

FREEZE_THRESHOLD_SECONDS = float(os.getenv("MONITOR_FREEZE_THRESHOLD_SECONDS", "600"))
WATCHDOG_INTERVAL_SECONDS = 30.0


class VolumeCounter(threading.Thread):
    """Poll a Kafka topic, count messages per minute, write volume events.

    One thread is enough — counting is cheap and a single consumer can
    easily keep up with the firehose.

    Windows are aligned to wall-clock minute boundaries (:00 seconds) so
    that ``date_trunc('minute', event_at)`` on the volume event matches
    the detector's ``window_end`` boundary exactly.
    """

    def __init__(self, topic: str, stop: threading.Event) -> None:
        super().__init__(daemon=True, name="volume-counter")
        self.topic = topic
        self.stop = stop
        self.last_progress_at = time.monotonic()
        self._count = 0
        self._total = 0
        self._current_minute: datetime | None = None
        self._consumer = build_consumer(group_id="phishing-radar-volume-counter")
        self._consumer.subscribe([topic])
        self._conn = connect_db()
        ensure_pipeline_events_table(self._conn)

    def run(self) -> None:
        log.info("volume counter started on topic=%s", self.topic)
        try:
            while not self.stop.is_set():
                msg = self._consumer.poll(1.0)
                self.last_progress_at = time.monotonic()
                if msg is None:
                    self._maybe_flush()
                    continue
                if msg.error():
                    log.warning("consumer error: %s", msg.error())
                    continue
                self._count += 1
                self._maybe_flush()
        finally:
            self._maybe_flush()
            self._consumer.close()
            self._conn.close()
            log.info("volume counter stopped total_counted=%d", self._total)

    def _maybe_flush(self) -> None:
        now_utc = datetime.now(UTC)
        current_minute = now_utc.replace(second=0, microsecond=0)
        if self._current_minute is None:
            self._current_minute = current_minute
            return
        if current_minute > self._current_minute:
            execute_with_retry(
                self._conn,
                f"INSERT INTO {PIPELINE_EVENTS_TABLE} VALUES (?, 'volume_counter', 'volume', ?::JSON)",
                [current_minute.isoformat(), json.dumps({"cert_count": self._count, "topic": self.topic})],
            )
            log.info("volume: %d certs in the last minute", self._count)
            self._total += self._count
            self._count = 0
            self._current_minute = current_minute


def _watchdog(counter: VolumeCounter, stop: threading.Event) -> None:
    while not stop.is_set():
        time.sleep(WATCHDOG_INTERVAL_SECONDS)
        stalled_for = time.monotonic() - counter.last_progress_at
        if stalled_for > FREEZE_THRESHOLD_SECONDS:
            log.error(
                "watchdog: volume counter stalled for %.0fs (threshold=%.0fs); exiting for restart",
                stalled_for,
                FREEZE_THRESHOLD_SECONDS,
            )
            try:
                conn = connect_db()
                execute_with_retry(
                    conn,
                    f"INSERT INTO {PIPELINE_EVENTS_TABLE} VALUES (NOW(), 'monitor_watchdog', 'freeze', ?::JSON)",
                    [json.dumps({"stalled_sec": int(stalled_for)})],
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

    counter = VolumeCounter(CERTSTREAM_TOPIC, stop)
    counter.start()

    threading.Thread(
        target=_watchdog, args=(counter, stop), daemon=True, name="monitor-watchdog"
    ).start()

    while not stop.is_set():
        time.sleep(1)

    log.info("shutdown signal received, waiting for volume counter")
    counter.join(timeout=15)
    log.info("volume counter stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
