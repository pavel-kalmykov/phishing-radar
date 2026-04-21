"""Run all batch ingestions sequentially.

Entry point for `make batch` and for the daily Kestra/GitHub Actions flow.
"""
from __future__ import annotations

import logging
import os
import sys

log = logging.getLogger("run-all")


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    from batch import ingest_cisa_kev, ingest_feodo, ingest_mitre, ingest_spamhaus

    pipelines = [
        ("cisa_kev", ingest_cisa_kev.run),
        ("feodo", ingest_feodo.run),
        ("spamhaus", ingest_spamhaus.run),
        ("mitre", ingest_mitre.run),
    ]

    # MaxMind requires a license key; skip gracefully if missing
    if os.getenv("MAXMIND_LICENSE_KEY"):
        from batch import ingest_maxmind
        pipelines.append(("maxmind", ingest_maxmind.run))
    else:
        log.warning("MAXMIND_LICENSE_KEY not set, skipping MaxMind ingestion")

    failures: list[str] = []
    for name, fn in pipelines:
        log.info("=== running %s ===", name)
        try:
            fn()
        except Exception as e:
            log.exception("%s failed: %s", name, e)
            failures.append(name)

    if failures:
        log.error("failed pipelines: %s", ",".join(failures))
        return 1
    log.info("all %d pipelines succeeded", len(pipelines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
