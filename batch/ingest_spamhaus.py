"""Spamhaus DROP / EDROP lists -> BigQuery.

DROP = Don't Route Or Peer. CIDR ranges Spamhaus considers hijacked or fully
controlled by criminal operations. EDROP extends the list with blocks leased
to known spam / malware operators.

Docs: https://www.spamhaus.org/drop/
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator

import dlt

from batch.common import http_session, build_pipeline

log = logging.getLogger("ingest-spamhaus")

SOURCES = {
    "drop": "https://www.spamhaus.org/drop/drop.txt",
    "edrop": "https://www.spamhaus.org/drop/edrop.txt",
}

LINE_RE = re.compile(r"^(?P<cidr>[\d./]+)\s*;\s*(?P<sbl>\S+)\s*$")


@dlt.resource(name="spamhaus_drop", write_disposition="replace")
def spamhaus_drop_resource() -> Iterator[dict]:
    session = http_session()
    for list_name, url in SOURCES.items():
        log.info("fetching %s", url)
        resp = session.get(url, timeout=60)
        resp.raise_for_status()

        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            match = LINE_RE.match(line)
            if not match:
                continue
            yield {
                "list": list_name,
                "cidr": match.group("cidr"),
                "sbl_ref": match.group("sbl"),
            }


def run() -> dict:
    logging.basicConfig(level=logging.INFO)
    pipeline = build_pipeline("ingest_spamhaus")
    load_info = pipeline.run(spamhaus_drop_resource())
    log.info("loaded: %s", load_info)
    return load_info


if __name__ == "__main__":
    run()
