"""abuse.ch Feodo Tracker C2 blocklist -> BigQuery.

Active botnet command-and-control IPs, refreshed every few minutes by abuse.ch.
Covers Emotet, QBot, TrickBot, Dridex, IcedID, Heodo and others. Each entry has
IP, port, first/last seen, and malware family.

Docs: https://feodotracker.abuse.ch/blocklist/
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

import dlt

from batch.common import http_session, md_pipeline

log = logging.getLogger("ingest-feodo")

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


@dlt.resource(name="feodo_c2", write_disposition="replace")
def feodo_c2_resource() -> Iterator[dict]:
    log.info("fetching %s", FEODO_URL)
    resp = http_session().get(FEODO_URL, timeout=60)
    resp.raise_for_status()
    entries = resp.json()

    for entry in entries:
        yield {
            "ip_address": entry.get("ip_address"),
            "port": entry.get("port"),
            "status": entry.get("status"),
            "hostname": entry.get("hostname"),
            "as_number": entry.get("as_number"),
            "as_name": entry.get("as_name"),
            "country": entry.get("country"),
            "first_seen": entry.get("first_seen"),
            "last_online": entry.get("last_online"),
            "malware": entry.get("malware"),
        }


def run() -> dict:
    logging.basicConfig(level=logging.INFO)
    pipeline = md_pipeline("ingest_feodo")
    load_info = pipeline.run(feodo_c2_resource())
    log.info("loaded: %s", load_info)
    return load_info


if __name__ == "__main__":
    run()
