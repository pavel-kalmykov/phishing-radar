"""abuse.ch ThreatFox IoCs -> MotherDuck.

Community-driven IoC feed. We keep only rows tagged as botnet C2 so the
resulting table plays the same role as Feodo Tracker but with broader
malware family coverage (Vidar, Cobalt Strike, ValleyRAT, Remcos...).

ThreatFox gives us ip:port, domain and url IoCs. For the map we care only
about ip:port entries; domain and url entries are kept with ip_address=null
so downstream marts can decide what to do.

Docs: https://threatfox.abuse.ch/api/
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

import dlt
import requests

from batch.common import md_pipeline

log = logging.getLogger("ingest-threatfox")

THREATFOX_URL = "https://threatfox.abuse.ch/export/json/recent/"


def _split_ip_port(value: str) -> tuple[str | None, int | None]:
    if ":" not in value:
        return None, None
    ip, _, port = value.rpartition(":")
    try:
        return ip, int(port)
    except ValueError:
        return ip, None


@dlt.resource(name="threatfox_iocs", write_disposition="replace")
def threatfox_iocs() -> Iterator[dict]:
    log.info("fetching %s", THREATFOX_URL)
    resp = requests.get(THREATFOX_URL, timeout=120)
    resp.raise_for_status()
    payload = resp.json()

    for _, entries in payload.items():
        entry = entries[0] if isinstance(entries, list) else entries
        if entry.get("threat_type") != "botnet_cc":
            continue

        ioc_type = entry.get("ioc_type")
        ioc_value = entry.get("ioc_value") or ""
        ip, port = (None, None)
        if ioc_type == "ip:port":
            ip, port = _split_ip_port(ioc_value)

        yield {
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "ip_address": ip,
            "port": port,
            "malware": entry.get("malware_printable") or entry.get("malware"),
            "malware_alias": entry.get("malware_alias"),
            "threat_type": entry.get("threat_type"),
            "confidence_level": entry.get("confidence_level"),
            "first_seen_utc": entry.get("first_seen_utc"),
            "last_seen_utc": entry.get("last_seen_utc"),
            "tags": entry.get("tags"),
            "reporter": entry.get("reporter"),
        }


def run() -> dict:
    logging.basicConfig(level=logging.INFO)
    pipeline = md_pipeline("ingest_threatfox")
    load_info = pipeline.run(threatfox_iocs())
    log.info("loaded: %s", load_info)
    return load_info


if __name__ == "__main__":
    run()
