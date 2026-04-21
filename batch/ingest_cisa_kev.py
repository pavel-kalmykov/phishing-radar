"""CISA Known Exploited Vulnerabilities catalog -> BigQuery.

CISA publishes a daily catalog of CVEs that are actively exploited in the wild.
This is the operational subset of NVD: if a CVE is here, attackers are using it
right now. ~1600 entries as of April 2026.

Docs: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""
from __future__ import annotations

import logging
from collections.abc import Iterator

import dlt
import requests

from batch.common import md_pipeline

log = logging.getLogger("ingest-cisa-kev")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dlt.resource(name="cisa_kev", write_disposition="replace", primary_key="cve_id")
def cisa_kev_resource() -> Iterator[dict]:
    log.info("fetching %s", CISA_KEV_URL)
    resp = requests.get(CISA_KEV_URL, timeout=60)
    resp.raise_for_status()
    payload = resp.json()

    catalog_version = payload.get("catalogVersion")
    date_released = payload.get("dateReleased")

    for vuln in payload.get("vulnerabilities", []):
        yield {
            "cve_id": vuln.get("cveID"),
            "vendor": vuln.get("vendorProject"),
            "product": vuln.get("product"),
            "name": vuln.get("vulnerabilityName"),
            "date_added": vuln.get("dateAdded"),
            "description": vuln.get("shortDescription"),
            "required_action": vuln.get("requiredAction"),
            "due_date": vuln.get("dueDate"),
            "known_ransomware_use": vuln.get("knownRansomwareCampaignUse"),
            "notes": vuln.get("notes"),
            "cwes": vuln.get("cwes") or [],
            "catalog_version": catalog_version,
            "date_released": date_released,
        }


def run() -> dict:
    logging.basicConfig(level=logging.INFO)
    pipeline = md_pipeline("ingest_cisa_kev")
    load_info = pipeline.run(cisa_kev_resource())
    log.info("loaded: %s", load_info)
    return load_info


if __name__ == "__main__":
    run()
