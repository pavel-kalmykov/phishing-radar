"""MITRE ATT&CK STIX bundle -> BigQuery.

Loads the Enterprise matrix: tactics, techniques, software (malware + tools),
and groups (APTs). Used to annotate streaming detections with threat actor
and technique context.

Docs: https://github.com/mitre/cti
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

import dlt
import requests

from batch.common import md_pipeline

log = logging.getLogger("ingest-mitre")

ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def _external_id(obj: dict, source: str = "mitre-attack") -> str | None:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == source:
            return ref.get("external_id")
    return None


def _get_kill_chain(obj: dict) -> list[str]:
    return [kc.get("phase_name") for kc in obj.get("kill_chain_phases", []) or [] if kc.get("phase_name")]


@dlt.source(name="mitre_attack")
def mitre_attack_source() -> Iterator:
    log.info("fetching %s", ATTACK_URL)
    resp = requests.get(ATTACK_URL, timeout=120)
    resp.raise_for_status()
    bundle = resp.json()
    objects = bundle.get("objects", [])

    @dlt.resource(name="mitre_techniques", write_disposition="replace", primary_key="id")
    def techniques() -> Iterator[dict]:
        for o in objects:
            if o.get("type") == "attack-pattern":
                yield {
                    "id": o["id"],
                    "attack_id": _external_id(o),
                    "name": o.get("name"),
                    "description": o.get("description"),
                    "kill_chain_phases": _get_kill_chain(o),
                    "platforms": o.get("x_mitre_platforms") or [],
                    "data_sources": o.get("x_mitre_data_sources") or [],
                    "is_subtechnique": o.get("x_mitre_is_subtechnique", False),
                    "revoked": o.get("revoked", False),
                }

    @dlt.resource(name="mitre_software", write_disposition="replace", primary_key="id")
    def software() -> Iterator[dict]:
        for o in objects:
            if o.get("type") in ("malware", "tool"):
                yield {
                    "id": o["id"],
                    "attack_id": _external_id(o),
                    "type": o.get("type"),
                    "name": o.get("name"),
                    "description": o.get("description"),
                    "platforms": o.get("x_mitre_platforms") or [],
                    "aliases": o.get("x_mitre_aliases") or [],
                    "is_family": o.get("is_family", False),
                    "revoked": o.get("revoked", False),
                }

    @dlt.resource(name="mitre_groups", write_disposition="replace", primary_key="id")
    def groups() -> Iterator[dict]:
        for o in objects:
            if o.get("type") == "intrusion-set":
                yield {
                    "id": o["id"],
                    "attack_id": _external_id(o),
                    "name": o.get("name"),
                    "aliases": o.get("aliases") or [],
                    "description": o.get("description"),
                    "revoked": o.get("revoked", False),
                }

    return [techniques(), software(), groups()]


def run() -> dict:
    logging.basicConfig(level=logging.INFO)
    pipeline = md_pipeline("ingest_mitre")
    load_info = pipeline.run(mitre_attack_source())
    log.info("loaded: %s", load_info)
    return load_info


if __name__ == "__main__":
    run()
