"""Unit tests for batch ingesters.

Covers two layers:

1. **Parsing**: each ingester's resource function is invoked with a mocked
   HTTP response and the yielded rows are checked against fixtures.
2. **Retry/backoff**: `batch.common.http_session()` retries 5xx responses
   with the configured backoff factor. We assert the underlying urllib3
   adapter is wired up correctly without making real network calls.
"""

from __future__ import annotations

import json
from unittest.mock import patch

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from batch import (
    ingest_cisa_kev,
    ingest_feodo,
    ingest_mitre,
    ingest_spamhaus,
    ingest_threatfox,
)
from batch.common import http_session


class _FakeResponse:
    def __init__(self, payload: object, text: str | None = None, status: int = 200):
        self._payload = payload
        self.text = text or ""
        self.status_code = status

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self) -> object:
        return self._payload

    @property
    def content(self) -> bytes:
        return json.dumps(self._payload).encode()


# ---------- http_session ----------


def test_http_session_returns_configured_session() -> None:
    s = http_session(total_retries=3, backoff_factor=0.25)
    https_adapter = s.adapters["https://"]
    http_adapter = s.adapters["http://"]
    assert isinstance(https_adapter, HTTPAdapter)
    assert https_adapter is http_adapter

    retry = https_adapter.max_retries
    assert isinstance(retry, Retry)
    assert retry.total == 3
    assert retry.backoff_factor == 0.25
    assert 503 in retry.status_forcelist
    assert 429 in retry.status_forcelist
    assert "GET" in (retry.allowed_methods or set())


# ---------- CISA KEV ----------


def test_cisa_kev_parses_catalog() -> None:
    fake = _FakeResponse(
        {
            "catalogVersion": "2026.04.27",
            "dateReleased": "2026-04-27",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-1111",
                    "vendorProject": "Acme",
                    "product": "Widget",
                    "vulnerabilityName": "Buffer overflow",
                    "dateAdded": "2026-04-26",
                    "shortDescription": "Trivial",
                    "requiredAction": "Patch",
                    "dueDate": "2026-05-26",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "",
                    "cwes": ["CWE-119"],
                }
            ],
        }
    )
    with patch("batch.ingest_cisa_kev.http_session") as session:
        session.return_value.get.return_value = fake
        rows = list(ingest_cisa_kev.cisa_kev_resource())

    assert len(rows) == 1
    row = rows[0]
    assert row["cve_id"] == "CVE-2026-1111"
    assert row["vendor"] == "Acme"
    assert row["known_ransomware_use"] == "Known"
    assert row["catalog_version"] == "2026.04.27"


# ---------- Feodo ----------


def test_feodo_parses_blocklist() -> None:
    fake = _FakeResponse(
        [
            {
                "ip_address": "1.2.3.4",
                "port": 443,
                "status": "online",
                "hostname": None,
                "as_number": 64500,
                "as_name": "EXAMPLE-AS",
                "country": "US",
                "first_seen": "2026-04-01 00:00:00",
                "last_online": "2026-04-27 12:00:00",
                "malware": "QBot",
            }
        ]
    )
    with patch("batch.ingest_feodo.http_session") as session:
        session.return_value.get.return_value = fake
        rows = list(ingest_feodo.feodo_c2_resource())

    assert len(rows) == 1
    assert rows[0]["ip_address"] == "1.2.3.4"
    assert rows[0]["malware"] == "QBot"


# ---------- ThreatFox ----------


def test_threatfox_keeps_only_botnet_cc_and_splits_ip_port() -> None:
    fake = _FakeResponse(
        {
            "1": [
                {
                    "ioc_type": "ip:port",
                    "ioc_value": "5.6.7.8:8080",
                    "malware_printable": "Vidar",
                    "malware_alias": "vidar_stealer",
                    "threat_type": "botnet_cc",
                    "confidence_level": 75,
                    "first_seen_utc": "2026-04-26 00:00:00",
                    "last_seen_utc": "2026-04-27 00:00:00",
                    "tags": ["stealer"],
                    "reporter": "abuse.ch",
                }
            ],
            "2": [
                {
                    "ioc_type": "url",
                    "ioc_value": "http://benign.test",
                    "threat_type": "payload_delivery",  # filtered out
                }
            ],
        }
    )
    with patch("batch.ingest_threatfox.http_session") as session:
        session.return_value.get.return_value = fake
        rows = list(ingest_threatfox.threatfox_iocs())

    assert len(rows) == 1
    assert rows[0]["ip_address"] == "5.6.7.8"
    assert rows[0]["port"] == 8080
    assert rows[0]["malware"] == "Vidar"


def test_threatfox_split_ip_port_handles_garbage() -> None:
    assert ingest_threatfox._split_ip_port("not-an-ip") == (None, None)
    assert ingest_threatfox._split_ip_port("1.2.3.4:not_a_port") == ("1.2.3.4", None)


# ---------- Spamhaus ----------


def test_spamhaus_parses_drop_format() -> None:
    text = """
; Spamhaus DROP list 2026-04-27
1.2.0.0/16 ; SBL12345
2.3.4.0/24 ; SBL67890

malformed line
""".strip()

    fake = _FakeResponse(payload={}, text=text)
    with patch("batch.ingest_spamhaus.http_session") as session:
        session.return_value.get.return_value = fake
        rows = list(ingest_spamhaus.spamhaus_drop_resource())

    # Two URLs (drop + edrop), each returns the same fake => 4 rows.
    assert len(rows) == 4
    assert {r["cidr"] for r in rows} == {"1.2.0.0/16", "2.3.4.0/24"}
    assert {r["sbl_ref"] for r in rows} == {"SBL12345", "SBL67890"}
    assert {r["list"] for r in rows} == {"drop", "edrop"}


# ---------- MITRE ----------


def test_mitre_partitions_objects_into_three_resources() -> None:
    fake = _FakeResponse(
        {
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--1",
                    "name": "Spearphishing",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "T1566"}],
                    "kill_chain_phases": [{"phase_name": "initial-access"}],
                    "x_mitre_platforms": ["Linux"],
                },
                {
                    "type": "malware",
                    "id": "malware--1",
                    "name": "QBot",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "S1000"}],
                },
                {
                    "type": "intrusion-set",
                    "id": "intrusion-set--1",
                    "name": "APT99",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "G9999"}],
                    "aliases": ["Group99"],
                },
                {"type": "x-mitre-tactic", "id": "tactic--1"},  # ignored
            ]
        }
    )
    with patch("batch.ingest_mitre.http_session") as session:
        session.return_value.get.return_value = fake
        techniques, software, groups = ingest_mitre.mitre_attack_source().resources.values()
        tech_rows = list(techniques)
        soft_rows = list(software)
        grp_rows = list(groups)

    assert tech_rows[0]["attack_id"] == "T1566"
    assert tech_rows[0]["kill_chain_phases"] == ["initial-access"]
    assert soft_rows[0]["attack_id"] == "S1000"
    assert grp_rows[0]["attack_id"] == "G9999"
