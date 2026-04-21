"""MaxMind GeoLite2 -> MotherDuck country/ASN dim tables.

Downloads the GeoLite2-ASN and GeoLite2-Country CSV zips and loads them as
lookup tables in MotherDuck. If the paid MMDB editions are available on the
account, also caches a local .mmdb for in-process IP lookups; otherwise
falls back to CSV-only.

Requires MAXMIND_LICENSE_KEY env var (plus MOTHERDUCK_TOKEN for dlt).
"""
from __future__ import annotations

import csv
import io
import logging
import os
import zipfile
from pathlib import Path
from typing import Iterator

import dlt
import requests

from batch.common import md_pipeline

log = logging.getLogger("ingest-maxmind")

BASE_URL = "https://download.maxmind.com/app/geoip_download"
EDITIONS_CSV = {
    "asn": "GeoLite2-ASN-CSV",
    "country": "GeoLite2-Country-CSV",
}
EDITIONS_MMDB = {
    "asn": "GeoLite2-ASN",
    "country": "GeoLite2-Country",
}


def _download_zip(edition: str) -> bytes:
    license_key = os.environ["MAXMIND_LICENSE_KEY"]
    url = f"{BASE_URL}?edition_id={edition}&license_key={license_key}&suffix=zip"
    log.info("fetching %s", edition)
    resp = requests.get(url, timeout=300)
    resp.raise_for_status()
    return resp.content


def _iter_csv(content: bytes, filename_suffix: str) -> Iterator[dict]:
    with zipfile.ZipFile(io.BytesIO(content)) as zf:
        target = next((n for n in zf.namelist() if n.endswith(filename_suffix)), None)
        if not target:
            raise FileNotFoundError(f"no {filename_suffix} in zip (files: {zf.namelist()})")
        with zf.open(target) as fh:
            reader = csv.DictReader(io.TextIOWrapper(fh, "utf-8"))
            yield from reader


def _save_mmdb(edition: str, target_dir: Path) -> None:
    content = _download_zip(EDITIONS_MMDB[edition])
    target_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(content)) as zf:
        target = next((n for n in zf.namelist() if n.endswith(".mmdb")), None)
        if not target:
            raise FileNotFoundError("no .mmdb in zip")
        out = target_dir / Path(target).name
        out.write_bytes(zf.read(target))
        log.info("saved %s", out)


@dlt.resource(name="geoip_asn_blocks", write_disposition="replace")
def asn_blocks() -> Iterator[dict]:
    content = _download_zip(EDITIONS_CSV["asn"])
    for row in _iter_csv(content, "GeoLite2-ASN-Blocks-IPv4.csv"):
        yield {
            "network": row["network"],
            "autonomous_system_number": int(row["autonomous_system_number"]) if row["autonomous_system_number"] else None,
            "autonomous_system_organization": row["autonomous_system_organization"],
        }


@dlt.resource(name="geoip_country_blocks", write_disposition="replace")
def country_blocks() -> Iterator[dict]:
    content = _download_zip(EDITIONS_CSV["country"])
    for row in _iter_csv(content, "GeoLite2-Country-Blocks-IPv4.csv"):
        yield {
            "network": row["network"],
            "geoname_id": int(row["geoname_id"]) if row["geoname_id"] else None,
            "registered_country_geoname_id": int(row["registered_country_geoname_id"]) if row["registered_country_geoname_id"] else None,
            "represented_country_geoname_id": int(row["represented_country_geoname_id"]) if row["represented_country_geoname_id"] else None,
            "is_anonymous_proxy": row["is_anonymous_proxy"] == "1",
            "is_satellite_provider": row["is_satellite_provider"] == "1",
        }


@dlt.resource(name="geoip_country_locations", write_disposition="replace")
def country_locations() -> Iterator[dict]:
    content = _download_zip(EDITIONS_CSV["country"])
    for row in _iter_csv(content, "GeoLite2-Country-Locations-en.csv"):
        yield {
            "geoname_id": int(row["geoname_id"]),
            "locale_code": row["locale_code"],
            "continent_code": row["continent_code"],
            "continent_name": row["continent_name"],
            "country_iso_code": row["country_iso_code"],
            "country_name": row["country_name"],
            "is_in_european_union": row["is_in_european_union"] == "1",
        }


def run(mmdb_dir: str = "data/geoip") -> dict:
    logging.basicConfig(level=logging.INFO)

    # MMDB download requires a paid product tier; the free GeoLite2 account
    # only gets CSV. Skip gracefully if the MMDB 404s so the CSV load still runs.
    for edition in ("asn", "country"):
        try:
            _save_mmdb(edition, Path(mmdb_dir))
        except requests.exceptions.HTTPError as e:
            log.warning("MMDB download for %s unavailable (%s); using CSV only", edition, e)

    pipeline = md_pipeline("ingest_maxmind")
    load_info = pipeline.run([asn_blocks(), country_blocks(), country_locations()])
    log.info("loaded: %s", load_info)
    return load_info


if __name__ == "__main__":
    run()
