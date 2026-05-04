"""Shared helpers for batch ingestion pipelines."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import dlt
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

MD_DATABASE = os.getenv("MD_DATABASE", "main")
DATABASE_URL = os.getenv("DATABASE_URL", "")


def build_pipeline(name: str) -> Any:
    """Build a dlt pipeline that writes to the configured destination.

    When DATABASE_URL is set (local DuckDB), uses the duckdb destination.
    Otherwise writes to MotherDuck (reads MOTHERDUCK_TOKEN from env).
    """
    if DATABASE_URL:
        db_path = Path(DATABASE_URL)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        return dlt.pipeline(
            pipeline_name=name,
            destination=dlt.destinations.duckdb(str(db_path)),
            dataset_name=MD_DATABASE,
        )
    return dlt.pipeline(
        pipeline_name=name,
        destination="motherduck",
        dataset_name=MD_DATABASE,
    )


def http_session(total_retries: int = 5, backoff_factor: float = 0.5) -> requests.Session:
    """Build a requests Session with exponential-backoff retries.

    Retries on 429 / 5xx responses and on connection / read errors. With the
    defaults a fully-failed call takes total_retries=5 attempts spaced
    0.5, 1, 2, 4, 8 seconds, which is short enough for a Kestra task
    SLA and long enough to ride out a transient CISA / abuse.ch 503.
    """
    retry = Retry(
        total=total_retries,
        connect=total_retries,
        read=total_retries,
        status=total_retries,
        backoff_factor=backoff_factor,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("HEAD", "GET", "OPTIONS"),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session
