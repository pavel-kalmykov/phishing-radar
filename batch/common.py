"""Shared helpers for batch ingestion pipelines."""

from __future__ import annotations

import os
from typing import Any

import dlt

MD_DATABASE = os.getenv("MD_DATABASE", "main")


def md_pipeline(name: str) -> Any:
    """Build a dlt pipeline that writes to MotherDuck, database `phishing_radar`.

    dlt reads the MOTHERDUCK_TOKEN env var automatically for the motherduck destination.
    """
    return dlt.pipeline(
        pipeline_name=name,
        destination="motherduck",
        dataset_name=MD_DATABASE,
    )
