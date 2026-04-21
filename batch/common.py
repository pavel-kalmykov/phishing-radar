"""Shared helpers for batch ingestion pipelines."""
from __future__ import annotations

import os
from typing import Any

import dlt

BQ_DATASET = os.getenv("BQ_DATASET", "phishing_radar")


def bigquery_pipeline(name: str) -> Any:
    """Build a dlt pipeline that writes to BigQuery, dataset phishing_radar."""
    return dlt.pipeline(
        pipeline_name=name,
        destination="bigquery",
        dataset_name=BQ_DATASET,
    )
