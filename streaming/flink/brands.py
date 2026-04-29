"""Brand list loader for typosquatting detection.

The list itself lives in `brands.yaml`. Loading is cached so the YAML is read
once at process start. Path is overridable via STREAMING_BRAND_LIST_PATH for
local experiments and for shipping a different list per environment without
editing code.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import yaml

DEFAULT_BRAND_LIST_PATH = Path(__file__).parent / "brands.yaml"


@lru_cache(maxsize=1)
def load_brands() -> dict[str, str]:
    """Read the configured brand list from disk and return name -> category."""
    path = Path(os.getenv("STREAMING_BRAND_LIST_PATH", str(DEFAULT_BRAND_LIST_PATH)))
    with path.open() as fh:
        data = yaml.safe_load(fh) or {}
    brands = data.get("brands") or {}
    if not isinstance(brands, dict):
        raise ValueError(f"{path}: 'brands' must be a mapping of <name>: <category>")
    return brands


# Module-level constant kept for the existing import sites in detectors.py and
# the python_detector / phishing_detector entry points.
POPULAR_BRANDS: dict[str, str] = load_brands()
