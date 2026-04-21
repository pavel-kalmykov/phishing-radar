"""Unit tests for the typosquatting detector.

The detector is the one piece of logic that can genuinely ship with bugs (the
ingestion and sink are mostly glue). These tests lock down a handful of known
impersonations plus a few legitimate domains that must never be flagged.
"""
from __future__ import annotations

import pytest

from streaming.flink.detectors import detect


@pytest.mark.parametrize(
    "domain,expected_brand,expected_reason",
    [
        # Rule 1: homoglyph substitution
        ("paypa1.com", "paypal", "homoglyph"),
        ("goog1e.com", "google", "homoglyph"),
        ("micr0soft.net", "microsoft", "homoglyph"),
        # Rule 2: brand embedded inside a label
        ("login-paypal-secure.example.net", "paypal", "brand_as_label"),
        ("microsoft-support.org", "microsoft", "brand_as_label"),
        ("amaz0n-login.net", "amazon", "brand_as_label"),
        # Rule 1: Unicode homoglyph (Cyrillic look-alikes)
        ("аpple.com", "apple", "homoglyph"),
        # Rule 3: Damerau-Levenshtein 1..2 (including transpositions as 1 edit)
        ("paypai.com", "paypal", "dlev_1"),
        ("paypla.com", "paypal", "dlev_1"),
        ("amzaon.com", "amazon", "dlev_1"),
    ],
)
def test_typosquatting_positives(domain: str, expected_brand: str, expected_reason: str) -> None:
    d = detect(domain)
    assert d is not None, f"{domain} should be flagged"
    assert d.brand == expected_brand, f"{domain} matched wrong brand {d.brand}"
    assert d.reason == expected_reason, f"{domain} matched wrong reason {d.reason}"


@pytest.mark.parametrize(
    "domain",
    [
        "google.com",
        "mail.google.com",
        "paypal.com",
        "amazon.co.uk",
        "github.com",
        "example.org",
        "arandomdomain.net",
    ],
)
def test_legitimate_domains_are_not_flagged(domain: str) -> None:
    assert detect(domain) is None, f"{domain} was incorrectly flagged"


def test_detect_handles_wildcard_prefix() -> None:
    # CertStream publishes wildcard SAN entries; our detector must strip the `*.`
    assert detect("*.google.com") is None


def test_detect_ignores_empty_input() -> None:
    assert detect("") is None
    assert detect(".") is None
