"""Typosquatting detection heuristics.

Given a domain, decide if it looks like a phishing impersonation of a known brand.
Three signals, from cheapest to most specific:

1. Exact brand substring in a non-canonical position (e.g. `paypal-login.com`).
2. Levenshtein distance <= 2 against a brand label, on the second-level domain.
3. Homoglyph substitution (1 -> l, 0 -> o) normalized before comparison.

Returns the matched brand and the reason, or None. Kept pure so Flink / dbt /
pytest can all call it.
"""
from __future__ import annotations

from dataclasses import dataclass

from rapidfuzz.distance import Levenshtein

from .brands import POPULAR_BRANDS

# Canonical domains we never flag against themselves
CANONICAL_DOMAINS: frozenset[str] = frozenset({
    f"{b}.com" for b in POPULAR_BRANDS
} | {
    "microsoft.com", "live.com", "office.com", "outlook.com", "office365.com",
    "paypal.com", "paypal.me", "google.com", "googlemail.com", "gmail.com",
    "amazon.com", "amazon.co.uk", "amazon.de", "amazon.es", "amazon.fr",
    "apple.com", "icloud.com", "facebook.com", "fb.com", "instagram.com",
    "github.com", "github.io", "githubusercontent.com",
})

HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "5": "s", "3": "e", "4": "a"})


@dataclass(frozen=True)
class Detection:
    brand: str
    category: str
    reason: str
    score: int  # 1 (weak) to 3 (strong)


def _second_level(domain: str) -> str:
    """mail.google.com -> google"""
    domain = domain.lower().lstrip("*.").strip(".")
    parts = domain.split(".")
    return parts[-2] if len(parts) >= 2 else domain


def _is_canonical(domain: str) -> bool:
    domain = domain.lower().lstrip("*.").strip(".")
    return any(domain == c or domain.endswith("." + c) for c in CANONICAL_DOMAINS)


def detect(domain: str) -> Detection | None:
    if not domain or _is_canonical(domain):
        return None

    sld = _second_level(domain)
    if not sld:
        return None

    sld_norm = sld.translate(HOMOGLYPHS)
    full_norm = domain.lower().translate(HOMOGLYPHS)

    for brand, category in POPULAR_BRANDS.items():
        if sld == brand:
            continue  # exact match to brand label alone is treated as canonical

        # Rule 1: brand appears as a full label in the hostname (not as TLD/SLD match)
        labels = [lbl for lbl in full_norm.split(".") if lbl]
        if brand in labels and labels[-2:-1] != [brand]:
            return Detection(brand, category, "brand_as_label", score=3)

        # Rule 2: Levenshtein distance 1..2 on SLD
        if 1 <= len(sld) <= 30 and sld != brand:
            dist = Levenshtein.distance(sld_norm, brand, score_cutoff=2)
            if 1 <= dist <= 2:
                return Detection(brand, category, f"lev_{dist}", score=3 - dist + 1)

        # Rule 3: brand appears as a substring of SLD (paypal-security)
        if brand in sld_norm and brand != sld_norm:
            return Detection(brand, category, "brand_substring", score=2)

    return None
