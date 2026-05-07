"""Typosquatting detection heuristics.

Given a domain, decide if it looks like a phishing impersonation of a known brand.
Four rules, from strongest to weakest:

1. Homoglyph substitution (`paypa1.com`, `goog1e.com`): the second-level domain
   equals a brand after we normalise digits that are visually similar to letters
   (`1 -> l`, `0 -> o`, `5 -> s`, etc.). Score 3.
2. Brand appears as a substring of a hostname label other than the TLD
   (`login-paypal-secure.example.net`, `microsoft-support.org`). Score 2.
3. Levenshtein distance 1..2 between the second-level domain and a brand, after
   homoglyph normalisation (`paypa-l.com`, `amaz0n.com`). Score 3 - dist + 1.

Returns the matched brand + reason, or None. Pure function: the Flink/Python
detector job, dbt, and pytest all call it.
"""
from __future__ import annotations

from dataclasses import dataclass

from rapidfuzz.distance import Levenshtein

from .brands import POPULAR_BRANDS

# Canonical domains never flagged against themselves
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


def _labels_without_tld(domain: str) -> list[str]:
    """Strip the TLD (last label). `login-paypal.example.net` -> `[login-paypal, example]`."""
    domain = domain.lower().lstrip("*.").strip(".")
    parts = [p for p in domain.split(".") if p]
    return parts[:-1] if len(parts) >= 2 else parts


def detect(domain: str) -> Detection | None:
    if not domain:
        return None
    if _is_canonical(domain):
        return None

    sld = _second_level(domain)
    if not sld:
        return None

    sld_norm = sld.translate(HOMOGLYPHS)
    labels = _labels_without_tld(domain)
    labels_norm = [label.translate(HOMOGLYPHS) for label in labels]

    for brand, category in POPULAR_BRANDS.items():
        # The domain is exactly the brand on its own SLD: leave it alone.
        if sld == brand:
            continue

        # Rule 1: homoglyph attack. The raw SLD looks like the brand once digits
        # are normalised. Covers paypa1, goog1e, micr0soft, etc.
        if sld_norm == brand and sld != brand:
            return Detection(brand, category, "homoglyph", score=3)

        # Rule 2: brand appears as a substring of any hostname label (other than
        # the TLD). Catches login-paypal-secure.example.net, microsoft-support.org
        # and amaz0n-login.net (because amaz0n normalises to amazon).
        for lbl in labels_norm:
            if brand != lbl and brand in lbl:
                return Detection(brand, category, "brand_as_label", score=2)

        # Rule 3: fuzzy match on the SLD itself (handles single-letter typos like
        # paypa-l, amzaon, etc.).
        if 3 <= len(sld_norm) <= 30:
            dist = Levenshtein.distance(sld_norm, brand, score_cutoff=2)
            if 1 <= dist <= 2:
                return Detection(brand, category, f"lev_{dist}", score=3 - dist + 1)

    return None
