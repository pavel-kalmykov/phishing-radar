"""Typosquatting detection heuristics.

Given a domain, decide if it looks like a phishing impersonation of a known brand.
Four rules, from strongest to weakest:

1. Homoglyph substitution (`paypa1.com`, `goog1e.com`, `аpple.com`): the
   second-level domain equals a brand after we normalise digits and Unicode
   confusables (Cyrillic look-alikes) to their ASCII counterparts. Score 3.
2. Brand appears as a substring of a hostname label other than the TLD
   (`login-paypal-secure.example.net`, `microsoft-support.org`). Score 2.
3. Damerau-Levenshtein distance 1..2 between the second-level domain and a
   brand, after normalisation. Covers single-char edits plus transpositions
   (`paypla`, `amzaon`). Score 3 - dist + 1.
4. Jaro-Winkler similarity >= 0.92 on the normalised SLD. Weak signal,
   favours prefix-preserving attacks (`paypal-support`, `amazon-eu`). Score 1.

Returns the matched brand + reason, or None. Pure function: the Flink/Python
detector job, dbt, and pytest all call it.

See docs/detection_alternatives.md for the rationale behind this mix (and why
MinHash, n-gram Jaccard and friends live elsewhere).
"""

from __future__ import annotations

from dataclasses import dataclass

from rapidfuzz.distance import DamerauLevenshtein, JaroWinkler

from .brands import POPULAR_BRANDS

# Canonical domains never flagged against themselves
CANONICAL_DOMAINS: frozenset[str] = frozenset(
    {f"{b}.com" for b in POPULAR_BRANDS}
    | {
        "microsoft.com",
        "live.com",
        "office.com",
        "outlook.com",
        "office365.com",
        "paypal.com",
        "paypal.me",
        "google.com",
        "googlemail.com",
        "gmail.com",
        "amazon.com",
        "amazon.co.uk",
        "amazon.de",
        "amazon.es",
        "amazon.fr",
        "apple.com",
        "icloud.com",
        "facebook.com",
        "fb.com",
        "instagram.com",
        "github.com",
        "github.io",
        "githubusercontent.com",
    }
)

# Digit-to-letter confusables plus Cyrillic look-alikes that commonly show up
# in IDN phishing (`аpple.com`, `gооgle.com`, `раypal.com`).
HOMOGLYPHS = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "5": "s",
        "3": "e",
        "4": "a",
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ѕ": "s",
        "ӏ": "l",
    }
)

JARO_WINKLER_THRESHOLD = 0.92
JW_MIN_LEN = 8


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

        # Rule 3: Damerau-Levenshtein on the SLD. Catches single-char edits plus
        # transpositions as one edit (paypla, amzaon), which plain Levenshtein
        # would score as 2.
        if 3 <= len(sld_norm) <= 30:
            dist = DamerauLevenshtein.distance(sld_norm, brand, score_cutoff=2)
            if 1 <= dist <= 2:
                return Detection(brand, category, f"dlev_{dist}", score=3 - dist + 1)

        # Rule 4: Jaro-Winkler rewards common prefixes, catching attacks that
        # keep the brand as a prefix and append noise. Deliberately weak.
        if len(sld_norm) >= JW_MIN_LEN:
            sim = JaroWinkler.similarity(sld_norm, brand)
            if sim >= JARO_WINKLER_THRESHOLD:
                return Detection(brand, category, "jaro_winkler", score=1)

    return None
