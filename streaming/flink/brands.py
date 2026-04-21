"""Popular brands (and their canonical domains) that phishers impersonate the most.

Source: a distillation from anti-phishing reports (APWG, PhishLabs). Keep it short
and high-signal; we match on the second-level domain label so adding every
possible brand is not necessary, and it keeps Levenshtein false positives low.
"""
from __future__ import annotations

# Mapping: canonical second-level label -> brand category
POPULAR_BRANDS: dict[str, str] = {
    "google": "internet",
    "amazon": "ecommerce",
    "paypal": "finance",
    "microsoft": "tech",
    "office365": "tech",
    "outlook": "tech",
    "apple": "tech",
    "netflix": "media",
    "facebook": "social",
    "instagram": "social",
    "whatsapp": "social",
    "linkedin": "social",
    "github": "tech",
    "dropbox": "tech",
    "adobe": "tech",
    "docusign": "tech",
    "wellsfargo": "finance",
    "chase": "finance",
    "hsbc": "finance",
    "santander": "finance",
    "bbva": "finance",
    "caixabank": "finance",
    "binance": "crypto",
    "coinbase": "crypto",
    "metamask": "crypto",
    "dhl": "logistics",
    "fedex": "logistics",
    "ups": "logistics",
    "correos": "logistics",
    "usps": "logistics",
    "ebay": "ecommerce",
    "aliexpress": "ecommerce",
    "shopify": "ecommerce",
    "walmart": "ecommerce",
    "booking": "travel",
    "airbnb": "travel",
    "spotify": "media",
    "twitch": "media",
    "steam": "gaming",
    "epicgames": "gaming",
    "discord": "gaming",
    "telegram": "social",
    "zoom": "tech",
}
