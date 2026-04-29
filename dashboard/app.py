"""Phishing Radar dashboard.

Operational view over MotherDuck. Uses st.tabs so navigation can never
collapse into invisibility, renders every block inside a card panel, reads
from pre-aggregated dbt marts, and exposes a sticky filter bar so every
widget responds to the same slice of time, brand and CA.

See docs/detection_alternatives.md for the rationale behind the detector's
similarity rules.
"""

from __future__ import annotations

import hashlib
import os
from datetime import date, datetime, timedelta
from typing import Any

import duckdb
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

MD_CATALOG = os.getenv("MD_CATALOG", "phishing_radar")
MD_DATABASE = os.getenv("MD_DATABASE", "main")

st.set_page_config(
    page_title="Phishing Radar",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# =============================================================================
# DATA LAYER
# =============================================================================


@st.cache_resource
def get_conn() -> duckdb.DuckDBPyConnection:
    token = os.getenv("MOTHERDUCK_TOKEN")
    if not token:
        try:
            token = st.secrets["MOTHERDUCK_TOKEN"]
        except Exception as e:
            raise RuntimeError("MOTHERDUCK_TOKEN not set in env or Streamlit secrets") from e
    return duckdb.connect(f"md:{MD_CATALOG}?motherduck_token={token}")


def run_query(sql: str, params: tuple | None = None) -> pd.DataFrame:
    """Plain executor. Caching is the caller's responsibility because TTL
    depends on what the query reads (streaming vs batch vs filter list)."""
    if params:
        return get_conn().execute(sql, params).df()
    return get_conn().execute(sql).df()


# Cache TTL tiers so refreshes match the cadence of the underlying data:
LIVE_TTL = 60  # streaming-derived widgets (KPIs, suspicious_certs slices)
BATCH_TTL = 300  # slower-moving aggregates (KEV, Spamhaus, C2 marts)
FILTER_TTL = 600  # filter dropdowns (brand list, top issuers)


# =============================================================================
# STYLE
# =============================================================================
#
# Cyberpunk-leaning dark palette. Intentionally diverges from the previous
# capstone's GitHub-flavoured grey/blue palette: deep violets, hot pink,
# electric cyan.

BG = "#0a0a14"
BG_CARD = "#141229"
BG_RAISED = "#1e1b3f"
BORDER = "#2c2858"
TEXT = "#e8e6ff"
TEXT_MUTED = "#9b99c9"
TEXT_DIM = "#6b6890"

ACCENT_PINK = "#ff3d71"
ACCENT_CYAN = "#00e5ff"
ACCENT_GOLD = "#ffb800"
ACCENT_VIOLET = "#7c4dff"
ACCENT_GREEN = "#00ffa3"

st.markdown(
    f"""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@500;700&display=swap');

  header[data-testid="stHeader"] {{ display: none; }}
  [data-testid="stSidebar"] {{ display: none; }}
  [data-testid="collapsedControl"] {{ display: none; }}
  [data-testid="stApp"] {{ background:
      radial-gradient(circle at 0% 0%, rgba(124,77,255,0.08), transparent 40%),
      radial-gradient(circle at 100% 0%, rgba(255,61,113,0.06), transparent 45%),
      {BG};
  }}
  html, body, [data-testid="stApp"] {{ font-family: 'Space Grotesk', sans-serif; color: {TEXT}; }}
  .block-container {{ padding: 1.6rem 2rem 2.6rem !important; max-width: 1320px !important; }}

  h1, h2, h3 {{ font-family: 'Space Grotesk', sans-serif; letter-spacing: -0.02em; }}
  h1 {{ font-weight: 700 !important; font-size: 2.3rem !important; margin: 0 0 0.25rem 0 !important;
       background: linear-gradient(90deg, {ACCENT_PINK}, {ACCENT_VIOLET}, {ACCENT_CYAN});
       -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
  h2 {{ font-weight: 600 !important; font-size: 1.3rem !important; margin: 1.6rem 0 0.6rem 0 !important; }}

  p, li {{ color: {TEXT_MUTED}; font-size: 0.95rem; line-height: 1.55; }}
  a {{ color: {ACCENT_CYAN}; text-decoration: none; border-bottom: 1px dotted {ACCENT_CYAN}; }}

  abbr[title] {{
    text-decoration: none;
    border-bottom: 1px dashed {ACCENT_VIOLET};
    cursor: help; color: {TEXT};
  }}

  .subtitle {{ color: {TEXT_MUTED}; font-size: 0.98rem; margin: 0 0 1.3rem 0; }}
  .intro {{ color: {TEXT_MUTED}; font-size: 0.98rem; margin: 0 0 1.6rem 0; line-height: 1.6; }}

  .kpi-grid {{
    display: grid; gap: 0.75rem; margin: 0.6rem 0 1.2rem 0;
    grid-template-columns: repeat(6, 1fr);
  }}
  /* Responsive KPI grid: 6 cols on desktop, 3 on tablet, 2 on phone. */
  @media (max-width: 980px) {{
    .kpi-grid {{ grid-template-columns: repeat(3, 1fr); }}
  }}
  @media (max-width: 560px) {{
    .kpi-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .block-container {{ padding: 1rem !important; }}
    .kpi .value {{ font-size: 1.35rem !important; }}
    .footer {{ flex-direction: column; }}
  }}
  .kpi {{
    background: {BG_CARD}; border: 1px solid {BORDER}; border-radius: 10px;
    padding: 0.95rem 1rem; position: relative; overflow: hidden;
    cursor: help;
  }}
  .kpi .label {{
    border-bottom: 1px dashed {BORDER};
    padding-bottom: 0.15rem; width: fit-content;
  }}
  .kpi:hover .label {{ border-bottom-color: {ACCENT_VIOLET}; color: {TEXT_MUTED}; }}
  .kpi::before {{
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: var(--accent, {ACCENT_VIOLET});
  }}
  .kpi .value {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.65rem; font-weight: 700; line-height: 1.15; letter-spacing: -0.02em;
  }}
  .kpi .label {{
    color: {TEXT_DIM}; font-size: 0.7rem; letter-spacing: 0.1em;
    text-transform: uppercase; margin-top: 0.3rem;
  }}
  .kpi.pink   {{ --accent: {ACCENT_PINK}; }}   .kpi.pink .value   {{ color: {ACCENT_PINK}; }}
  .kpi.cyan   {{ --accent: {ACCENT_CYAN}; }}   .kpi.cyan .value   {{ color: {ACCENT_CYAN}; }}
  .kpi.gold   {{ --accent: {ACCENT_GOLD}; }}   .kpi.gold .value   {{ color: {ACCENT_GOLD}; }}
  .kpi.violet {{ --accent: {ACCENT_VIOLET}; }} .kpi.violet .value {{ color: {ACCENT_VIOLET}; }}
  .kpi.green  {{ --accent: {ACCENT_GREEN}; }}  .kpi.green .value  {{ color: {ACCENT_GREEN}; }}

  .card {{
    background: {BG_CARD}; border: 1px solid {BORDER}; border-radius: 10px;
    padding: 1rem 1.1rem; margin-bottom: 1rem;
  }}
  .card h3 {{ font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.1em;
              color: {TEXT_DIM}; margin: 0 0 0.5rem 0; font-weight: 600; }}
  .card h3 .badge {{
    display: inline-block; font-size: 0.62rem; font-weight: 600;
    padding: 0.1rem 0.45rem; border-radius: 10px; margin-left: 0.5rem;
    letter-spacing: 0.08em; vertical-align: middle;
  }}
  .card h3 .badge.filtered {{
    background: rgba(0,229,255,0.12); color: {ACCENT_CYAN};
    border: 1px solid rgba(0,229,255,0.3);
  }}
  .card h3 .badge.static {{
    background: rgba(155,153,201,0.08); color: {TEXT_DIM};
    border: 1px solid {BORDER};
  }}
  .card .tagline {{ color: {TEXT_MUTED}; font-size: 0.88rem; margin: 0 0 0.5rem 0; }}

  .source {{
    font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;
    color: {TEXT_DIM}; margin: 0.5rem 0 1rem 0; letter-spacing: 0.02em;
    padding: 0.4rem 0.6rem; background: rgba(255,255,255,0.02);
    border-radius: 4px; border-left: 2px solid {BORDER};
  }}

  .tag {{
    display: inline-block; background: {BG_RAISED}; color: {TEXT_MUTED};
    font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;
    padding: 0.2rem 0.55rem; border-radius: 4px;
    border: 1px solid {BORDER}; margin: 0.15rem 0.25rem 0.15rem 0;
  }}

  .filter-bar {{
    background: {BG_CARD}; border: 1px solid {BORDER}; border-radius: 10px;
    padding: 0.9rem 1rem; margin-bottom: 1rem;
  }}
  .filter-bar .label {{ font-size: 0.7rem; letter-spacing: 0.1em; text-transform: uppercase;
                       color: {TEXT_DIM}; font-weight: 600; }}

  /* Tabs restyle: the native st.tabs component's DOM uses data-baseweb
   * hooks; overriding those gives us a pill look with no flicker bar
   * instead of the default Streamlit underline tabs. */
  .stTabs [data-baseweb="tab-list"] {{
    gap: 0.3rem; background: {BG_CARD}; border: 1px solid {BORDER};
    border-radius: 10px; padding: 0.35rem; margin-bottom: 1rem;
  }}
  .stTabs [data-baseweb="tab"] {{
    background: transparent; color: {TEXT_MUTED}; border: none;
    padding: 0.55rem 1.1rem; border-radius: 7px; font-weight: 500;
    font-size: 0.92rem;
  }}
  .stTabs [data-baseweb="tab"]:hover {{ background: rgba(0,229,255,0.06); color: {TEXT}; }}
  .stTabs [aria-selected="true"] {{
    background: {BG_RAISED} !important; color: {TEXT} !important;
    box-shadow: 0 0 12px rgba(124,77,255,0.18) inset;
  }}
  .stTabs [data-baseweb="tab-highlight"] {{ display: none; }}
  .stTabs [data-baseweb="tab-border"] {{ display: none; }}

  /* Dataframe */
  [data-testid="stDataFrame"] {{
    border: 1px solid {BORDER}; border-radius: 10px; overflow: hidden;
  }}

  /* Streamlit selectbox / date input tuning to match the dark palette */
  [data-baseweb="select"] > div, [data-testid="stDateInput"] input {{
    background: {BG_RAISED} !important; border-color: {BORDER} !important;
    color: {TEXT} !important;
  }}

  .footer {{
    margin-top: 2rem; padding: 1rem 1.2rem;
    background: {BG_CARD}; border: 1px solid {BORDER}; border-radius: 10px;
    color: {TEXT_DIM}; font-size: 0.78rem; line-height: 1.6;
    display: flex; justify-content: space-between; gap: 1rem; flex-wrap: wrap;
  }}
  .footer a {{ color: {ACCENT_CYAN}; }}
</style>
""",
    unsafe_allow_html=True,
)


CHART = dict(
    plot_bgcolor=BG_CARD,
    paper_bgcolor=BG_CARD,
    font=dict(color=TEXT, family="Space Grotesk", size=11),
    margin=dict(l=10, r=10, t=10, b=30),
    xaxis=dict(gridcolor="rgba(255,255,255,0.04)", zerolinecolor=BORDER),
    yaxis=dict(gridcolor="rgba(255,255,255,0.04)", zerolinecolor=BORDER),
    legend=dict(bgcolor="rgba(0,0,0,0)", bordercolor=BORDER, borderwidth=1, font=dict(size=10)),
)


# =============================================================================
# DOMAIN KNOWLEDGE
# =============================================================================

GLOSSARY = {
    "CT": (
        "Certificate Transparency. An open, append-only log system that every "
        "public TLS certificate has to be written to."
    ),
    "SAN": ("Subject Alternative Name. The cert field that lists every hostname a certificate is valid for."),
    "CA": "Certificate Authority. The organisation that signs and issues TLS certificates.",
    "CVE": ("Common Vulnerabilities and Exposures. The global ID for a publicly disclosed security flaw."),
    "KEV": ("Known Exploited Vulnerabilities. CISA's catalogue of CVEs with evidence of active exploitation."),
    "C2": "Command and Control. The server a malware implant calls home to for instructions.",
    "CIDR": ("Classless Inter-Domain Routing. The /24, /16 notation that describes an IP range."),
    "DROP": ("Don't Route Or Peer. Spamhaus's list of IP ranges that transit providers should drop entirely."),
    "TLD": "Top-Level Domain. The rightmost label of a hostname (.com, .org, .co.uk).",
    "SLD": "Second-Level Domain. The label immediately to the left of the TLD.",
    "EDROP": (
        "Extended DROP. Spamhaus's companion list for hijacked netblocks allocated to "
        "legitimate RIRs but used by spam-friendly operators."
    ),
    "typosquatting": "Registering a domain that is visually or phonetically close to a legitimate one.",
    "homoglyph": (
        "Two characters that look identical or near-identical to a human reader "
        "(0 vs o, 1 vs l, Cyrillic а vs Latin a)."
    ),
    "Damerau-Levenshtein": (
        "Edit distance that counts insertions, deletions, substitutions and transpositions. "
        "Catches paypla vs paypal as 1 edit, which plain Levenshtein would score as 2."
    ),
    "Jaro-Winkler": (
        "String similarity that rewards a shared prefix. Useful for attacks that keep the "
        "brand at the start (paypal-login, amazon-eu)."
    ),
    "ATT&CK": (
        "MITRE ATT&CK. Structured catalogue of adversary techniques, malware and intrusion "
        "sets. Each entry has a stable ID (T1566, S0266, G0008...)."
    ),
    "dlt": (
        "dlthub. Declarative Python library for writing small resumable ingestion pipelines straight into a warehouse."
    ),
    "Kestra": ("Open-source workflow orchestrator. YAML flows, easy to self-host."),
    "Redpanda": ("Kafka-compatible streaming platform. Drop-in wire-protocol replacement for Kafka clients; no JVM."),
    "MotherDuck": "Managed DuckDB service. Same SQL dialect as local DuckDB, storage on the cloud.",
    "CertStream": (
        "Public feed that fans out new entries from Certificate Transparency logs over a "
        "WebSocket as they are published."
    ),
    "Fly.io": ("PaaS that runs Docker images as Firecracker microVMs. Host for the always-on Python services here."),
    "Feodo": (
        "abuse.ch Feodo Tracker. Curated list of active botnet C2 IPs (Emotet, QakBot, "
        "Dridex, IcedID...), refreshed every few minutes."
    ),
    "ThreatFox": (
        "abuse.ch crowd-sourced IoC feed. Covers ip:port, domain and URL IoCs tagged by "
        "threat type (botnet_cc, payload_delivery...)."
    ),
    "phishing site": (
        "A web page that mimics a legitimate brand to steal credentials, payment details or session tokens."
    ),
    "phishing kit": (
        "A pre-built bundle (HTML/CSS/JS) that replicates a brand's login page. Attackers "
        "unzip one into a compromised host to stand up a phishing site in minutes."
    ),
    "TLS certificate": (
        "Cryptographic credential that tells a browser the site is who it claims to be and "
        "encrypts the connection. Any public CA issuance is logged to CT."
    ),
    "malware": (
        "Software written to harm: steal data, exfiltrate credentials, encrypt files for "
        "ransom, hijack machines into botnets."
    ),
    "landing page": (
        "The page a victim lands on after clicking the phishing link. Usually a clone of the real brand's login form."
    ),
    "append-only": (
        "A data structure that accepts new entries but never rewrites or deletes old ones. "
        "CT logs are Merkle-tree append-only; auditors can cryptographically prove no cert "
        "was removed or backdated."
    ),
    "threat-intel": (
        "Threat intelligence. Curated data about attacker infrastructure and activity (bad "
        "IPs, hashes, techniques), published so defenders can block early."
    ),
    "CISA": ("Cybersecurity and Infrastructure Security Agency. US federal agency; publishes the KEV catalogue."),
    "abuse.ch": (
        "Swiss non-profit that runs Feodo Tracker, ThreatFox, URLhaus and MalwareBazaar. "
        "Community-maintained threat-intel feeds, freely downloadable."
    ),
    "Spamhaus": (
        "UK/CH anti-spam outfit that maintains DROP, EDROP and the SBL/XBL block-lists used across the industry."
    ),
    "MITRE": ("MITRE Corporation. Runs ATT&CK and maintains the CVE program."),
    "MaxMind": (
        "Company behind the GeoIP / GeoLite2 databases. GeoLite2 is a free CSV/MMDB set "
        "that maps IPv4/IPv6 ranges to ASN, country and city."
    ),
    "AS": (
        "Autonomous System. A block of IPs administered by a single organisation and routed as a unit on the Internet."
    ),
}

MALWARE_DESCRIPTIONS = {
    "emotet": "Banking trojan turned malware distribution platform. Takedown in 2021, back by late 2021.",
    "heodo": "abuse.ch alias for Emotet variants.",
    "qakbot": "Qbot / Pinkslipbot. Banking trojan and loader; common entry point for Conti and Black Basta ransomware.",
    "trickbot": "Modular banking trojan turned ransomware loader (Ryuk, Conti). Disrupted 2020; fragments remain.",
    "icedid": "BokBot. Info stealer and loader, delivered through malicious Office docs and ZIPs.",
    "dridex": (
        "Long-running banking trojan tied to Evil Corp. Macro-enabled Office documents plus later-stage payloads."
    ),
    "cobalt strike": "Commercial adversary simulation toolkit. Cracked versions are ubiquitous in ransomware ops.",
    "cobaltstrike": "Commercial adversary simulation toolkit. Cracked versions are ubiquitous in ransomware ops.",
    "bumblebee": "Loader family from 2022, suspected Qakbot successor. Linked to Conti-era operators.",
    "remcos": "Commercial RAT sold as legit admin software. Abused by low-effort phishing campaigns.",
    "asyncrat": "Open-source RAT, trivial to deploy. Commonly dropped by commodity loaders.",
    "njrat": "Long-lived commodity RAT, popular in the Middle East. Cheap, feature-rich, mass-deployed.",
    "formbook": "Info stealer sold as MaaS. Harvests credentials from browsers and email clients.",
    "lokibot": "Credential stealer, targets browsers, FTP clients, crypto wallets.",
    "agenttesla": "Keylogger + stealer, distributed through phishing attachments targeting SMEs.",
    "pikabot": "Loader that emerged in 2023 as a suspected Qakbot successor. Associated with Black Basta.",
    "vidar": "Info stealer sold on underground markets. Grabs browser credentials, crypto wallets, 2FA backups.",
    "valleyrat": "Chinese-origin RAT, aka Winos. Heavy use in campaigns against Chinese-speaking targets.",
    "nanocore rat": "Commodity .NET RAT, full remote control. Popular in low-skill phishing kits.",
    "nanocore": "Commodity .NET RAT, full remote control. Popular in low-skill phishing kits.",
    "xworm": "RAT + loader combo with anti-analysis tricks. Sold cheaply on forums.",
    "mirai": "IoT botnet blueprint. Every bored script kiddie forks it.",
    "sliver": "Open-source red-team C2 framework. Used legitimately by pentesters and maliciously by operators.",
    "darkcomet": "Old-school RAT, still alive. GUI-driven, visible in low-effort campaigns.",
    "purerat": ".NET RAT sold as a commercial product. Turns up in business email compromise kits.",
    "sectoprat": "Remote-access tool with screen-spying features, distributed via cracked software.",
    "dcrat": "Modular RAT sold on Russian forums. Plugin architecture.",
    "kimwolf": "Less-documented botnet family. Appears in ThreatFox feeds tied to loader infrastructure.",
    "stealc": "Information stealer, clone of Raccoon. Credentials, crypto wallets, browser data.",
}


# Badges for card headers: "FILTERED" means the widget responds to the global
# filter bar; "SNAPSHOT" means it reads from a pre-aggregated daily mart.
BADGE_FILTERED = (
    "<span class='badge filtered' title='Responds to the filter bar (date range, brand, CA).'>FILTERED</span>"
)
BADGE_STATIC = (
    "<span class='badge static' title='Batch mart refreshed daily. Not driven by the filter bar.'>SNAPSHOT</span>"
)


def tip(term: str, label: str | None = None) -> str:
    desc = GLOSSARY.get(term, "")
    text = label or term
    return f'<abbr title="{desc}">{text}</abbr>' if desc else text


def malware_tooltip(family: str | None) -> str:
    """HTML-safe one-liner for hover tooltips on charts."""
    if not family:
        return ""
    desc = MALWARE_DESCRIPTIONS.get(family.lower().strip())
    if not desc:
        return ""
    # Plotly hovertemplate is HTML; ampersand escape is enough since we
    # control the strings.
    return desc.replace("&", "&amp;").replace("<", "&lt;")


# =============================================================================
# QUERIES
# =============================================================================
#
# Everything the dashboard reads is either a pre-aggregated mart (dbt-built,
# refreshed daily) or a small slice of stg_suspicious_certs filtered by the
# global filter bar.


@st.cache_data(ttl=LIVE_TTL)
def q_kpis() -> dict[str, Any]:
    return run_query(f"select * from {MD_DATABASE}.mart_dashboard_kpis").iloc[0].to_dict()


@st.cache_data(ttl=BATCH_TTL)
def q_c2_by_country() -> pd.DataFrame:
    # Join back to mart_c2_active so we surface the full country name in the
    # legend rather than the 2-letter ISO code the aggregate mart keeps.
    return run_query(f"""
        select b.country,
               coalesce(max(a.country_name), b.country) as country_name,
               b.active_c2, b.distinct_families, b.top_family, b.sources
        from {MD_DATABASE}.mart_dashboard_c2_by_country b
        left join {MD_DATABASE}.mart_c2_active a on a.country = b.country
        group by b.country, b.active_c2, b.distinct_families, b.top_family, b.sources
        order by b.active_c2 desc
    """)


@st.cache_data(ttl=BATCH_TTL)
def q_c2_active_rows() -> pd.DataFrame:
    return run_query(f"""
        select ip_address, port, malware_family, country, country_name,
               city_name, latitude, longitude, accuracy_radius,
               as_name, source, first_seen, last_seen
        from {MD_DATABASE}.mart_c2_active
        order by last_seen desc nulls last
    """)


@st.cache_data(ttl=BATCH_TTL)
def q_c2_by_malware() -> pd.DataFrame:
    return run_query(f"""
        select malware_family, count(*) as active_c2
        from {MD_DATABASE}.mart_c2_active
        where malware_family is not null
        group by 1 order by active_c2 desc
    """)


@st.cache_data(ttl=BATCH_TTL)
def q_kev_monthly() -> pd.DataFrame:
    return run_query(f"select * from {MD_DATABASE}.mart_dashboard_kev_monthly")


@st.cache_data(ttl=BATCH_TTL)
def q_kev_vendors() -> pd.DataFrame:
    return run_query(f"select * from {MD_DATABASE}.mart_dashboard_kev_vendors")


@st.cache_data(ttl=BATCH_TTL)
def q_spamhaus_buckets() -> pd.DataFrame:
    return run_query(f"select * from {MD_DATABASE}.mart_spamhaus_by_country")


# Filtered queries: accept date range + optional brand/issuer, read directly
# from the staging table so filters are honest (no pre-agg loses rows).


def q_suspicious_hourly(since: datetime, until: datetime, issuer: str | None) -> pd.DataFrame:
    clauses = ["seen_at_ts between ? and ?"]
    params: list[Any] = [since, until]
    if issuer and issuer != "(all)":
        clauses.append("issuer_cn = ?")
        params.append(issuer)
    return run_query(
        f"""
        select date_trunc('hour', seen_at_ts) as hour, count(*) as flagged,
               date_trunc('hour', seen_at_ts) >= date_trunc('hour', now()) as is_partial_hour
        from {MD_DATABASE}.stg_suspicious_certs
        where {" and ".join(clauses)}
        group by 1 order by 1
    """,
        tuple(params),
    )


def q_top_brands(since: datetime, until: datetime, issuer: str | None) -> pd.DataFrame:
    clauses = ["s.seen_at_ts between ? and ?"]
    params: list[Any] = [since, until]
    if issuer and issuer != "(all)":
        clauses.append("s.issuer_cn = ?")
        params.append(issuer)
    return run_query(
        f"""
        select brand, count(*) as hits
        from (
          select s.seen_at_ts, json_extract_string(d.value, '$.brand') as brand
          from {MD_DATABASE}.stg_suspicious_certs s,
          lateral (select unnest(from_json(s.detections_raw::varchar, '["json"]')) as value) d
          where {" and ".join(clauses)}
        )
        where brand is not null
        group by 1 order by hits desc limit 15
    """,
        tuple(params),
    )


def q_recent_suspicious(since: datetime, until: datetime, brand: str | None, issuer: str | None) -> pd.DataFrame:
    clauses = ["seen_at_ts between ? and ?"]
    params: list[Any] = [since, until]
    if issuer and issuer != "(all)":
        clauses.append("issuer_cn = ?")
        params.append(issuer)
    if brand and brand != "(all)":
        # Brand lives inside the detections JSON; check via the raw substring
        # to avoid a lateral unnest per row.
        clauses.append("detections_raw::varchar ilike ?")
        params.append(f'%"brand":"{brand}"%')
    return run_query(
        f"""
        select seen_at_ts, primary_domain, issuer_cn, max_score
        from {MD_DATABASE}.stg_suspicious_certs
        where {" and ".join(clauses)}
        order by seen_at_ts desc limit 50
    """,
        tuple(params),
    )


def q_top_issuers(since: datetime, until: datetime) -> pd.DataFrame:
    return run_query(
        f"""
        select coalesce(issuer_cn, '(unknown)') as issuer, count(*) as hits
        from {MD_DATABASE}.stg_suspicious_certs
        where seen_at_ts between ? and ?
        group by 1 order by hits desc limit 12
    """,
        (since, until),
    )


@st.cache_data(ttl=FILTER_TTL)
def q_filter_options() -> dict[str, list[str]]:
    brands = run_query("""
        select distinct brand from mart_top_impersonated_brands
        where brand is not null order by brand
    """)["brand"].tolist()
    issuers = run_query(f"""
        select issuer from {MD_DATABASE}.mart_dashboard_top_issuers
        where issuer != '(unknown)' order by hits desc limit 20
    """)["issuer"].tolist()
    return {"brands": brands, "issuers": issuers}


# =============================================================================
# HEADER + KPIs
# =============================================================================

kpis = q_kpis()

st.markdown("<h1>Phishing Radar</h1>", unsafe_allow_html=True)
st.markdown(
    "<p class='subtitle'>Every "
    + tip("phishing site", "phishing site")
    + " needs a "
    + tip("TLS certificate", "TLS certificate")
    + ". We tail the "
    + tip("CT", "Certificate Transparency")
    + " firehose, flag impersonations, and cross-reference against live "
    + tip("malware", "malware")
    + " infrastructure.</p>",
    unsafe_allow_html=True,
)


def _kpi(klass: str, value: int, label: str, tooltip: str) -> str:
    return (
        f"<div class='kpi {klass}' title='{tooltip}'>"
        f"<div class='value'>{value:,}</div>"
        f"<div class='label'>{label}</div>"
        "</div>"
    )


st.markdown(
    "<div class='kpi-grid'>"
    + _kpi(
        "pink",
        int(kpis["kev_total"]),
        "CVEs actively exploited",
        "CVEs added to CISA's Known Exploited Vulnerabilities catalogue in the last 365 days.",
    )
    + _kpi(
        "gold",
        int(kpis["kev_ransomware"]),
        "Used by ransomware",
        "Subset of KEV flagged by CISA as tied to known ransomware campaigns.",
    )
    + _kpi(
        "cyan",
        int(kpis["c2_total"]),
        "Online botnet C2s",
        "Active Command-and-Control IPs from abuse.ch Feodo Tracker + ThreatFox (botnet_cc IoCs).",
    )
    + _kpi(
        "violet",
        int(kpis["c2_countries"]),
        "Countries hosting C2s",
        "Distinct hosting countries across the C2 IPs, derived from MaxMind GeoLite2-Country.",
    )
    + _kpi(
        "green",
        int(kpis["malware_total"]),
        "Malware in MITRE",
        "Software entries in the MITRE ATT&CK catalogue (malware + tools).",
    )
    + _kpi(
        "pink",
        int(kpis["suspicious_total"]),
        "Phishing certs seen",
        "Total TLS certs flagged as likely impersonations since the CertStream producer came up.",
    )
    + "</div>",
    unsafe_allow_html=True,
)


st.markdown(
    "<p class='intro'>"
    + "A modern "
    + tip("phishing kit", "phishing kit")
    + " needs three things: a look-alike domain, a "
    + tip("TLS certificate", "TLS cert")
    + " so browsers don&rsquo;t panic, and somewhere to host the "
    + tip("landing page", "landing page")
    + ". The domain and the cert are the two things we can see before the first email "
    + "ever leaves. Public "
    + tip("CT", "CT")
    + " logs make it inevitable: every certificate issued has to be written to an "
    + tip("append-only", "append-only")
    + ", cryptographically verifiable log. This report tails that firehose in real time "
    + "and lines the findings up against what the rest of the criminal ecosystem is "
    + "doing today."
    + "</p>",
    unsafe_allow_html=True,
)


# =============================================================================
# GLOBAL FILTER BAR
# =============================================================================

filter_opts = q_filter_options()

# Filter bar. st.container(border=True) gives us the panel outline; inside,
# four columns hold date range, brand, issuing CA and the Live-refresh toggle
# that drives the Live stream fragment.
with st.container(border=True):
    fcol1, fcol2, fcol3, fcol4 = st.columns([2, 1.3, 1.3, 1])
    with fcol1:
        today = date.today()
        default_since = today - timedelta(days=7)
        date_range = st.date_input(
            "Date range",
            value=(default_since, today),
            max_value=today,
            help="Filters every chart that reads the suspicious-cert stream.",
        )
    with fcol2:
        brand = st.selectbox("Brand", ["(all)"] + filter_opts["brands"])
    with fcol3:
        issuer = st.selectbox("Issuing CA", ["(all)"] + filter_opts["issuers"])
    with fcol4:
        live = st.toggle("Live refresh", value=False, help="Re-queries the stream every 30s.")

if isinstance(date_range, tuple) and len(date_range) == 2:
    since_d, until_d = date_range
else:
    since_d = date_range if isinstance(date_range, date) else default_since
    until_d = today

since = datetime.combine(since_d, datetime.min.time())
until = datetime.combine(until_d, datetime.max.time())


tab_overview, tab_stream, tab_batch, tab_map, tab_about = st.tabs(
    ["Overview", "Live phishing stream", "Threat landscape", "Map", "Stack"]
)


# =============================================================================
# HELPERS
# =============================================================================


def render_c2_malware_chart(key_suffix: str, height: int = 360) -> None:
    """Horizontal bar of active C2s per malware family, with hover tooltip
    drawn from MALWARE_DESCRIPTIONS."""
    c2_mal = q_c2_by_malware()
    if c2_mal.empty:
        st.info("No active C2s tracked right now.")
        return
    c2_mal = c2_mal.head(14).copy()
    c2_mal["tooltip"] = c2_mal["malware_family"].map(malware_tooltip)
    fig = go.Figure(
        go.Bar(
            x=c2_mal["active_c2"],
            y=c2_mal["malware_family"],
            orientation="h",
            marker_color=ACCENT_CYAN,
            customdata=c2_mal[["tooltip"]].values,
            hovertemplate="<b>%{y}</b><br>%{x} active C2s<br><i>%{customdata[0]}</i><extra></extra>",
        )
    )
    fig.update_layout(height=height, **CHART)
    fig.update_xaxes(title_text="Active C2s")
    fig.update_yaxes(autorange="reversed")
    st.plotly_chart(fig, use_container_width=True, key=f"c2_malware_{key_suffix}")


def render_suspicious_hourly(key_suffix: str) -> None:
    sus_time = q_suspicious_hourly(since, until, issuer)
    if sus_time.empty:
        st.info("No flagged certs in the selected range.")
        return
    complete = sus_time[~sus_time["is_partial_hour"]]
    partial = sus_time[sus_time["is_partial_hour"]]
    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=complete["hour"],
            y=complete["flagged"],
            mode="lines+markers",
            line=dict(color=ACCENT_CYAN, width=2),
            marker=dict(size=5, color=ACCENT_CYAN),
            fill="tozeroy",
            fillcolor="rgba(0,229,255,0.08)",
            name="Hourly count",
            hovertemplate="<b>%{x|%Y-%m-%d %H:00}</b><br>%{y} flagged<extra></extra>",
        )
    )
    if not partial.empty:
        fig.add_trace(
            go.Scatter(
                x=partial["hour"],
                y=partial["flagged"],
                mode="markers",
                marker=dict(size=9, color=ACCENT_PINK, symbol="diamond-open"),
                name="Current hour (partial)",
                hovertemplate="<b>%{x|%Y-%m-%d %H:00}</b><br>%{y} flagged (still in progress)<extra></extra>",
            )
        )
    fig.update_layout(height=300, **CHART)
    st.plotly_chart(fig, use_container_width=True, key=f"hourly_{key_suffix}")


def render_top_issuers(key_suffix: str) -> None:
    issuers = q_top_issuers(since, until)
    if issuers.empty:
        st.info("No data for this range.")
        return
    fig = go.Figure(
        go.Bar(
            x=issuers["hits"],
            y=issuers["issuer"],
            orientation="h",
            marker_color=ACCENT_VIOLET,
            hovertemplate="<b>%{y}</b><br>%{x} flagged certs<extra></extra>",
        )
    )
    fig.update_layout(height=300, **CHART)
    fig.update_yaxes(autorange="reversed")
    st.plotly_chart(fig, use_container_width=True, key=f"issuers_{key_suffix}")


def render_top_brands(key_suffix: str) -> None:
    brands = q_top_brands(since, until, issuer)
    if brands.empty:
        st.info("No brand impersonations in this range.")
        return
    fig = go.Figure(
        go.Bar(
            x=brands["hits"],
            y=brands["brand"],
            orientation="h",
            marker_color=ACCENT_PINK,
            hovertemplate="<b>%{y}</b><br>%{x} flagged certs<extra></extra>",
        )
    )
    fig.update_layout(height=360, **CHART)
    fig.update_xaxes(title_text="Flagged certs")
    fig.update_yaxes(autorange="reversed")
    st.plotly_chart(fig, use_container_width=True, key=f"brands_{key_suffix}")


def render_recent_table(key_suffix: str) -> None:
    recent = q_recent_suspicious(since, until, brand, issuer)
    if recent.empty:
        st.info("No flagged certs in this slice.")
        return
    st.dataframe(
        recent.rename(
            columns={
                "seen_at_ts": "First seen",
                "primary_domain": "Domain",
                "issuer_cn": "Issuer",
                "max_score": "Score",
            }
        ),
        use_container_width=True,
        hide_index=True,
        height=420,
    )


# =============================================================================
# TAB: OVERVIEW
# =============================================================================

with tab_overview:
    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown(
            f"""
<div class='card'>
  <h3>The streaming lane {BADGE_FILTERED}</h3>
  <p class='tagline'>A producer pulls every cert from {tip("CT", "CT")} logs via
  {tip("CertStream")}, a Python detector scores each domain against a short list of popular
  brands using {tip("homoglyph")} normalisation, substring matching and
  {tip("typosquatting")} ({tip("Damerau-Levenshtein")} 1 or 2 plus {tip("Jaro-Winkler")}),
  and writes the hits to {tip("MotherDuck")}.</p>
  <p class='tagline' style='margin-top:0.5rem;'>Top impersonated brands in the selected window:</p>
</div>
""",
            unsafe_allow_html=True,
        )
        render_top_brands("ovr")
        st.markdown(
            "<div class='source'>stg_suspicious_certs &middot; filtered by date range and issuer.</div>",
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
<div class='card'>
  <h3>The batch lane {BADGE_STATIC}</h3>
  <p class='tagline'>Six {tip("threat-intel", "threat-intel")} feeds
  ({tip("CISA", "CISA")} {tip("KEV")}, {tip("abuse.ch", "abuse.ch")} {tip("Feodo")},
  {tip("abuse.ch", "abuse.ch")} {tip("ThreatFox")}, {tip("Spamhaus", "Spamhaus")}
  {tip("DROP")} and {tip("EDROP")}, {tip("ATT&amp;CK", "MITRE ATT&amp;CK")},
  {tip("MaxMind", "MaxMind")} GeoLite2) refresh daily via {tip("Kestra")}, land in
  {tip("MotherDuck")} through {tip("dlt")}, and dbt materialises them into the marts this
  dashboard reads.</p>
  <p class='tagline' style='margin-top:0.5rem;'>Active {tip("C2", "C2")} servers by
  malware family (hover for context):</p>
</div>
""",
            unsafe_allow_html=True,
        )
        render_c2_malware_chart("ovr")
        st.markdown(
            "<div class='source'>"
            "mart_c2_active &middot; union of Feodo + ThreatFox. "
            "Hover a bar for the malware description."
            "</div>",
            unsafe_allow_html=True,
        )


# =============================================================================
# TAB: LIVE PHISHING STREAM (fragment for optional auto-refresh)
# =============================================================================


@st.fragment(run_every=30 if False else None)  # placeholder; rebound below
def _stream_panel_placeholder() -> None: ...


def stream_panel() -> None:
    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown(
            f"""
<div class='card'>
  <h3>Suspicious certs over time {BADGE_FILTERED}</h3>
  <p class='tagline'>Hourly count of flagged certificates. Pink diamonds mark the
  current hour, which is still in progress and should not be compared against
  complete hours.</p>
</div>
""",
            unsafe_allow_html=True,
        )
        render_suspicious_hourly("stream")
        st.markdown(
            "<div class='source'>"
            "stg_suspicious_certs &middot; mart_dashboard_suspicious_hourly flags partial hours."
            "</div>",
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
<div class='card'>
  <h3>Top issuing {tip("CA", "CAs")} {BADGE_FILTERED}</h3>
  <p class='tagline'>Which certificate authorities signed the suspicious certs. A Let&rsquo;s
  Encrypt cert for a typosquatted domain is a different story than a paid DV from DigiCert.</p>
</div>
""",
            unsafe_allow_html=True,
        )
        render_top_issuers("stream")
        st.markdown(
            "<div class='source'>mart_dashboard_top_issuers &middot; names as they appear in the CT log.</div>",
            unsafe_allow_html=True,
        )

    st.markdown(
        f"""
<div class='card'>
  <h3>Latest flagged certificates {BADGE_FILTERED}</h3>
  <p class='tagline'>The fifty most recent hits in the current slice. Not every row is
  malicious: legitimate resellers and fan sites trip the rules too.</p>
</div>
""",
        unsafe_allow_html=True,
    )
    render_recent_table("stream")
    st.markdown(
        "<div class='source'>stg_suspicious_certs &middot; filters honoured.</div>",
        unsafe_allow_html=True,
    )


# st.fragment's run_every takes a string like "30s"; None disables the
# auto-rerun. We rebind the fragment with a concrete interval so toggling the
# "Live refresh" switch in the filter bar controls whether this block
# re-queries MotherDuck every 30 seconds or sits still.
stream_fragment = st.fragment(run_every="30s" if live else None)(stream_panel)

with tab_stream:
    stream_fragment()


# =============================================================================
# TAB: THREAT LANDSCAPE
# =============================================================================

with tab_batch:
    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown(
            f"""
<div class='card'>
  <h3>KEV monthly additions {BADGE_STATIC}</h3>
  <p class='tagline'>Every time a CVE lands in CISA&rsquo;s {tip("KEV")} catalogue, it
  means there is evidence of active exploitation in the wild. The current
  month is rendered in a lighter shade because it is still in progress and
  inevitably undercounts.</p>
</div>
""",
            unsafe_allow_html=True,
        )
        kev_monthly = q_kev_monthly()
        if not kev_monthly.empty:
            # Plotly only accepts alpha via rgba(), not 8-digit hex, so we
            # render partial months translucent using the gold accent's rgb.
            colors = ["rgba(255,184,0,0.33)" if partial else ACCENT_GOLD for partial in kev_monthly["is_partial_month"]]
            fig = go.Figure(
                go.Bar(
                    x=kev_monthly["month"],
                    y=kev_monthly["additions"],
                    marker_color=colors,
                    hovertemplate="<b>%{x|%B %Y}</b><br>%{y} CVEs added<extra></extra>",
                )
            )
            fig.update_layout(height=300, **CHART)
            st.plotly_chart(fig, use_container_width=True, key="batch_kev_month")
        st.markdown(
            "<div class='source'>mart_dashboard_kev_monthly &middot; current month flagged as partial.</div>",
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
<div class='card'>
  <h3>Hijacked IP ranges {BADGE_STATIC}</h3>
  <p class='tagline'>Spamhaus bucketizes hijacked CIDRs by prefix length. Small blocks
  (/24 and below) dominate; attackers prefer splatter over single big takeovers.</p>
</div>
""",
            unsafe_allow_html=True,
        )
        spam = q_spamhaus_buckets()
        if not spam.empty:
            # Force prefix-length order (huge first, small last) so the bars
            # read as a histogram of block sizes, not alphabetically.
            bucket_order = [
                "huge (/8-/16)",
                "large (/17-/20)",
                "medium (/21-/24)",
                "small (/25+)",
            ]
            fig = px.bar(
                spam,
                x="block_size_bucket",
                y="block_count",
                color="list",
                color_discrete_map={"drop": ACCENT_PINK, "edrop": ACCENT_GOLD},
                barmode="group",
                category_orders={"block_size_bucket": bucket_order},
            )
            fig.update_layout(height=300, **CHART)
            fig.update_xaxes(title_text="Block size (prefix length)")
            fig.update_yaxes(title_text="Hijacked blocks")
            st.plotly_chart(fig, use_container_width=True, key="batch_spamhaus")
        st.markdown(
            "<div class='source'>mart_spamhaus_by_country &middot; DROP + EDROP lists.</div>",
            unsafe_allow_html=True,
        )

    col1, col2 = st.columns([1, 1])
    with col1:
        st.markdown(
            f"""
<div class='card'>
  <h3>Top KEV vendors {BADGE_STATIC}</h3>
  <p class='tagline'>Bar length is total CVEs in KEV; colour intensity is the
  percent of those linked to ransomware operations. High ratio matters more
  than high count.</p>
</div>
""",
            unsafe_allow_html=True,
        )
        kev_vendors = q_kev_vendors()
        if not kev_vendors.empty:
            # Clamp the color scale at 50% so one outlier vendor (SmarterTools
            # with 1 CVE, 100% ransomware-linked) doesn't flatten the rest of
            # the gradient. The hover still shows the true ratio.
            kv = kev_vendors.copy()
            kv["label"] = kv["ransomware_ratio_pct"].map(lambda r: f"{r:.0f}%" if r > 0 else "")
            fig = go.Figure(
                go.Bar(
                    x=kv["cves"],
                    y=kv["vendor"],
                    orientation="h",
                    text=kv["label"],
                    textposition="outside",
                    textfont=dict(color=ACCENT_GOLD, size=11),
                    marker=dict(
                        color=kv["ransomware_ratio_pct"],
                        colorscale=[[0, ACCENT_VIOLET], [1, ACCENT_PINK]],
                        cmin=0,
                        cmax=50,
                        colorbar=dict(
                            title=dict(text="% ransomware", font=dict(color=TEXT_MUTED, size=10)),
                            tickfont=dict(color=TEXT_MUTED, size=9),
                            tickvals=[0, 10, 25, 50],
                            ticktext=["0%", "10%", "25%", "50%+"],
                            thickness=10,
                            len=0.7,
                            outlinewidth=0,
                            bgcolor="rgba(0,0,0,0)",
                        ),
                    ),
                    customdata=kv[["ransomware_linked", "ransomware_ratio_pct"]].values,
                    hovertemplate=(
                        "<b>%{y}</b><br>%{x} CVEs in KEV<br>"
                        "%{customdata[0]} tied to ransomware (%{customdata[1]:.1f}%)<extra></extra>"
                    ),
                )
            )
            fig.update_layout(height=400, **CHART)
            fig.update_xaxes(title_text="CVEs in KEV (label = % ransomware-linked)")
            fig.update_yaxes(autorange="reversed")
            st.plotly_chart(fig, use_container_width=True, key="batch_kev_vendors")
        st.markdown(
            "<div class='source'>mart_dashboard_kev_vendors &middot; ratio column pre-computed.</div>",
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
<div class='card'>
  <h3>Active C2s by hosting country {BADGE_STATIC}</h3>
  <p class='tagline'>Countries where the actual {tip("C2")} servers sit. Not the same as
  attribution: hosting is fluid and most abuse lives in permissive transit networks.</p>
</div>
""",
            unsafe_allow_html=True,
        )
        c2_country = q_c2_by_country()
        if not c2_country.empty:
            top = c2_country[c2_country["country"] != "(unknown)"].head(15).copy()
            top["tooltip"] = top["top_family"].map(malware_tooltip)
            fig = go.Figure(
                go.Bar(
                    x=top["active_c2"],
                    y=top["country_name"],
                    orientation="h",
                    marker_color=ACCENT_CYAN,
                    customdata=top[["top_family", "tooltip", "sources"]].values,
                    hovertemplate=(
                        "<b>%{y}</b><br>%{x} active C2s<br>"
                        "Top family: %{customdata[0]}<br>"
                        "<i>%{customdata[1]}</i><br>"
                        "Sources: %{customdata[2]}<extra></extra>"
                    ),
                )
            )
            fig.update_layout(height=400, **CHART)
            fig.update_xaxes(title_text="Active C2s")
            fig.update_yaxes(autorange="reversed")
            st.plotly_chart(fig, use_container_width=True, key="batch_c2_country")
        st.markdown(
            "<div class='source'>"
            "mart_dashboard_c2_by_country &middot; Feodo + ThreatFox, geolocated via MaxMind."
            "</div>",
            unsafe_allow_html=True,
        )


# =============================================================================
# TAB: MAP (scatter_geo)
# =============================================================================

with tab_map:
    st.markdown(
        f"""
<div class='card'>
  <h3>Where the {tip("C2", "C2")} servers live {BADGE_STATIC}</h3>
  <p class='tagline'>Every dot is one active {tip("C2")} IP, placed at the
  lat/lon {tip("MaxMind", "MaxMind")} GeoLite2-City reports for its hosting block.
  Colour is the {tip("malware", "malware")} family. Hosting location is a noisy signal
  (hosting is cheap and fluid, attribution belongs to operators not servers) but it
  still paints a useful picture: attackers cluster where transit is permissive,
  bulletproof providers tolerate them and takedown notices are slow to land.</p>
  <p class='tagline' style='margin-top:0.5rem;'>Accuracy is coarse: many of
  the free-tier records only resolve to the country-level centroid, so IPs
  from the same {tip("AS", "AS")} land on top of each other. We jitter &plusmn;0.3&deg;
  to pull apart stacks around a single coordinate.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    c2_rows = q_c2_active_rows()
    mappable = c2_rows.dropna(subset=["latitude", "longitude"]).copy()
    unmapped = c2_rows[c2_rows["latitude"].isna()].copy()

    if mappable.empty:
        st.info("No geolocated C2s right now.")
    else:
        # Deterministic jitter so dots don't dance across reruns: hash the IP
        # and map to +/- 0.3 degrees. Keeps IPs on the same AS visually
        # separable without lying about the location (jitter << country size).
        def _jitter(ip: str, i: int) -> float:
            h = int(hashlib.md5(f"{ip}:{i}".encode()).hexdigest()[:8], 16)
            return ((h % 1000) / 1000.0 - 0.5) * 0.6  # +/- 0.3 deg

        mappable["lat_jit"] = [
            lat + _jitter(ip, 0) for ip, lat in zip(mappable["ip_address"], mappable["latitude"], strict=True)
        ]
        mappable["lon_jit"] = [
            lon + _jitter(ip, 1) for ip, lon in zip(mappable["ip_address"], mappable["longitude"], strict=True)
        ]
        mappable["place"] = [
            f"{c}, {n}" if c else n for c, n in zip(mappable["city_name"], mappable["country_name"], strict=True)
        ]
        mappable["fam_display"] = mappable["malware_family"].fillna("(unknown)")
        mappable["desc"] = mappable["malware_family"].map(malware_tooltip)

        # One trace per malware family so plotly auto-assigns colours and the
        # legend lets you toggle families on/off.
        families = mappable["fam_display"].value_counts()
        palette = [
            ACCENT_PINK,
            ACCENT_CYAN,
            ACCENT_GOLD,
            ACCENT_VIOLET,
            ACCENT_GREEN,
            "#ff9acb",
            "#7ae9ff",
            "#ffdd7d",
            "#b69eff",
            "#7affcb",
        ]
        fig = go.Figure()
        for idx, (fam, _count) in enumerate(families.items()):
            sub = mappable[mappable["fam_display"] == fam]
            fig.add_trace(
                go.Scattergeo(
                    lon=sub["lon_jit"],
                    lat=sub["lat_jit"],
                    name=fam,
                    text=sub["ip_address"],
                    customdata=sub[["place", "fam_display", "desc", "port", "source"]].values,
                    marker=dict(
                        size=9,
                        color=palette[idx % len(palette)],
                        line=dict(color="rgba(255,255,255,0.35)", width=0.5),
                        opacity=0.85,
                    ),
                    hovertemplate=(
                        "<b>%{text}</b>:%{customdata[3]}<br>"
                        "%{customdata[0]}<br>"
                        "Family: %{customdata[1]}<br>"
                        "<i>%{customdata[2]}</i><br>"
                        "Source: %{customdata[4]}<extra></extra>"
                    ),
                )
            )

        fig.update_geos(
            projection_type="natural earth",
            bgcolor=BG_CARD,
            showcountries=True,
            countrycolor=BORDER,
            showocean=True,
            oceancolor=BG,
            showland=True,
            landcolor="#10102a",
            showframe=False,
            showcoastlines=False,
        )
        fig.update_layout(
            height=560,
            margin=dict(l=0, r=0, t=10, b=0),
            paper_bgcolor=BG_CARD,
            geo=dict(bgcolor=BG_CARD),
            legend=dict(
                bgcolor="rgba(0,0,0,0.3)",
                bordercolor=BORDER,
                borderwidth=1,
                font=dict(color=TEXT_MUTED, size=10),
            ),
        )
        st.plotly_chart(fig, use_container_width=True, key="map_c2_ip_scatter")

        col1, col2 = st.columns([1, 1])
        with col1:
            st.markdown(
                "<div class='card'><h3>Geolocated IPs</h3><p class='tagline'>Active C2s placed on the map.</p></div>",
                unsafe_allow_html=True,
            )
            st.dataframe(
                mappable.rename(
                    columns={
                        "ip_address": "IP",
                        "port": "Port",
                        "malware_family": "Family",
                        "place": "Place",
                        "source": "Source",
                    }
                )[["IP", "Port", "Family", "Place", "Source"]].head(30),
                use_container_width=True,
                hide_index=True,
                height=380,
            )
        with col2:
            if not unmapped.empty:
                st.markdown(
                    "<div class='card'><h3>Not geolocated</h3>"
                    "<p class='tagline'>IPs whose block doesn&rsquo;t match a GeoLite2 "
                    "row (usually tiny registrations, anycast or Seychelles-flagged "
                    "bulletproof hosts). They count towards totals but don&rsquo;t "
                    "appear on the map.</p></div>",
                    unsafe_allow_html=True,
                )
                st.dataframe(
                    unmapped.rename(
                        columns={
                            "ip_address": "IP",
                            "port": "Port",
                            "malware_family": "Family",
                            "country_name": "Country",
                        }
                    )[["IP", "Port", "Family", "Country"]],
                    use_container_width=True,
                    hide_index=True,
                    height=240,
                )
        st.markdown(
            "<div class='source'>"
            "mart_c2_active &middot; one row per IP, lat/lon from MaxMind GeoLite2-City. "
            "Jitter &plusmn;0.3&deg; applied so IPs sharing a block are visible."
            "</div>",
            unsafe_allow_html=True,
        )


# =============================================================================
# TAB: STACK
# =============================================================================


def _tag_link(label: str, url: str) -> str:
    # Tag rendered as a link, inherits the .tag look so the Stack tab is
    # consistent with the inline tags used elsewhere in the copy.
    return (
        f'<a class="tag" href="{url}" target="_blank" rel="noopener" '
        f'style="color:inherit;border-bottom:none;">{label}</a>'
    )


with tab_about:
    col1, col2 = st.columns([1, 1])
    with col1:
        st.markdown(
            "<div class='card'>"
            "<h3>Streaming</h3>"
            "<p class='tagline'>Five always-on Fly.io machines: a self-hosted "
            "certstream-server-go aggregates the CT firehose, a Python producer "
            "pushes events to Redpanda Cloud, a detector enriches and windows "
            "them, a sink lands everything into MotherDuck.</p>"
            "<div>"
            + _tag_link("certstream-server-go", "https://github.com/d-Rickyy-b/certstream-server-go")
            + _tag_link("Redpanda Cloud", "https://redpanda.com/")
            + _tag_link("confluent-kafka", "https://github.com/confluentinc/confluent-kafka-python")
            + _tag_link("rapidfuzz", "https://github.com/rapidfuzz/RapidFuzz")
            + _tag_link(
                "PyFlink (reference job)",
                "https://nightlies.apache.org/flink/flink-docs-release-1.19/docs/dev/python/overview/",
            )
            + "</div></div>"
            "<div class='card'>"
            "<h3>Batch</h3>"
            "<p class='tagline'>Kestra schedules the daily refresh: six dlt "
            "pipelines load raw feeds into MotherDuck, then dbt transforms "
            "staging views into pre-aggregated marts that back the dashboard.</p>"
            "<div>"
            + _tag_link("Kestra", "https://kestra.io/")
            + _tag_link("dlt", "https://dlthub.com/")
            + _tag_link("dbt-duckdb", "https://github.com/duckdb/dbt-duckdb")
            + _tag_link("MotherDuck", "https://motherduck.com/")
            + "</div></div>",
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            "<div class='card'>"
            "<h3>Dashboard and CI/CD</h3>"
            "<p class='tagline'>Streamlit Cloud hosts this page and reads "
            "pre-aggregated marts straight from MotherDuck. GitHub Actions runs "
            "ruff, pytest and dbt parse on every push, and re-deploys the four "
            "Python services plus Kestra to Fly.io when anything under "
            "<span class='tag'>streaming/</span>, <span class='tag'>batch/</span>, "
            "<span class='tag'>kestra/</span> or <span class='tag'>dbt/</span> "
            "changes.</p>"
            "<div>"
            + _tag_link("Streamlit Cloud", "https://streamlit.io/cloud")
            + _tag_link("Plotly", "https://plotly.com/python/")
            + _tag_link("GitHub Actions", "https://github.com/pavel-kalmykov/phishing-radar/actions")
            + _tag_link("Fly.io", "https://fly.io/")
            + "</div></div>"
            "<div class='card'>"
            "<h3>Data sources</h3>"
            "<p class='tagline'>All public, all free:</p>"
            "<div>"
            + _tag_link("Certificate Transparency logs", "https://certificate.transparency.dev/")
            + _tag_link("CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
            + _tag_link("abuse.ch Feodo Tracker", "https://feodotracker.abuse.ch/")
            + _tag_link("abuse.ch ThreatFox", "https://threatfox.abuse.ch/")
            + _tag_link("Spamhaus DROP / EDROP", "https://www.spamhaus.org/drop/")
            + _tag_link("MITRE ATT&amp;CK", "https://attack.mitre.org/")
            + _tag_link("MaxMind GeoLite2", "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
            + "</div>"
            "<p class='tagline' style='margin-top:0.9rem;'>Source on "
            "<a href='https://github.com/pavel-kalmykov/phishing-radar'>GitHub</a>. "
            "Data Engineering Zoomcamp 2026.</p>"
            "</div>",
            unsafe_allow_html=True,
        )


# =============================================================================
# FOOTER
# =============================================================================

st.markdown(
    "<div class='footer'>"
    "<span>Phishing Radar &middot; capstone for the "
    "<a href='https://github.com/DataTalksClub/data-engineering-zoomcamp'>"
    "DataTalksClub Data Engineering Zoomcamp 2026</a> by "
    "<a href='https://github.com/pavel-kalmykov'>@pavel-kalmykov</a>.</span>"
    "<span>Data from public feeds; nothing here is actionable attribution. "
    "See the source on "
    "<a href='https://github.com/pavel-kalmykov/phishing-radar'>GitHub</a>.</span>"
    "</div>",
    unsafe_allow_html=True,
)
