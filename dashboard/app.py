"""Phishing Radar dashboard.

Operational view over MotherDuck. Uses st.tabs so navigation can never
collapse into invisibility, renders every block inside a card panel, reads
from pre-aggregated dbt marts, and exposes a sticky filter bar so every
widget responds to the same slice of time, brand and CA.

See docs/detection_alternatives.md for the rationale behind the detector's
similarity rules.
"""

from __future__ import annotations

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


@st.cache_data(ttl=300)
def run_query(sql: str, params: tuple | None = None) -> pd.DataFrame:
    if params:
        return get_conn().execute(sql, params).df()
    return get_conn().execute(sql).df()


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

  .kpi-grid {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 0.75rem; margin: 0.6rem 0 1.2rem 0; }}
  .kpi {{
    background: {BG_CARD}; border: 1px solid {BORDER}; border-radius: 10px;
    padding: 0.95rem 1rem; position: relative; overflow: hidden;
  }}
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
    gap: 0; background: {BG_CARD}; border: 1px solid {BORDER};
    border-radius: 10px; padding: 0.35rem; margin-bottom: 1rem;
  }}
  .stTabs [data-baseweb="tab"] {{
    background: transparent; color: {TEXT_MUTED}; border: none;
    padding: 0.55rem 1.1rem; border-radius: 7px; font-weight: 500;
    font-size: 0.92rem;
  }}
  .stTabs [data-baseweb="tab"]:hover {{ background: rgba(0,229,255,0.06); color: {TEXT}; }}
  .stTabs [aria-selected="true"] {{ background: {BG_RAISED} !important; color: {TEXT} !important;
    box-shadow: 0 0 0 1px {ACCENT_VIOLET}44, 0 0 12px {ACCENT_VIOLET}22 inset; }}
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
    "typosquatting": ("Registering a domain that is visually or phonetically close to a legitimate one."),
    "homoglyph": (
        "Two characters that look identical or near-identical to a human reader "
        "(0 vs o, 1 vs l, Cyrillic а vs Latin a)."
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


# ISO-2 to ISO-3 and country centroid. Used to render the C2 map: per country
# we plot one dot sized by the count, placed at the country centroid so the
# geography reads even with <200 IPs. Only the countries we actually see.
COUNTRY_META = {
    "AE": ("ARE", "United Arab Emirates", 23.4, 53.8),
    "AR": ("ARG", "Argentina", -38.4, -63.6),
    "AT": ("AUT", "Austria", 47.5, 14.5),
    "AU": ("AUS", "Australia", -25.0, 133.0),
    "BR": ("BRA", "Brazil", -14.2, -51.9),
    "CA": ("CAN", "Canada", 56.1, -106.3),
    "CH": ("CHE", "Switzerland", 46.8, 8.2),
    "CN": ("CHN", "China", 35.9, 104.2),
    "CZ": ("CZE", "Czechia", 49.8, 15.5),
    "DE": ("DEU", "Germany", 51.2, 10.4),
    "DK": ("DNK", "Denmark", 56.3, 9.5),
    "ES": ("ESP", "Spain", 40.5, -3.7),
    "FI": ("FIN", "Finland", 61.9, 25.7),
    "FR": ("FRA", "France", 46.2, 2.2),
    "GB": ("GBR", "United Kingdom", 55.4, -3.4),
    "HK": ("HKG", "Hong Kong", 22.3, 114.2),
    "ID": ("IDN", "Indonesia", -0.8, 113.9),
    "IE": ("IRL", "Ireland", 53.4, -8.2),
    "IL": ("ISR", "Israel", 31.0, 34.9),
    "IN": ("IND", "India", 20.6, 78.9),
    "IT": ("ITA", "Italy", 41.9, 12.6),
    "JP": ("JPN", "Japan", 36.2, 138.3),
    "KR": ("KOR", "South Korea", 35.9, 127.8),
    "LU": ("LUX", "Luxembourg", 49.8, 6.1),
    "MX": ("MEX", "Mexico", 23.6, -102.5),
    "NL": ("NLD", "Netherlands", 52.1, 5.3),
    "NO": ("NOR", "Norway", 60.5, 8.5),
    "NZ": ("NZL", "New Zealand", -40.9, 174.9),
    "PA": ("PAN", "Panama", 8.5, -80.8),
    "PH": ("PHL", "Philippines", 12.9, 121.8),
    "PL": ("POL", "Poland", 51.9, 19.1),
    "PT": ("PRT", "Portugal", 39.4, -8.2),
    "RO": ("ROU", "Romania", 45.9, 24.9),
    "RU": ("RUS", "Russia", 61.5, 105.3),
    "SA": ("SAU", "Saudi Arabia", 23.9, 45.1),
    "SC": ("SYC", "Seychelles", -4.7, 55.5),
    "SE": ("SWE", "Sweden", 60.1, 18.6),
    "SG": ("SGP", "Singapore", 1.4, 103.8),
    "TH": ("THA", "Thailand", 15.9, 100.9),
    "TR": ("TUR", "Turkey", 38.9, 35.2),
    "TW": ("TWN", "Taiwan", 23.7, 121.0),
    "UA": ("UKR", "Ukraine", 48.4, 31.2),
    "US": ("USA", "United States", 37.1, -95.7),
    "VN": ("VNM", "Vietnam", 14.1, 108.3),
    "ZA": ("ZAF", "South Africa", -30.6, 22.9),
}


# =============================================================================
# QUERIES
# =============================================================================
#
# Everything the dashboard reads is either a pre-aggregated mart (dbt-built,
# refreshed daily) or a small slice of stg_suspicious_certs filtered by the
# global filter bar.


@st.cache_data(ttl=300)
def q_kpis() -> dict[str, Any]:
    return run_query(f"select * from {MD_DATABASE}.mart_dashboard_kpis").iloc[0].to_dict()


@st.cache_data(ttl=300)
def q_c2_by_country() -> pd.DataFrame:
    return run_query(f"select * from {MD_DATABASE}.mart_dashboard_c2_by_country")


@st.cache_data(ttl=300)
def q_c2_active_rows() -> pd.DataFrame:
    return run_query(f"""
        select ip_address, port, malware_family, country, as_name, source,
               first_seen, last_seen
        from {MD_DATABASE}.mart_c2_active
        order by last_seen desc nulls last
    """)


@st.cache_data(ttl=300)
def q_c2_by_malware() -> pd.DataFrame:
    return run_query(f"""
        select malware_family, count(*) as active_c2
        from {MD_DATABASE}.mart_c2_active
        where malware_family is not null
        group by 1 order by active_c2 desc
    """)


@st.cache_data(ttl=300)
def q_kev_monthly() -> pd.DataFrame:
    return run_query(f"select * from {MD_DATABASE}.mart_dashboard_kev_monthly")


@st.cache_data(ttl=300)
def q_kev_vendors() -> pd.DataFrame:
    return run_query(f"select * from {MD_DATABASE}.mart_dashboard_kev_vendors")


@st.cache_data(ttl=300)
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


@st.cache_data(ttl=600)
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
    f"<p class='subtitle'>Every phishing site needs a TLS certificate. We tail the "
    f"{tip('CT', 'Certificate Transparency')} firehose, flag impersonations, and cross-reference "
    f"against live malware infrastructure.</p>",
    unsafe_allow_html=True,
)


def _kpi(klass: str, value: int, label: str) -> str:
    return f"<div class='kpi {klass}'><div class='value'>{value:,}</div><div class='label'>{label}</div></div>"


st.markdown(
    "<div class='kpi-grid'>"
    + _kpi("pink", int(kpis["kev_total"]), "CVEs actively exploited")
    + _kpi("gold", int(kpis["kev_ransomware"]), "Used by ransomware")
    + _kpi("cyan", int(kpis["c2_total"]), "Online botnet C2s")
    + _kpi("violet", int(kpis["c2_countries"]), "Countries hosting C2s")
    + _kpi("green", int(kpis["malware_total"]), "Malware in MITRE")
    + _kpi("pink", int(kpis["suspicious_total"]), "Phishing certs seen")
    + "</div>",
    unsafe_allow_html=True,
)


st.markdown(
    "<p class='intro'>"
    "A modern phishing kit needs three things: a look-alike domain, a TLS cert so "
    "browsers don&rsquo;t panic, and somewhere to host the landing page. The domain and "
    "the cert are the two things we can see before the first email ever leaves. "
    "Public CT logs make it inevitable: every certificate issued has to be written to "
    "an append-only, cryptographically verifiable log. This report tails that firehose "
    "in real time and lines the findings up against what the rest of the criminal "
    "ecosystem is doing today."
    "</p>",
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
            marker=dict(color=c2_mal["active_c2"], colorscale=[[0, ACCENT_VIOLET], [1, ACCENT_CYAN]]),
            customdata=c2_mal[["tooltip"]].values,
            hovertemplate="<b>%{y}</b><br>%{x} active C2s<br><i>%{customdata[0]}</i><extra></extra>",
        )
    )
    fig.update_layout(height=height, **CHART)
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
  <h3>The streaming lane</h3>
  <p class='tagline'>A producer pulls every cert from CT logs, a Python detector scores each
  domain against a short list of popular brands using {tip("homoglyph")} normalisation,
  substring matching and {tip("typosquatting")} (Damerau-Levenshtein 1&ndash;2 plus
  Jaro-Winkler), and writes the hits to MotherDuck.</p>
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
  <h3>The batch lane</h3>
  <p class='tagline'>Six threat-intel feeds (CISA {tip("KEV")}, abuse.ch Feodo Tracker,
  abuse.ch ThreatFox, Spamhaus {tip("DROP")}, MITRE ATT&amp;CK, MaxMind GeoLite2) refresh
  daily via Kestra, land in MotherDuck through <span class='tag'>dlt</span>, and dbt
  materialises them into the marts this dashboard reads.</p>
  <p class='tagline' style='margin-top:0.5rem;'>Active C2 servers by malware family (hover for context):</p>
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
            """
<div class='card'>
  <h3>Suspicious certs over time</h3>
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
  <h3>Top issuing {tip("CA", "CAs")}</h3>
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
        """
<div class='card'>
  <h3>Latest flagged certificates</h3>
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
  <h3>KEV monthly additions</h3>
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
            """
<div class='card'>
  <h3>Hijacked IP ranges</h3>
  <p class='tagline'>Spamhaus bucketizes hijacked CIDRs by prefix length. Small blocks
  (/24 and below) dominate; attackers prefer splatter over single big takeovers.</p>
</div>
""",
            unsafe_allow_html=True,
        )
        spam = q_spamhaus_buckets()
        if not spam.empty:
            fig = px.bar(
                spam,
                x="block_size_bucket",
                y="block_count",
                color="list",
                color_discrete_map={"drop": ACCENT_PINK, "edrop": ACCENT_GOLD},
                barmode="group",
            )
            fig.update_layout(height=300, **CHART)
            fig.update_xaxes(title_text="")
            fig.update_yaxes(title_text="")
            st.plotly_chart(fig, use_container_width=True, key="batch_spamhaus")
        st.markdown(
            "<div class='source'>mart_spamhaus_by_country &middot; DROP + EDROP lists.</div>",
            unsafe_allow_html=True,
        )

    col1, col2 = st.columns([1, 1])
    with col1:
        st.markdown(
            """
<div class='card'>
  <h3>Top KEV vendors</h3>
  <p class='tagline'>Bar length is total CVEs in KEV; colour intensity is the
  percent of those linked to ransomware operations. High ratio matters more
  than high count.</p>
</div>
""",
            unsafe_allow_html=True,
        )
        kev_vendors = q_kev_vendors()
        if not kev_vendors.empty:
            fig = go.Figure(
                go.Bar(
                    x=kev_vendors["cves"],
                    y=kev_vendors["vendor"],
                    orientation="h",
                    marker=dict(
                        color=kev_vendors["ransomware_ratio_pct"],
                        colorscale=[[0, ACCENT_VIOLET], [1, ACCENT_PINK]],
                        cmin=0,
                        cmax=max(20, kev_vendors["ransomware_ratio_pct"].max()),
                        colorbar=dict(
                            title=dict(text="% ransomware", font=dict(color=TEXT_MUTED, size=10)),
                            tickfont=dict(color=TEXT_MUTED, size=9),
                            thickness=10,
                            len=0.7,
                            outlinewidth=0,
                            bgcolor="rgba(0,0,0,0)",
                        ),
                    ),
                    customdata=kev_vendors[["ransomware_linked", "ransomware_ratio_pct"]].values,
                    hovertemplate=(
                        "<b>%{y}</b><br>%{x} CVEs in KEV<br>"
                        "%{customdata[0]} tied to ransomware (%{customdata[1]:.1f}%)<extra></extra>"
                    ),
                )
            )
            fig.update_layout(height=400, **CHART)
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
  <h3>Active C2s by hosting country</h3>
  <p class='tagline'>Countries where the actual {tip("C2")} servers sit. Not the same as
  attribution: hosting is fluid and most abuse lives in permissive transit networks.</p>
</div>
""",
            unsafe_allow_html=True,
        )
        c2_country = q_c2_by_country()
        if not c2_country.empty:
            top = c2_country[c2_country["country"] != "(unknown)"].head(15)
            top["tooltip"] = top["top_family"].map(malware_tooltip)
            fig = go.Figure(
                go.Bar(
                    x=top["active_c2"],
                    y=top["country"],
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
  <h3>Where the C2 servers live</h3>
  <p class='tagline'>Every dot is a country currently hosting at least one
  tracked {tip("C2")} server. Dot size scales with the number of active C2s,
  colour with the dominant malware family. Hosting country is a noisy signal
  (hosting is cheap and fluid, attribution belongs to the operators not the
  servers) but it still paints a useful picture: attackers cluster where
  transit is permissive, bulletproof providers tolerate them and takedown
  notices are slow to land.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    c2_country = q_c2_by_country()
    mappable = c2_country[c2_country["country"].isin(COUNTRY_META.keys())].copy()
    unmapped = c2_country[~c2_country["country"].isin(COUNTRY_META.keys())].copy()
    if mappable.empty:
        st.info("No geolocated C2s right now.")
    else:
        mappable["iso3"] = mappable["country"].map(lambda c: COUNTRY_META[c][0])
        mappable["country_name"] = mappable["country"].map(lambda c: COUNTRY_META[c][1])
        mappable["lat"] = mappable["country"].map(lambda c: COUNTRY_META[c][2])
        mappable["lon"] = mappable["country"].map(lambda c: COUNTRY_META[c][3])
        mappable["top_family_display"] = mappable["top_family"].fillna("(unknown)")
        mappable["tooltip"] = mappable["top_family"].map(malware_tooltip)

        fig = go.Figure(
            go.Scattergeo(
                lon=mappable["lon"],
                lat=mappable["lat"],
                text=mappable["country_name"],
                customdata=mappable[["active_c2", "top_family_display", "tooltip", "sources"]].values,
                marker=dict(
                    size=mappable["active_c2"],
                    sizemode="area",
                    sizeref=2.0 * mappable["active_c2"].max() / (60.0**2),
                    sizemin=6,
                    color=mappable["active_c2"],
                    colorscale=[[0, ACCENT_VIOLET], [0.5, ACCENT_PINK], [1, ACCENT_GOLD]],
                    line=dict(color=ACCENT_CYAN, width=1),
                    opacity=0.85,
                    colorbar=dict(
                        title=dict(text="Active C2s", font=dict(color=TEXT_MUTED, size=11)),
                        tickfont=dict(color=TEXT_MUTED, size=10),
                        thickness=12,
                        len=0.7,
                        outlinewidth=0,
                        bgcolor="rgba(0,0,0,0)",
                    ),
                ),
                hovertemplate=(
                    "<b>%{text}</b><br>%{customdata[0]} active C2s<br>"
                    "Top family: %{customdata[1]}<br><i>%{customdata[2]}</i><br>"
                    "Sources: %{customdata[3]}<extra></extra>"
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
        )
        st.plotly_chart(fig, use_container_width=True, key="map_c2_scatter")

        col1, col2 = st.columns([1, 1])
        with col1:
            st.markdown(
                "<div class='card'><h3>Top countries</h3><p class='tagline'>Raw numbers behind the map.</p></div>",
                unsafe_allow_html=True,
            )
            st.dataframe(
                mappable.rename(
                    columns={
                        "country_name": "Country",
                        "active_c2": "Active C2s",
                        "top_family_display": "Top family",
                        "sources": "Sources",
                    }
                )[["Country", "Active C2s", "Top family", "Sources"]].head(20),
                use_container_width=True,
                hide_index=True,
                height=380,
            )
        with col2:
            if not unmapped.empty:
                st.markdown(
                    "<div class='card'><h3>Unmapped</h3>"
                    "<p class='tagline'>Countries the feed reports without an ISO centroid in "
                    "our dict (usually tiny or edge-case territories), plus ThreatFox rows "
                    "whose IP didn&rsquo;t match any GeoLite2 block.</p></div>",
                    unsafe_allow_html=True,
                )
                unmapped_view = unmapped.rename(columns={"country": "Country", "active_c2": "Active C2s"})[
                    ["Country", "Active C2s"]
                ]
                st.dataframe(
                    unmapped_view,
                    use_container_width=True,
                    hide_index=True,
                    height=240,
                )
        st.markdown(
            "<div class='source'>"
            "mart_dashboard_c2_by_country &middot; lat/lon from country centroids "
            "(one dot per country)."
            "</div>",
            unsafe_allow_html=True,
        )


# =============================================================================
# TAB: STACK
# =============================================================================

with tab_about:
    col1, col2 = st.columns([1, 1])
    with col1:
        st.markdown(
            """
<div class='card'>
  <h3>Streaming</h3>
  <p class='tagline'>Five always-on Fly.io machines: a self-hosted certstream-server-go
  aggregates the CT firehose, a Python producer pushes events to Redpanda Cloud, a
  detector enriches and windows them, a sink lands everything into MotherDuck.</p>
  <div>
    <span class='tag'>certstream-server-go</span>
    <span class='tag'>Redpanda Cloud</span>
    <span class='tag'>confluent-kafka</span>
    <span class='tag'>rapidfuzz</span>
    <span class='tag'>PyFlink (reference job)</span>
  </div>
</div>
<div class='card'>
  <h3>Batch</h3>
  <p class='tagline'>Kestra schedules the daily refresh: six ingestion pipelines
  load raw feeds into MotherDuck through <span class='tag'>dlt</span>, then dbt
  transforms staging views into pre-aggregated marts that back the dashboard.</p>
  <div>
    <span class='tag'>Kestra</span>
    <span class='tag'>dlt</span>
    <span class='tag'>dbt-duckdb</span>
    <span class='tag'>MotherDuck</span>
  </div>
</div>
""",
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            """
<div class='card'>
  <h3>Dashboard and CI/CD</h3>
  <p class='tagline'>Streamlit Cloud hosts this page and reads pre-aggregated marts
  straight from MotherDuck. GitHub Actions runs ruff, pytest and dbt parse on every
  push, and re-deploys the four Python services to Fly.io when anything under
  <span class='tag'>streaming/</span> or <span class='tag'>batch/</span> changes.</p>
  <div>
    <span class='tag'>Streamlit Cloud</span>
    <span class='tag'>plotly</span>
    <span class='tag'>GitHub Actions</span>
    <span class='tag'>Fly.io</span>
  </div>
</div>
<div class='card'>
  <h3>Data sources</h3>
  <p class='tagline'>All public, all free:</p>
  <div>
    <span class='tag'>Certificate Transparency logs</span>
    <span class='tag'>CISA KEV</span>
    <span class='tag'>abuse.ch Feodo Tracker</span>
    <span class='tag'>abuse.ch ThreatFox</span>
    <span class='tag'>Spamhaus DROP / EDROP</span>
    <span class='tag'>MITRE ATT&amp;CK</span>
    <span class='tag'>MaxMind GeoLite2</span>
  </div>
  <p class='tagline' style='margin-top:0.9rem;'>Source on
  <a href='https://github.com/pavel-kalmykov/phishing-radar'>GitHub</a>.
  Data Engineering Zoomcamp 2026.</p>
</div>
""",
            unsafe_allow_html=True,
        )
