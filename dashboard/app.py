"""Phishing Radar dashboard.

Card-based operational view with horizontal tabs. Reads straight from
MotherDuck. Deliberately uses `st.tabs` instead of a sidebar so the navigation
cannot be collapsed into invisibility, and renders everything in `st.columns`
panels so it reads as a dashboard rather than a long-form article.
"""
from __future__ import annotations

import os
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
def run_query(sql: str) -> pd.DataFrame:
    return get_conn().execute(sql).df()


# =============================================================================
# STYLE
# =============================================================================

BG = "#0a0f1c"
BG_CARD = "#111a2e"
BG_RAISED = "#18223a"
BORDER = "#243153"
TEXT = "#e2e8f0"
TEXT_MUTED = "#94a3b8"
TEXT_DIM = "#64748b"

ACCENT_TEAL = "#22d3ee"
ACCENT_CORAL = "#fb7185"
ACCENT_AMBER = "#fbbf24"
ACCENT_LAVENDER = "#a78bfa"
ACCENT_MINT = "#34d399"

st.markdown(
    f"""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@500;700&display=swap');

  header[data-testid="stHeader"] {{ display: none; }}
  [data-testid="stSidebar"] {{ display: none; }}
  [data-testid="collapsedControl"] {{ display: none; }}
  [data-testid="stApp"] {{ background: {BG}; }}
  html, body, [data-testid="stApp"] {{ font-family: 'Inter', sans-serif; color: {TEXT}; }}
  .block-container {{ padding: 1.6rem 2rem 2.6rem !important; max-width: 1280px !important; }}

  h1, h2, h3 {{ font-family: 'Inter', sans-serif; letter-spacing: -0.02em; }}
  h1 {{ font-weight: 700 !important; font-size: 2.2rem !important; margin: 0 0 0.2rem 0 !important; }}
  h2 {{ font-weight: 600 !important; font-size: 1.3rem !important; margin: 1.6rem 0 0.6rem 0 !important; }}

  p, li {{ color: {TEXT_MUTED}; font-size: 0.95rem; line-height: 1.55; }}
  a {{ color: {ACCENT_TEAL}; text-decoration: none; border-bottom: 1px dotted {ACCENT_TEAL}; }}

  abbr[title] {{
    text-decoration: none;
    border-bottom: 1px dashed {ACCENT_LAVENDER};
    cursor: help; color: {TEXT};
  }}

  .subtitle {{ color: {TEXT_MUTED}; font-size: 0.98rem; margin: 0 0 1.3rem 0; }}

  .kpi-grid {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 0.75rem; margin: 0.6rem 0 1.2rem 0; }}
  .kpi {{
    background: {BG_CARD}; border: 1px solid {BORDER}; border-radius: 10px;
    padding: 0.95rem 1rem;
  }}
  .kpi .value {{ font-family: 'IBM Plex Mono', monospace; font-size: 1.6rem; font-weight: 700; line-height: 1.15; letter-spacing: -0.02em; }}
  .kpi .label {{ color: {TEXT_DIM}; font-size: 0.7rem; letter-spacing: 0.1em; text-transform: uppercase; margin-top: 0.3rem; }}
  .kpi.teal .value {{ color: {ACCENT_TEAL}; }}
  .kpi.coral .value {{ color: {ACCENT_CORAL}; }}
  .kpi.amber .value {{ color: {ACCENT_AMBER}; }}
  .kpi.lavender .value {{ color: {ACCENT_LAVENDER}; }}
  .kpi.mint .value {{ color: {ACCENT_MINT}; }}

  .card {{
    background: {BG_CARD}; border: 1px solid {BORDER}; border-radius: 10px;
    padding: 1rem 1.1rem; margin-bottom: 0.8rem;
  }}
  .card h3 {{ font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.1em;
              color: {TEXT_DIM}; margin: 0 0 0.5rem 0; font-weight: 600; }}
  .card .tagline {{ color: {TEXT_MUTED}; font-size: 0.88rem; margin: 0 0 0.5rem 0; }}

  .source {{
    font-family: 'IBM Plex Mono', monospace; font-size: 0.72rem;
    color: {TEXT_DIM}; margin: 0.3rem 0 0 0; letter-spacing: 0.02em;
  }}

  .tag {{
    display: inline-block; background: {BG_RAISED}; color: {TEXT_MUTED};
    font-family: 'IBM Plex Mono', monospace; font-size: 0.72rem;
    padding: 0.18rem 0.55rem; border-radius: 4px;
    border: 1px solid {BORDER}; margin: 0.15rem 0.25rem 0.15rem 0;
  }}

  .malware-card {{
    background: {BG_CARD}; border: 1px solid {BORDER};
    padding: 0.7rem 0.9rem; margin-bottom: 0.55rem; border-radius: 8px;
  }}
  .malware-card .name {{ color: {ACCENT_CORAL}; font-family: 'IBM Plex Mono', monospace;
                        font-weight: 700; font-size: 0.9rem; }}
  .malware-card .desc {{ color: {TEXT_MUTED}; font-size: 0.85rem; margin-top: 0.2rem; line-height: 1.45; }}

  /* Tabs restyle */
  .stTabs [data-baseweb="tab-list"] {{
    gap: 0; background: {BG_CARD}; border: 1px solid {BORDER};
    border-radius: 10px; padding: 0.35rem; margin-bottom: 1rem;
  }}
  .stTabs [data-baseweb="tab"] {{
    background: transparent; color: {TEXT_MUTED}; border: none;
    padding: 0.55rem 1.1rem; border-radius: 7px; font-weight: 500;
    font-size: 0.92rem;
  }}
  .stTabs [data-baseweb="tab"]:hover {{ background: rgba(34,211,238,0.06); color: {TEXT}; }}
  .stTabs [aria-selected="true"] {{ background: {BG_RAISED} !important; color: {TEXT} !important; }}
  .stTabs [data-baseweb="tab-highlight"] {{ display: none; }}
  .stTabs [data-baseweb="tab-border"] {{ display: none; }}

  /* Dataframe */
  [data-testid="stDataFrame"] {{
    border: 1px solid {BORDER}; border-radius: 10px; overflow: hidden;
  }}
</style>
""",
    unsafe_allow_html=True,
)


CHART = dict(
    plot_bgcolor=BG_CARD,
    paper_bgcolor=BG_CARD,
    font=dict(color=TEXT, family="Inter", size=11),
    margin=dict(l=10, r=10, t=10, b=30),
    xaxis=dict(gridcolor="rgba(255,255,255,0.04)", zerolinecolor=BORDER),
    yaxis=dict(gridcolor="rgba(255,255,255,0.04)", zerolinecolor=BORDER),
    legend=dict(bgcolor="rgba(0,0,0,0)", bordercolor=BORDER, borderwidth=1, font=dict(size=10)),
)


# =============================================================================
# DOMAIN KNOWLEDGE
# =============================================================================

GLOSSARY = {
    "CT": "Certificate Transparency. An open, append-only log system that every public TLS certificate has to be written to.",
    "SAN": "Subject Alternative Name. The cert field that lists every hostname a certificate is valid for.",
    "CA": "Certificate Authority. The organisation that signs and issues TLS certificates.",
    "CVE": "Common Vulnerabilities and Exposures. The global ID for a publicly disclosed security flaw.",
    "KEV": "Known Exploited Vulnerabilities. CISA's catalogue of CVEs with evidence of active exploitation.",
    "C2": "Command and Control. The server a malware implant calls home to for instructions.",
    "CIDR": "Classless Inter-Domain Routing. The /24, /16 notation that describes an IP range.",
    "DROP": "Don't Route Or Peer. Spamhaus's list of IP ranges that transit providers should drop entirely.",
    "TLD": "Top-Level Domain. The rightmost label of a hostname (.com, .org, .co.uk).",
    "SLD": "Second-Level Domain. The label immediately to the left of the TLD.",
    "typosquatting": "Registering a domain that is visually or phonetically close to a legitimate one.",
    "homoglyph": "Two characters that look identical or near-identical to a human reader (0 vs o, 1 vs l).",
}

MALWARE_DESCRIPTIONS = {
    "emotet": "Banking trojan turned malware distribution platform. Takedown in 2021, back in late 2021.",
    "heodo": "abuse.ch alias for Emotet variants.",
    "qakbot": "Qbot/Pinkslipbot. Banking trojan and loader; common entry point for Conti and Black Basta ransomware.",
    "trickbot": "Modular banking trojan turned ransomware loader (Ryuk, Conti). Disrupted 2020; fragments remain.",
    "icedid": "BokBot. Info stealer and loader, delivered through malicious Office docs and ZIPs.",
    "dridex": "Long-running banking trojan tied to Evil Corp. Macro-enabled Office documents plus later-stage payloads.",
    "cobaltstrike": "Commercial adversary simulation toolkit. Cracked versions are ubiquitous in ransomware ops.",
    "bumblebee": "Loader family from 2022, suspected Qakbot successor. Linked to Conti-era operators.",
    "remcos": "Commercial RAT sold as legit admin software. Abused by low-effort phishing campaigns.",
    "asyncrat": "Open-source RAT, trivial to deploy. Commonly dropped by commodity loaders.",
    "njrat": "Long-lived commodity RAT, popular in the Middle East. Cheap, feature-rich, mass-deployed.",
    "formbook": "Info stealer sold as MaaS. Harvests credentials from browsers and email clients.",
    "lokibot": "Credential stealer, targets browsers, FTP clients, crypto wallets.",
    "agenttesla": "Keylogger + stealer, distributed through phishing attachments targeting SMEs.",
    "pikabot": "Loader that emerged in 2023 as a suspected Qakbot successor. Associated with Black Basta.",
}


def tip(term: str, label: str | None = None) -> str:
    desc = GLOSSARY.get(term, "")
    text = label or term
    return f'<abbr title="{desc}">{text}</abbr>' if desc else text


# =============================================================================
# QUERIES
# =============================================================================

def q_counts() -> dict[str, Any]:
    return run_query(f"""
        select
          (select count(*) from {MD_DATABASE}.mart_kev_pulse) as kev_total,
          (select count(*) filter (where known_ransomware_use = 'Known') from {MD_DATABASE}.mart_kev_pulse) as kev_ransomware,
          (select count(*) from {MD_DATABASE}.mart_c2_active) as c2_total,
          (select count(*) from {MD_DATABASE}.stg_spamhaus) as spam_total,
          (select count(*) from {MD_DATABASE}.mart_mitre_malware_catalog) as malware_total,
          (select count(*) from {MD_DATABASE}.stg_suspicious_certs) as suspicious_total
    """).iloc[0].to_dict()


def q_top_brands() -> pd.DataFrame:
    return run_query(f"""
        select brand, count(*) as hits
        from (
          select s.seen_at_ts, json_extract_string(d.value, '$.brand') as brand
          from {MD_DATABASE}.stg_suspicious_certs s,
          lateral (select unnest(from_json(s.detections_raw::varchar, '[\"json\"]')) as value) d
        )
        where brand is not null
        group by 1 order by hits desc limit 12
    """)


def q_recent_suspicious() -> pd.DataFrame:
    return run_query(f"""
        select seen_at_ts, primary_domain, issuer_cn, max_score
        from {MD_DATABASE}.stg_suspicious_certs
        where seen_at_ts is not null
        order by seen_at_ts desc limit 20
    """)


def q_suspicious_over_time() -> pd.DataFrame:
    return run_query(f"""
        select date_trunc('hour', seen_at_ts) as hour, count(*) as flagged
        from {MD_DATABASE}.stg_suspicious_certs
        where seen_at_ts is not null
        group by 1 order by 1
    """)


def q_top_issuers() -> pd.DataFrame:
    return run_query(f"""
        select coalesce(issuer_cn, '(unknown)') as issuer, count(*) as hits
        from {MD_DATABASE}.stg_suspicious_certs
        group by 1 order by hits desc limit 10
    """)


def q_kev_by_vendor() -> pd.DataFrame:
    return run_query(f"""
        select vendor, count(*) as cves,
               count(*) filter (where known_ransomware_use = 'Known') as ransomware_linked
        from {MD_DATABASE}.mart_kev_pulse
        where vendor is not null
        group by 1 order by cves desc limit 12
    """)


def q_kev_monthly() -> pd.DataFrame:
    return run_query(f"""
        select date_trunc('month', date_added) as month, count(*) as additions
        from {MD_DATABASE}.mart_kev_pulse
        where date_added is not null
        group by 1 order by 1
    """)


def q_c2_by_malware() -> pd.DataFrame:
    return run_query(f"""
        select malware_family, count(*) as active_c2
        from {MD_DATABASE}.mart_c2_active
        group by 1 order by active_c2 desc
    """)


def q_c2_by_country() -> pd.DataFrame:
    return run_query(f"""
        select country, count(*) as active_c2
        from {MD_DATABASE}.mart_c2_active
        where country is not null
        group by 1 order by active_c2 desc
    """)


# ISO-2 to ISO-3 so plotly's choropleth can colour-code every country the C2
# feed mentions without a separate dependency. Only the ones we actually see.
_ISO2_TO_ISO3 = {
    "AR": "ARG", "AT": "AUT", "AU": "AUS", "BA": "BIH", "BE": "BEL", "BG": "BGR",
    "BR": "BRA", "CA": "CAN", "CH": "CHE", "CL": "CHL", "CN": "CHN", "CO": "COL",
    "CY": "CYP", "CZ": "CZE", "DE": "DEU", "DK": "DNK", "EE": "EST", "ES": "ESP",
    "FI": "FIN", "FR": "FRA", "GB": "GBR", "GR": "GRC", "HK": "HKG", "HR": "HRV",
    "HU": "HUN", "ID": "IDN", "IE": "IRL", "IL": "ISR", "IN": "IND", "IR": "IRN",
    "IS": "ISL", "IT": "ITA", "JP": "JPN", "KE": "KEN", "KR": "KOR", "KZ": "KAZ",
    "LT": "LTU", "LU": "LUX", "LV": "LVA", "MD": "MDA", "MX": "MEX", "MY": "MYS",
    "NG": "NGA", "NL": "NLD", "NO": "NOR", "NZ": "NZL", "PA": "PAN", "PE": "PER",
    "PH": "PHL", "PL": "POL", "PT": "PRT", "RO": "ROU", "RS": "SRB", "RU": "RUS",
    "SA": "SAU", "SE": "SWE", "SG": "SGP", "SI": "SVN", "SK": "SVK", "TH": "THA",
    "TR": "TUR", "TW": "TWN", "UA": "UKR", "US": "USA", "VN": "VNM", "ZA": "ZAF",
}


def q_spamhaus_buckets() -> pd.DataFrame:
    return run_query(f"select * from {MD_DATABASE}.mart_spamhaus_by_country")


# =============================================================================
# RENDER
# =============================================================================

counts = q_counts()


st.markdown("<h1>Phishing Radar</h1>", unsafe_allow_html=True)
st.markdown(
    f"<p class='subtitle'>Every phishing site needs a TLS certificate. We tail the "
    f"{tip('CT', 'Certificate Transparency')} firehose, flag impersonations, and cross-reference "
    f"against live malware infrastructure.</p>",
    unsafe_allow_html=True,
)


st.markdown(
    f"""
<div class='kpi-grid'>
  <div class='kpi coral'><div class='value'>{int(counts['kev_total']):,}</div><div class='label'>CVEs actively exploited</div></div>
  <div class='kpi amber'><div class='value'>{int(counts['kev_ransomware']):,}</div><div class='label'>Used by ransomware</div></div>
  <div class='kpi teal'><div class='value'>{int(counts['c2_total']):,}</div><div class='label'>Online botnet C2s</div></div>
  <div class='kpi lavender'><div class='value'>{int(counts['spam_total']):,}</div><div class='label'>Hijacked IP ranges</div></div>
  <div class='kpi mint'><div class='value'>{int(counts['malware_total']):,}</div><div class='label'>Malware in MITRE</div></div>
  <div class='kpi coral'><div class='value'>{int(counts['suspicious_total']):,}</div><div class='label'>Phishing certs seen</div></div>
</div>
""",
    unsafe_allow_html=True,
)


st.markdown(
    "<p class='subtitle' style='max-width:780px; margin-bottom:1.6rem;'>"
    "A modern phishing kit needs three things: a look-alike domain, a TLS cert so "
    "browsers don&rsquo;t panic, and somewhere to host the landing page. The domain and "
    "the cert are the two things we can see before the first email ever leaves. "
    "Public CT logs make it inevitable: every certificate issued has to be written to "
    "an append-only, cryptographically verifiable log. This report tails that firehose "
    "in real time and lines the findings up against what the rest of the criminal "
    "ecosystem is doing today.</p>",
    unsafe_allow_html=True,
)

tab_overview, tab_stream, tab_batch, tab_map, tab_malware, tab_about = st.tabs(
    ["Overview", "Live phishing stream", "Threat landscape", "Map", "Malware field guide", "Stack"]
)


# -----------------------------------------------------------------------------
# TAB: OVERVIEW
# -----------------------------------------------------------------------------

with tab_overview:
    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown(
            f"""
<div class='card'>
  <h3>The streaming lane</h3>
  <p class='tagline'>A producer pulls every cert from CT logs, a Python detector scores each
  domain against a short list of popular brands using {tip('homoglyph')} normalisation,
  substring matching and {tip('typosquatting')} (Levenshtein distance 1&ndash;2),
  and writes the hits to MotherDuck.</p>
  <p class='tagline' style='margin-top:0.5rem;'>Top impersonated brands in the stream:</p>
</div>
""",
            unsafe_allow_html=True,
        )
        brands = q_top_brands()
        if brands.empty:
            st.info("Detector is warming up. Come back in a few minutes.")
        else:
            fig = go.Figure(go.Bar(
                x=brands["hits"], y=brands["brand"], orientation="h",
                marker_color=ACCENT_CORAL,
                hovertemplate="<b>%{y}</b><br>%{x} flagged certs<extra></extra>",
            ))
            fig.update_layout(height=360, **CHART)
            fig.update_yaxes(autorange="reversed")
            st.plotly_chart(fig, use_container_width=True, key="ovr_brands")

    with col2:
        st.markdown(
            f"""
<div class='card'>
  <h3>The batch lane</h3>
  <p class='tagline'>Five threat-intel feeds (CISA {tip('KEV')}, abuse.ch Feodo Tracker,
  Spamhaus {tip('DROP')}, MITRE ATT&amp;CK, MaxMind GeoLite2) refresh daily via Kestra,
  land in MotherDuck through <code>dlt</code>, and dbt materialises them into the marts
  this dashboard reads.</p>
  <p class='tagline' style='margin-top:0.5rem;'>Active C2 servers by malware family:</p>
</div>
""",
            unsafe_allow_html=True,
        )
        c2_mal = q_c2_by_malware()
        if not c2_mal.empty:
            fig = go.Figure(go.Bar(
                x=c2_mal["active_c2"], y=c2_mal["malware_family"], orientation="h",
                marker_color=ACCENT_TEAL,
            ))
            fig.update_layout(height=360, **CHART)
            fig.update_yaxes(autorange="reversed")
            st.plotly_chart(fig, use_container_width=True, key="ovr_c2")


# -----------------------------------------------------------------------------
# TAB: LIVE PHISHING STREAM
# -----------------------------------------------------------------------------

with tab_stream:
    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown(
            """
<div class='card'>
  <h3>Suspicious certs over time</h3>
  <p class='tagline'>Hourly count of flagged certificates. Spikes usually mean an
  attacker batch-registering a fleet of look-alikes.</p>
</div>
""",
            unsafe_allow_html=True,
        )
        sus_time = q_suspicious_over_time()
        if not sus_time.empty:
            fig = go.Figure(go.Scatter(
                x=sus_time["hour"], y=sus_time["flagged"], mode="lines+markers",
                line=dict(color=ACCENT_TEAL, width=2),
                marker=dict(size=4, color=ACCENT_TEAL),
                fill="tozeroy", fillcolor="rgba(34, 211, 238, 0.08)",
            ))
            fig.update_layout(height=300, **CHART)
            st.plotly_chart(fig, use_container_width=True, key="stream_time")
        st.markdown(
            "<div class='source'>stg_suspicious_certs &middot; materialised from the detector output on Redpanda Cloud.</div>",
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
<div class='card'>
  <h3>Top issuing {tip('CA', 'CAs')}</h3>
  <p class='tagline'>Which certificate authorities signed the suspicious certs. A Let&rsquo;s
  Encrypt cert for a typosquatted domain is a different story than a paid DV from DigiCert.</p>
</div>
""",
            unsafe_allow_html=True,
        )
        issuers = q_top_issuers()
        if not issuers.empty:
            fig = go.Figure(go.Bar(
                x=issuers["hits"], y=issuers["issuer"], orientation="h",
                marker_color=ACCENT_LAVENDER,
            ))
            fig.update_layout(height=300, **CHART)
            fig.update_yaxes(autorange="reversed")
            st.plotly_chart(fig, use_container_width=True, key="stream_issuers")
        st.markdown(
            "<div class='source'>Issuer names as they appear in the CT log. No aggregation of subsidiaries.</div>",
            unsafe_allow_html=True,
        )

    st.markdown(
        """
<div class='card'>
  <h3>Latest flagged certificates</h3>
  <p class='tagline'>The twenty most recent hits, straight from the detector. Not every
  row is malicious: legitimate resellers and fan sites trip the rules too.</p>
</div>
""",
        unsafe_allow_html=True,
    )
    recent = q_recent_suspicious()
    if not recent.empty:
        st.dataframe(
            recent.rename(columns={
                "seen_at_ts": "First seen",
                "primary_domain": "Domain",
                "issuer_cn": "Issuer",
                "max_score": "Score",
            }),
            use_container_width=True, hide_index=True, height=480,
        )


# -----------------------------------------------------------------------------
# TAB: THREAT LANDSCAPE
# -----------------------------------------------------------------------------

with tab_batch:
    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown(
            f"""
<div class='card'>
  <h3>KEV monthly additions</h3>
  <p class='tagline'>Every time a CVE lands in CISA&rsquo;s {tip('KEV')} catalogue, it
  means there is evidence of active exploitation in the wild. Months with spikes are
  usually ransomware-driven.</p>
</div>
""",
            unsafe_allow_html=True,
        )
        kev_monthly = q_kev_monthly()
        if not kev_monthly.empty:
            fig = go.Figure(go.Bar(
                x=kev_monthly["month"], y=kev_monthly["additions"],
                marker_color=ACCENT_AMBER,
            ))
            fig.update_layout(height=300, **CHART)
            st.plotly_chart(fig, use_container_width=True, key="batch_kev_month")
        st.markdown("<div class='source'>mart_kev_pulse &middot; refreshed daily from cisa.gov.</div>", unsafe_allow_html=True)

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
                spam, x="block_size_bucket", y="block_count", color="list",
                color_discrete_map={"drop": ACCENT_CORAL, "edrop": ACCENT_AMBER},
                barmode="group",
            )
            fig.update_layout(height=300, **CHART)
            fig.update_xaxes(title_text="")
            fig.update_yaxes(title_text="")
            st.plotly_chart(fig, use_container_width=True, key="batch_spamhaus")
        st.markdown("<div class='source'>mart_spamhaus_by_country &middot; DROP + EDROP.</div>", unsafe_allow_html=True)

    col1, col2 = st.columns([1, 1])
    with col1:
        st.markdown(
            """
<div class='card'>
  <h3>Top KEV vendors</h3>
  <p class='tagline'>Amber = of those CVEs, how many are explicitly tied to ransomware
  in CISA&rsquo;s notes. Ratio matters more than absolute count.</p>
</div>
""",
            unsafe_allow_html=True,
        )
        kev_vendors = q_kev_by_vendor()
        if not kev_vendors.empty:
            fig = go.Figure()
            fig.add_trace(go.Bar(x=kev_vendors["cves"], y=kev_vendors["vendor"], orientation="h",
                                 marker_color=ACCENT_CORAL, name="Total"))
            fig.add_trace(go.Bar(x=kev_vendors["ransomware_linked"], y=kev_vendors["vendor"], orientation="h",
                                 marker_color=ACCENT_AMBER, name="Ransomware"))
            fig.update_layout(height=400, barmode="overlay", **CHART)
            fig.update_yaxes(autorange="reversed")
            st.plotly_chart(fig, use_container_width=True, key="batch_kev_vendors")

    with col2:
        st.markdown(
            f"""
<div class='card'>
  <h3>Active C2s by hosting country</h3>
  <p class='tagline'>Countries where the actual {tip('C2')} servers sit. Not the same as
  attribution: hosting is fluid and most abuse lives in permissive transit networks.</p>
</div>
""",
            unsafe_allow_html=True,
        )
        c2_country = q_c2_by_country()
        if not c2_country.empty:
            fig = go.Figure(go.Bar(
                x=c2_country["active_c2"], y=c2_country["country"], orientation="h",
                marker_color=ACCENT_LAVENDER,
            ))
            fig.update_layout(height=400, **CHART)
            fig.update_yaxes(autorange="reversed")
            st.plotly_chart(fig, use_container_width=True, key="batch_c2_country")


# -----------------------------------------------------------------------------
# TAB: MAP
# -----------------------------------------------------------------------------

with tab_map:
    st.markdown(
        f"""
<div class='card'>
  <h3>Where the C2 servers live</h3>
  <p class='tagline'>Every dot is an IP address currently acting as a
  {tip('C2')} for a tracked malware family. Host country is a noisy signal
  (hosting is cheap and fluid, attribution belongs to the operators not the
  servers) but it still paints a useful map: attackers cluster where transit
  is permissive, bulletproof providers tolerate them and takedown notices
  are slow to land.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    c2_country = q_c2_by_country()
    if c2_country.empty:
        st.info("No active C2s in the feed right now. abuse.ch's Feodo Tracker sometimes empties during disruption campaigns.")
    else:
        c2_country = c2_country.copy()
        c2_country["iso3"] = c2_country["country"].map(_ISO2_TO_ISO3)
        mappable = c2_country.dropna(subset=["iso3"])
        unmapped = c2_country[c2_country["iso3"].isna()]

        fig = go.Figure(go.Choropleth(
            locations=mappable["iso3"],
            z=mappable["active_c2"],
            colorscale=[[0, "#18223a"], [0.3, ACCENT_LAVENDER], [0.7, ACCENT_CORAL], [1, ACCENT_AMBER]],
            marker_line_color=BORDER,
            marker_line_width=0.5,
            colorbar=dict(
                title=dict(text="Active C2s", font=dict(color=TEXT_MUTED, size=11)),
                tickfont=dict(color=TEXT_MUTED, size=10),
                thickness=12, len=0.75, outlinewidth=0, bgcolor="rgba(0,0,0,0)",
            ),
            hovertemplate="<b>%{location}</b><br>%{z} active C2s<extra></extra>",
        ))
        fig.update_geos(
            projection_type="natural earth",
            bgcolor=BG_CARD,
            showcountries=True, countrycolor=BORDER,
            showocean=True, oceancolor=BG,
            showland=True, landcolor="#0f1626",
            showframe=False, showcoastlines=False,
        )
        fig.update_layout(
            height=520,
            margin=dict(l=0, r=0, t=10, b=0),
            paper_bgcolor=BG_CARD,
            geo=dict(bgcolor=BG_CARD),
        )
        st.plotly_chart(fig, use_container_width=True, key="map_c2")

        col1, col2 = st.columns([1, 1])
        with col1:
            st.markdown(
                "<div class='card'><h3>Top countries</h3>"
                "<p class='tagline'>Raw numbers behind the map.</p></div>",
                unsafe_allow_html=True,
            )
            st.dataframe(
                c2_country.rename(columns={"country": "Country", "active_c2": "Active C2s"})[["Country", "Active C2s"]].head(20),
                use_container_width=True, hide_index=True, height=360,
            )
        with col2:
            if not unmapped.empty:
                st.markdown(
                    "<div class='card'><h3>Unmapped</h3>"
                    "<p class='tagline'>Countries the feed reports that we do not have "
                    "an ISO mapping for yet. Usually tiny or edge-case territories.</p></div>",
                    unsafe_allow_html=True,
                )
                st.dataframe(
                    unmapped.rename(columns={"country": "Country", "active_c2": "Active C2s"})[["Country", "Active C2s"]],
                    use_container_width=True, hide_index=True, height=200,
                )
        st.markdown(
            "<div class='source'>mart_c2_active &middot; abuse.ch Feodo Tracker &middot; hosting country != attribution.</div>",
            unsafe_allow_html=True,
        )


# -----------------------------------------------------------------------------
# TAB: MALWARE FIELD GUIDE
# -----------------------------------------------------------------------------

with tab_malware:
    st.markdown(
        """
<div class='card'>
  <h3>Field guide</h3>
  <p class='tagline'>If you are not in security, the family names are just noise. Here is
  what each of them actually does, and why it shows up in the live C2 feed.</p>
</div>
""",
        unsafe_allow_html=True,
    )
    c2_mal = q_c2_by_malware()
    shown: set[str] = set()
    col1, col2 = st.columns([1, 1])
    cards = []
    if not c2_mal.empty:
        for family in c2_mal["malware_family"].str.lower().head(14):
            if family in MALWARE_DESCRIPTIONS and family not in shown:
                shown.add(family)
                cards.append((family, MALWARE_DESCRIPTIONS[family]))
    for family in ("emotet", "qakbot", "cobaltstrike", "bumblebee", "trickbot", "icedid", "dridex"):
        if family not in shown:
            shown.add(family)
            cards.append((family, MALWARE_DESCRIPTIONS[family]))

    for i, (family, desc) in enumerate(cards):
        target = col1 if i % 2 == 0 else col2
        with target:
            st.markdown(
                f"<div class='malware-card'><div class='name'>{family}</div>"
                f"<div class='desc'>{desc}</div></div>",
                unsafe_allow_html=True,
            )


# -----------------------------------------------------------------------------
# TAB: STACK
# -----------------------------------------------------------------------------

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
  <p class='tagline'>Kestra schedules the daily refresh: five <code>dlt</code> pipelines
  load raw feeds into MotherDuck, then dbt transforms staging views into the marts
  that back this dashboard.</p>
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
  <p class='tagline'>Streamlit Cloud hosts this page and reads straight from MotherDuck
  on every refresh. GitHub Actions runs ruff, pytest and dbt parse on every push, and
  re-deploys the three Python apps to Fly.io when anything under
  <code>streaming/</code>, <code>batch/</code> or the Dockerfile changes.</p>
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
    <span class='tag'>Spamhaus DROP / EDROP</span>
    <span class='tag'>MITRE ATT&amp;CK</span>
    <span class='tag'>MaxMind GeoLite2</span>
  </div>
  <p class='tagline' style='margin-top:0.9rem;'>Source on <a href='https://github.com/pavel-kalmykov/phishing-radar'>GitHub</a>. Data Engineering Zoomcamp 2026.</p>
</div>
""",
            unsafe_allow_html=True,
        )
