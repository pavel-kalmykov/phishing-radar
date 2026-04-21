"""Phishing Radar Streamlit dashboard (MotherDuck backend).

Three pages:

1. Landing: hero, headline numbers, the story, and the streaming highlights.
2. Batch threat intel: KEV pulse, active C2 infrastructure, Spamhaus, MITRE.
3. Live phishing radar: impersonated brands, issuer CA volume, suspicious certs.
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
    page_icon="https://abuse.ch/favicon.ico",
    layout="wide",
    initial_sidebar_state="expanded",
)


@st.cache_resource
def get_conn() -> duckdb.DuckDBPyConnection:
    # Streamlit Cloud injects the token via st.secrets; locally it comes from env.
    token = os.getenv("MOTHERDUCK_TOKEN")
    if not token:
        try:
            token = st.secrets["MOTHERDUCK_TOKEN"]
        except Exception as e:
            raise RuntimeError("MOTHERDUCK_TOKEN not set in env or Streamlit secrets") from e
    conn_str = f"md:{MD_CATALOG}?motherduck_token={token}"
    return duckdb.connect(conn_str)


@st.cache_data(ttl=300)
def run_query(sql: str) -> pd.DataFrame:
    return get_conn().execute(sql).df()


# =============================================================================
# STYLE
# =============================================================================

ACCENT_RED = "#cf222e"
ACCENT_BLUE = "#2f81f7"
ACCENT_ORANGE = "#f0883e"
ACCENT_GREEN = "#2da44e"
BG = "#0f1117"
BG_CARD = "#161b22"
BORDER = "#30363d"
TEXT = "#e6edf3"
TEXT_MUTED = "#8b949e"

st.markdown(
    f"""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;900&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@500;700&display=swap');

    header[data-testid="stHeader"] {{ display: none; }}
    [data-testid="stApp"] {{ background: {BG}; }}
    html, body, [data-testid="stApp"] {{ font-family: 'Inter', sans-serif; color: {TEXT}; }}
    .block-container {{ padding: 2rem 2rem 2rem !important; max-width: 1100px !important; }}

    h1 {{ font-weight: 900 !important; font-size: 2.5rem !important; margin: 0 0 0.5rem 0 !important; }}
    h2 {{ font-weight: 700 !important; font-size: 1.5rem !important; color: {TEXT} !important; }}
    h3 {{ font-weight: 600 !important; font-size: 1.15rem !important; color: {TEXT} !important; }}

    .tagline {{ color: {TEXT_MUTED}; font-size: 1.05rem; max-width: 780px; line-height: 1.6; }}

    .metric-row {{ display: flex; gap: 2rem; margin: 2rem 0 1rem 0; flex-wrap: wrap; }}
    .metric {{ min-width: 140px; }}
    .metric-value {{ font-family: 'JetBrains Mono', monospace; font-size: 2.2rem; font-weight: 700; letter-spacing: -1px; }}
    .metric-label {{ color: {TEXT_MUTED}; font-size: 0.75rem; letter-spacing: 0.08em; text-transform: uppercase; }}
    .metric.red .metric-value {{ color: {ACCENT_RED}; }}
    .metric.blue .metric-value {{ color: {ACCENT_BLUE}; }}
    .metric.orange .metric-value {{ color: {ACCENT_ORANGE}; }}
    .metric.green .metric-value {{ color: {ACCENT_GREEN}; }}

    .card {{
        background: {BG_CARD}; border: 1px solid {BORDER}; border-radius: 10px;
        padding: 1.2rem 1.5rem; margin: 1rem 0;
    }}
    .callout {{
        background: rgba(47, 129, 247, 0.08);
        border-left: 3px solid {ACCENT_BLUE};
        padding: 0.8rem 1.2rem; margin: 1rem 0; border-radius: 4px;
        color: {TEXT};
    }}
</style>
""",
    unsafe_allow_html=True,
)


CHART = dict(
    plot_bgcolor=BG,
    paper_bgcolor=BG,
    font=dict(color=TEXT, family="Inter", size=12),
    margin=dict(l=40, r=20, t=30, b=40),
    xaxis=dict(gridcolor="rgba(255,255,255,0.04)", zerolinecolor=BORDER),
    yaxis=dict(gridcolor="rgba(255,255,255,0.04)", zerolinecolor=BORDER),
)


# =============================================================================
# NAV
# =============================================================================

PAGES = ["Landing", "Batch threat intel", "Live phishing radar"]
page = st.sidebar.radio("Page", PAGES, label_visibility="collapsed")
st.sidebar.caption(f"MotherDuck: `{MD_DATABASE}`")


# =============================================================================
# QUERIES
# =============================================================================

def q_headline_numbers() -> dict[str, Any]:
    sql = f"""
    select
      (select count(*) from {MD_DATABASE}.mart_kev_pulse) as kev_total,
      (select count(*) from {MD_DATABASE}.mart_c2_active) as c2_total,
      (select count(*) from {MD_DATABASE}.stg_spamhaus) as spam_total,
      (select count(*) from {MD_DATABASE}.mart_mitre_malware_catalog) as malware_total,
      (select count(*) from {MD_DATABASE}.stg_suspicious_certs) as suspicious_total
    """
    return run_query(sql).iloc[0].to_dict()


def q_kev_daily() -> pd.DataFrame:
    return run_query(f"""
        select date_added, count(*) as additions
        from {MD_DATABASE}.mart_kev_pulse
        where date_added is not null
        group by 1 order by 1
    """)


def q_kev_by_vendor(limit: int = 15) -> pd.DataFrame:
    return run_query(f"""
        select vendor, count(*) as cves,
               count(*) filter (where known_ransomware_use = 'Known') as ransomware_linked
        from {MD_DATABASE}.mart_kev_pulse
        where vendor is not null
        group by 1 order by cves desc limit {limit}
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


def q_spamhaus_buckets() -> pd.DataFrame:
    return run_query(f"select * from {MD_DATABASE}.mart_spamhaus_by_country")


def q_top_brands_7d() -> pd.DataFrame:
    return run_query(f"""
        select brand, category, hits_7d, unique_domains_7d
        from {MD_DATABASE}.mart_top_impersonated_brands
        order by hits_7d desc
    """)


def q_issuer_volume_recent() -> pd.DataFrame:
    return run_query(f"""
        select window_end, issuer_cn, suspicious_count, total_count, suspicious_ratio
        from {MD_DATABASE}.mart_issuer_volume_1min
        where window_end >= now() - interval 1 hour
        order by window_end desc limit 200
    """)


def q_recent_suspicious_sample(limit: int = 15) -> pd.DataFrame:
    return run_query(f"""
        select seen_at_ts, primary_domain, issuer_cn, max_score
        from {MD_DATABASE}.stg_suspicious_certs
        order by seen_at_ts desc limit {limit}
    """)


# =============================================================================
# PAGES
# =============================================================================

def page_landing() -> None:
    st.markdown("<h1>Phishing Radar</h1>", unsafe_allow_html=True)
    st.markdown(
        "<p class='tagline'>Every time someone sets up a phishing site, they need a TLS certificate. "
        "Those certificates are published in Certificate Transparency logs within seconds. "
        "This dashboard watches that firehose, flags impersonation attempts in real time, "
        "and correlates the findings with active malware infrastructure.</p>",
        unsafe_allow_html=True,
    )

    try:
        h = q_headline_numbers()
    except Exception as e:
        st.error(f"MotherDuck not ready: {e}")
        return

    st.markdown(
        f"""
<div class='metric-row'>
  <div class='metric red'><div class='metric-value'>{int(h['kev_total']):,}</div><div class='metric-label'>CVEs actively exploited</div></div>
  <div class='metric orange'><div class='metric-value'>{int(h['c2_total']):,}</div><div class='metric-label'>Online botnet C2s</div></div>
  <div class='metric blue'><div class='metric-value'>{int(h['spam_total']):,}</div><div class='metric-label'>Hijacked IP ranges</div></div>
  <div class='metric green'><div class='metric-value'>{int(h['malware_total']):,}</div><div class='metric-label'>Malware tracked by MITRE</div></div>
  <div class='metric red'><div class='metric-value'>{int(h['suspicious_total']):,}</div><div class='metric-label'>Suspicious certs seen</div></div>
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown(
        """
<div class='callout'>
This is not a honeypot or a simulator. Every number above comes from a live public feed: Certificate
Transparency logs for the streaming side, and abuse.ch, CISA, MITRE and Spamhaus for the batch side.
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("### What the two lanes do")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(
            """
**Streaming lane**: connects to the Certificate Transparency firehose over WebSocket
(around 200 certs per second), runs a typosquatting detector on every certificate's
subject and SAN domains, and writes flagged events plus per-minute aggregates back
to Kafka. MotherDuck is the long-term home.
"""
        )
    with col2:
        st.markdown(
            """
**Batch lane**: a daily Kestra flow ingests CISA KEV, Feodo C2 blocklist, Spamhaus
DROP, MITRE ATT&CK and MaxMind GeoLite2 via `dlt`. dbt transforms them into
materialised marts ready for the dashboard.
"""
        )


def page_batch() -> None:
    st.markdown("<h1>Batch threat intel</h1>", unsafe_allow_html=True)
    st.markdown(
        "<p class='tagline'>Five feeds, updated daily, correlated in MotherDuck via dbt. "
        "This is the context layer: the CVEs attackers are actually using, the botnets live "
        "right now, the IP space criminal organisations hold.</p>",
        unsafe_allow_html=True,
    )

    st.markdown("### CISA KEV: vulnerabilities under active exploitation")
    kev_daily = q_kev_daily()
    if not kev_daily.empty:
        fig = go.Figure(go.Bar(x=kev_daily["date_added"], y=kev_daily["additions"], marker_color=ACCENT_RED))
        fig.update_layout(title="CVE additions over time", **CHART)
        st.plotly_chart(fig, use_container_width=True)

    kev_vendors = q_kev_by_vendor()
    if not kev_vendors.empty:
        fig = go.Figure()
        fig.add_trace(go.Bar(x=kev_vendors["cves"], y=kev_vendors["vendor"], orientation="h",
                             marker_color=ACCENT_RED, name="Total"))
        fig.add_trace(go.Bar(x=kev_vendors["ransomware_linked"], y=kev_vendors["vendor"], orientation="h",
                             marker_color=ACCENT_ORANGE, name="Ransomware-linked"))
        fig.update_layout(title="Top vendors in KEV", barmode="overlay", height=450, **CHART)
        fig.update_yaxes(autorange="reversed")
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Active botnet C2 infrastructure")
    c2_mal = q_c2_by_malware()
    c2_country = q_c2_by_country()
    cols = st.columns(2)
    if not c2_mal.empty:
        with cols[0]:
            fig = go.Figure(go.Bar(x=c2_mal["active_c2"], y=c2_mal["malware_family"], orientation="h",
                                   marker_color=ACCENT_ORANGE))
            fig.update_layout(title="By malware family", height=420, **CHART)
            fig.update_yaxes(autorange="reversed")
            st.plotly_chart(fig, use_container_width=True)
    if not c2_country.empty:
        with cols[1]:
            fig = go.Figure(go.Bar(x=c2_country["active_c2"], y=c2_country["country"], orientation="h",
                                   marker_color=ACCENT_BLUE))
            fig.update_layout(title="By hosting country", height=420, **CHART)
            fig.update_yaxes(autorange="reversed")
            st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Spamhaus DROP: hijacked IP space")
    spam = q_spamhaus_buckets()
    if not spam.empty:
        fig = px.bar(
            spam, x="block_size_bucket", y="block_count", color="list",
            color_discrete_map={"drop": ACCENT_RED, "edrop": ACCENT_ORANGE},
            barmode="group", title="Hijacked blocks by prefix size",
        )
        fig.update_layout(**CHART)
        st.plotly_chart(fig, use_container_width=True)


def page_live() -> None:
    st.markdown("<h1>Live phishing radar</h1>", unsafe_allow_html=True)
    st.markdown(
        "<p class='tagline'>The streaming lane flags certificates whose domain looks like a "
        "brand impersonation. Every number on this page reflects the most recent window of the "
        "Certificate Transparency firehose.</p>",
        unsafe_allow_html=True,
    )

    brands = q_top_brands_7d()
    if brands.empty:
        st.info("No flagged certificates yet. Start the producer and detector with `make producer` and `make detect`.")
    else:
        st.markdown("### Most impersonated brands (last 7 days)")
        fig = go.Figure()
        fig.add_trace(go.Bar(x=brands["hits_7d"], y=brands["brand"], orientation="h", marker_color=ACCENT_RED))
        fig.update_layout(height=450, **CHART)
        fig.update_yaxes(autorange="reversed")
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Suspicious-cert ratio per issuing CA (last hour)")
    vol = q_issuer_volume_recent()
    if vol.empty:
        st.info("Waiting for the detector to emit windowed data.")
    else:
        fig = px.scatter(
            vol, x="window_end", y="issuer_cn", size="total_count", color="suspicious_ratio",
            color_continuous_scale="Reds", title="Each point = one minute",
        )
        fig.update_layout(**CHART)
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Latest suspicious certificates")
    sample = q_recent_suspicious_sample()
    if not sample.empty:
        st.dataframe(sample, use_container_width=True, hide_index=True)


if page == "Landing":
    page_landing()
elif page == "Batch threat intel":
    page_batch()
else:
    page_live()
