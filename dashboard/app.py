"""Phishing Radar dashboard.

Single-page editorial report that reads straight from MotherDuck and walks the
reader through the story end-to-end: what Certificate Transparency is, how
typosquatting is flagged, which brands are in the crosshairs today, and which
criminal infrastructure is live right now.

Deliberately opinionated styling: navy background with cyan/coral/lavender
accents, IBM Plex Mono for numbers, Source Serif for headlines. Different from
my previous zoomcamp project on purpose.
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
    initial_sidebar_state="collapsed",
)


# =============================================================================
# BACKEND
# =============================================================================

@st.cache_resource
def get_conn() -> duckdb.DuckDBPyConnection:
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
# STYLE (deliberately different from the previous project)
# =============================================================================

BG = "#0b1120"
BG_CARD = "#111a2e"
BG_RAISED = "#18223a"
BORDER = "#1f2a45"
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
  @import url('https://fonts.googleapis.com/css2?family=Source+Serif+4:ital,wght@0,400;0,600;0,700;1,400&family=Inter:wght@400;500;600&family=IBM+Plex+Mono:wght@500;700&display=swap');

  header[data-testid="stHeader"] {{ display: none; }}
  [data-testid="stSidebar"] {{ display: none; }}
  [data-testid="stApp"] {{ background: {BG}; }}
  html, body, [data-testid="stApp"] {{
    font-family: 'Inter', sans-serif; color: {TEXT};
    line-height: 1.6;
  }}
  .block-container {{ padding: 2.5rem 2rem 4rem !important; max-width: 980px !important; }}

  h1, h2, h3 {{ font-family: 'Source Serif 4', serif; color: {TEXT}; }}
  h1 {{ font-weight: 700 !important; font-size: 3rem !important; letter-spacing: -0.02em; line-height: 1.1; margin: 0 0 0.6rem 0 !important; }}
  h2 {{ font-weight: 600 !important; font-size: 1.9rem !important; margin: 3rem 0 0.5rem 0 !important; letter-spacing: -0.01em; }}
  h3 {{ font-weight: 600 !important; font-size: 1.25rem !important; margin: 1.8rem 0 0.5rem 0 !important; color: {ACCENT_TEAL} !important; }}

  p, li {{ color: {TEXT}; font-size: 1.02rem; }}
  a {{ color: {ACCENT_TEAL}; text-decoration: none; border-bottom: 1px dotted {ACCENT_TEAL}; }}

  abbr[title] {{
    text-decoration: none;
    border-bottom: 1px dashed {ACCENT_LAVENDER};
    cursor: help;
    color: {TEXT};
  }}

  .deck {{ color: {TEXT_MUTED}; font-size: 1.1rem; line-height: 1.55; max-width: 680px; margin: 0 0 1.2rem 0; }}

  .metric-row {{ display: flex; gap: 1.6rem; margin: 1.8rem 0 1.4rem 0; flex-wrap: wrap; }}
  .metric {{ min-width: 130px; }}
  .metric-value {{ font-family: 'IBM Plex Mono', monospace; font-size: 2.3rem; font-weight: 700; letter-spacing: -0.02em; line-height: 1.1; }}
  .metric-label {{ color: {TEXT_DIM}; font-size: 0.73rem; letter-spacing: 0.12em; text-transform: uppercase; margin-top: 0.3rem; }}
  .metric.teal .metric-value {{ color: {ACCENT_TEAL}; }}
  .metric.coral .metric-value {{ color: {ACCENT_CORAL}; }}
  .metric.amber .metric-value {{ color: {ACCENT_AMBER}; }}
  .metric.lavender .metric-value {{ color: {ACCENT_LAVENDER}; }}
  .metric.mint .metric-value {{ color: {ACCENT_MINT}; }}

  blockquote, .pullquote {{
    border-left: 3px solid {ACCENT_LAVENDER};
    margin: 1.2rem 0; padding: 0.2rem 1.2rem;
    color: {TEXT_MUTED}; font-style: italic;
    font-family: 'Source Serif 4', serif; font-size: 1.08rem;
  }}

  .source {{
    font-size: 0.78rem; color: {TEXT_DIM}; margin: 0.3rem 0 2rem 0;
    font-family: 'IBM Plex Mono', monospace; letter-spacing: 0.02em;
  }}
  .source a {{ border-bottom-style: solid; }}

  .takeaway {{
    background: rgba(34, 211, 238, 0.06);
    border: 1px solid rgba(34, 211, 238, 0.25);
    border-radius: 8px;
    padding: 0.9rem 1.1rem; margin: 1.2rem 0;
    color: {TEXT};
    font-size: 0.97rem;
  }}
  .takeaway strong {{ color: {ACCENT_TEAL}; }}

  .tag {{
    display: inline-block;
    background: {BG_RAISED}; color: {TEXT_MUTED};
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.75rem; padding: 0.15rem 0.5rem;
    border-radius: 4px; border: 1px solid {BORDER};
    margin-right: 0.3rem;
  }}

  .malware-card {{
    background: {BG_CARD}; border: 1px solid {BORDER};
    padding: 0.9rem 1.1rem; margin-bottom: 0.7rem; border-radius: 6px;
  }}
  .malware-card .name {{ color: {ACCENT_CORAL}; font-family: 'IBM Plex Mono', monospace; font-weight: 700; }}
  .malware-card .desc {{ color: {TEXT_MUTED}; font-size: 0.92rem; margin-top: 0.25rem; }}

  .section-rule {{
    height: 1px; background: {BORDER};
    margin: 3rem 0 0 0;
  }}
</style>
""",
    unsafe_allow_html=True,
)


CHART = dict(
    plot_bgcolor=BG,
    paper_bgcolor=BG,
    font=dict(color=TEXT, family="Inter", size=12),
    margin=dict(l=40, r=20, t=20, b=40),
    xaxis=dict(gridcolor="rgba(255,255,255,0.04)", zerolinecolor=BORDER),
    yaxis=dict(gridcolor="rgba(255,255,255,0.04)", zerolinecolor=BORDER),
    legend=dict(bgcolor="rgba(0,0,0,0)", bordercolor=BORDER, borderwidth=1),
)


# =============================================================================
# DOMAIN KNOWLEDGE
# =============================================================================

GLOSSARY = {
    "CT": "Certificate Transparency. An open framework, mandatory for public CAs, that forces every issued TLS certificate to be written to append-only, cryptographically verifiable public logs.",
    "SAN": "Subject Alternative Name. A certificate extension that lists every hostname the certificate is valid for. Phishing certs often pack dozens of SANs covering brand look-alikes.",
    "CA": "Certificate Authority. The organisation that signs and issues TLS certificates after verifying that the requester controls the domain.",
    "CVE": "Common Vulnerabilities and Exposures. The global identifier (e.g. CVE-2024-1234) for a publicly disclosed security flaw.",
    "KEV": "Known Exploited Vulnerabilities. The CISA catalogue of CVEs for which there is reliable evidence of active exploitation in the wild.",
    "C2": "Command and Control. The server a malware implant calls home to for instructions. Feodo Tracker maintains a live list of known C2 addresses.",
    "CIDR": "Classless Inter-Domain Routing. The `/24`, `/16` notation that describes an IP range. Spamhaus DROP publishes CIDR blocks believed to be hijacked or criminal-controlled.",
    "DROP": "Don't Route Or Peer. Spamhaus's list of IP ranges so clearly criminal that transit providers are urged to drop traffic from them entirely.",
    "TLD": "Top-Level Domain. The rightmost label of a hostname (`.com`, `.org`, `.co.uk`).",
    "SLD": "Second-Level Domain. The label immediately to the left of the TLD. `paypal` in `paypal.com`.",
    "typosquatting": "Registering a domain that is visually or phonetically close to a legitimate one to trick users: `paypa1.com`, `g00gle.com`, `microsoft-support.org`.",
    "homoglyph": "Two characters that look identical or near-identical to a human reader. `0` vs `o`, `1` vs `l`, `rn` vs `m`. Bread-and-butter for phishing domains.",
}

MALWARE_DESCRIPTIONS = {
    "emotet": "Started in 2014 as a banking trojan; today it is a malware distribution platform that drops whatever payload its operators are paid to deliver. Takedown in 2021, resurrected in late 2021.",
    "heodo": "An alias for Emotet used in abuse.ch's feeds to refer to specific Emotet variants.",
    "qakbot": "Also known as Qbot or Pinkslipbot. Banking trojan and loader; frequently used as the entry point for Conti and Black Basta ransomware.",
    "trickbot": "Modular banking trojan that pivoted into being a ransomware loader (Ryuk, Conti). Infrastructure severely disrupted in 2020 but fragments remain.",
    "icedid": "Also known as BokBot. Information stealer and loader, spread through malicious Office documents and ZIP archives, historically delivered via Emotet.",
    "dridex": "Long-running banking trojan tied to the Evil Corp criminal group. Uses macro-enabled Office documents and drops later-stage payloads.",
    "cobaltstrike": "Commercial adversary simulation toolkit sold to red teams; cracked versions are ubiquitous in ransomware operations for post-exploitation.",
    "bumblebee": "A loader first seen in 2022, often replacing BazarLoader. Linked to Conti-era operators and used to deliver Cobalt Strike and ransomware.",
    "remcos": "Commercial remote-access trojan sold as legitimate administration software. Widely abused by low-effort phishing campaigns.",
    "asyncrat": "Open-source RAT, trivial to obtain and deploy. Frequently dropped by commodity loaders.",
    "njrat": "Long-lived commodity RAT popular in the Middle East. Cheap, feature-rich, mass-deployed.",
    "formbook": "Information stealer sold as malware-as-a-service. Harvests credentials from browsers and email clients.",
    "lokibot": "Another credential stealer sold on underground forums. Targets browsers, FTP clients, cryptocurrency wallets.",
    "agenttesla": "Keylogger and stealer family, distributed through phishing attachments targeting SMEs.",
    "pikabot": "Loader family that emerged in 2023 as a suspected Qakbot successor. Associated with Black Basta deliveries.",
}


def tip(term: str, label: str | None = None) -> str:
    """Render an `abbr` element so technical acronyms get dotted underlines and
    native browser tooltips."""
    desc = GLOSSARY.get(term, "")
    text = label or term
    if not desc:
        return text
    return f'<abbr title="{desc}">{text}</abbr>'


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
        group by 1
        order by hits desc
        limit 12
    """)


def q_recent_suspicious() -> pd.DataFrame:
    return run_query(f"""
        select seen_at_ts, primary_domain, issuer_cn, max_score
        from {MD_DATABASE}.stg_suspicious_certs
        where seen_at_ts is not null
        order by seen_at_ts desc
        limit 15
    """)


def q_suspicious_over_time() -> pd.DataFrame:
    return run_query(f"""
        select date_trunc('hour', seen_at_ts) as hour, count(*) as flagged
        from {MD_DATABASE}.stg_suspicious_certs
        where seen_at_ts is not null
        group by 1 order by 1
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


def q_spamhaus_buckets() -> pd.DataFrame:
    return run_query(f"select * from {MD_DATABASE}.mart_spamhaus_by_country")


# =============================================================================
# RENDER
# =============================================================================

counts = q_counts()


st.markdown("<h1>Phishing Radar</h1>", unsafe_allow_html=True)
st.markdown(
    f"""
<p class='deck'>
Every phishing site needs a TLS certificate. Those certificates are published
to {tip('CT', 'Certificate Transparency')} logs seconds after they are issued,
which means the scam infrastructure is visible while it is being built. This
report tails that firehose, flags impersonations as they happen, and lines
them up against what the rest of the criminal ecosystem is doing today.
</p>
""",
    unsafe_allow_html=True,
)

st.markdown(
    f"""
<div class='metric-row'>
  <div class='metric coral'><div class='metric-value'>{int(counts['kev_total']):,}</div><div class='metric-label'>CVEs under active exploitation</div></div>
  <div class='metric amber'><div class='metric-value'>{int(counts['kev_ransomware']):,}</div><div class='metric-label'>Of those, used by ransomware</div></div>
  <div class='metric teal'><div class='metric-value'>{int(counts['c2_total']):,}</div><div class='metric-label'>Online botnet C2 servers</div></div>
  <div class='metric lavender'><div class='metric-value'>{int(counts['spam_total']):,}</div><div class='metric-label'>Hijacked IP ranges (Spamhaus DROP)</div></div>
  <div class='metric mint'><div class='metric-value'>{int(counts['malware_total']):,}</div><div class='metric-label'>Malware tracked by MITRE ATT&amp;CK</div></div>
</div>
<div class='metric-row' style='margin-top:0.2rem;'>
  <div class='metric coral'><div class='metric-value'>{int(counts['suspicious_total']):,}</div><div class='metric-label'>Phishing certificates seen in this feed</div></div>
</div>
""",
    unsafe_allow_html=True,
)

st.markdown(
    """
<div class='takeaway'>
<strong>Every number on this page comes from a live public feed.</strong>
No simulations, no synthetic data. CT logs stream continuously, the batch
feeds refresh daily, and MotherDuck holds the lot. Nothing is aggregated away;
you can click any row below to see the raw certificate or CVE.
</div>
""",
    unsafe_allow_html=True,
)


st.markdown("<div class='section-rule'></div>", unsafe_allow_html=True)
st.markdown("<h2>What a phishing cert looks like</h2>", unsafe_allow_html=True)
st.markdown(
    f"""
<p>
A modern phishing kit needs three things: a look-alike domain, a working TLS
certificate so browsers do not panic, and somewhere to host the landing page.
The domain and the certificate are the easy-to-spot pieces, because the
certificate has to be logged publicly or Chrome will refuse it.
</p>
<p>
This feed treats any certificate whose name looks like a known brand as
suspicious. Three rules, in descending order of confidence:
</p>
<ul>
  <li><strong>{tip('homoglyph')}</strong>: the {tip('SLD')} matches a popular
  brand after digit-to-letter substitution (<code>paypa1</code> &rarr;
  <code>paypal</code>, <code>goog1e</code> &rarr; <code>google</code>).</li>
  <li><strong>Brand embedded as a label</strong>: the brand name appears as a
  substring of any non-{tip('TLD')} label (<code>login-paypal-secure.example.net</code>,
  <code>microsoft-support.org</code>).</li>
  <li><strong>Levenshtein distance 1&ndash;2</strong>: single or double typos
  on the brand name (<code>amzaon.com</code>, <code>paypai.com</code>).</li>
</ul>
<blockquote>
Not every hit is phishing. Legitimate resellers, support sites and fan wikis
will trip the same rules. The goal is to narrow a 200 cert/s firehose down to
something a human analyst can triage in a morning.
</blockquote>
""",
    unsafe_allow_html=True,
)


st.markdown("<h3>Brands in the crosshairs</h3>", unsafe_allow_html=True)
brands = q_top_brands()
if brands.empty:
    st.info("No flagged certificates in the warehouse yet. The streaming pipeline is running; come back in a few minutes.")
else:
    fig = go.Figure(go.Bar(
        x=brands["hits"], y=brands["brand"], orientation="h",
        marker_color=ACCENT_CORAL, hovertemplate="<b>%{y}</b><br>%{x} flagged certs<extra></extra>",
    ))
    fig.update_layout(height=380, **CHART)
    fig.update_yaxes(autorange="reversed")
    st.plotly_chart(fig, use_container_width=True)
st.markdown(
    "<div class='source'>Source: stg_suspicious_certs. Flagged by the Python detector running on Fly.io, materialised via dbt.</div>",
    unsafe_allow_html=True,
)


st.markdown("<h3>Suspicious certificates over time</h3>", unsafe_allow_html=True)
sus_time = q_suspicious_over_time()
if not sus_time.empty:
    fig = go.Figure(go.Scatter(
        x=sus_time["hour"], y=sus_time["flagged"], mode="lines+markers",
        line=dict(color=ACCENT_TEAL, width=2),
        marker=dict(size=5, color=ACCENT_TEAL),
        fill="tozeroy", fillcolor="rgba(34, 211, 238, 0.08)",
        hovertemplate="%{x}<br><b>%{y}</b> flagged certs<extra></extra>",
    ))
    fig.update_layout(height=300, **CHART)
    st.plotly_chart(fig, use_container_width=True)
st.markdown(
    "<div class='source'>One point per hour. Spikes usually mean an attacker batch-registering a look-alike fleet.</div>",
    unsafe_allow_html=True,
)


st.markdown("<h3>Latest suspicious certificates</h3>", unsafe_allow_html=True)
st.markdown(
    "<p>The fifteen most recent flagged certificates, including the CA that signed them. Issuer matters: "
    "a Let&rsquo;s Encrypt cert for <code>paypa1-login.com</code> is very different from a DigiCert EV for a "
    "registered business.</p>",
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
        use_container_width=True, hide_index=True, height=400,
    )


st.markdown("<div class='section-rule'></div>", unsafe_allow_html=True)
st.markdown("<h2>The criminal infrastructure behind it</h2>", unsafe_allow_html=True)
st.markdown(
    f"""
<p>
A phishing page is the front door. Behind it there is always something
nastier: a stealer that siphons credentials once the victim types them, a
ransomware dropper that calls home, a banking trojan that waits for a
two-factor prompt. The rest of this report looks at what that ecosystem is
doing right now.
</p>
""",
    unsafe_allow_html=True,
)


st.markdown("<h3>CISA KEV: what defenders are patching</h3>", unsafe_allow_html=True)
st.markdown(
    f"""
<p>
CISA&rsquo;s {tip('KEV')} catalogue is the short list: vulnerabilities for
which there is evidence of active exploitation. When a CVE lands here, it
means ransomware crews and espionage groups are already using it. There are
currently <strong>{int(counts['kev_total']):,}</strong> entries, of which
<strong>{int(counts['kev_ransomware']):,}</strong> are explicitly linked to
ransomware campaigns.
</p>
""",
    unsafe_allow_html=True,
)
kev_monthly = q_kev_monthly()
if not kev_monthly.empty:
    fig = go.Figure(go.Bar(
        x=kev_monthly["month"], y=kev_monthly["additions"],
        marker_color=ACCENT_AMBER,
        hovertemplate="%{x|%b %Y}<br><b>%{y}</b> CVEs added<extra></extra>",
    ))
    fig.update_layout(height=280, **CHART)
    st.plotly_chart(fig, use_container_width=True)
st.markdown(
    "<div class='source'>Monthly KEV additions. The 2024 dip was accurate, not data loss: CISA genuinely triaged fewer CVEs that quarter.</div>",
    unsafe_allow_html=True,
)

kev_vendors = q_kev_by_vendor()
if not kev_vendors.empty:
    fig = go.Figure()
    fig.add_trace(go.Bar(x=kev_vendors["cves"], y=kev_vendors["vendor"], orientation="h",
                         marker_color=ACCENT_CORAL, name="Total exploited CVEs"))
    fig.add_trace(go.Bar(x=kev_vendors["ransomware_linked"], y=kev_vendors["vendor"], orientation="h",
                         marker_color=ACCENT_AMBER, name="Of those, used by ransomware"))
    fig.update_layout(title="", barmode="overlay", height=420, **CHART)
    fig.update_yaxes(autorange="reversed")
    st.plotly_chart(fig, use_container_width=True)
st.markdown(
    "<div class='source'>Microsoft leads because it is the biggest attack surface. Ransomware ratios (amber) matter more than raw counts.</div>",
    unsafe_allow_html=True,
)


st.markdown("<h3>Active botnet infrastructure</h3>", unsafe_allow_html=True)
st.markdown(
    f"""
<p>
abuse.ch&rsquo;s Feodo Tracker publishes a live list of IPs that known
malware families use as {tip('C2')} servers. Every IP below is a live
&ldquo;phone home&rdquo; address that an infected machine somewhere is
currently talking to.
</p>
""",
    unsafe_allow_html=True,
)

c2_mal = q_c2_by_malware()
c2_country = q_c2_by_country()
cols = st.columns(2)
with cols[0]:
    if not c2_mal.empty:
        fig = go.Figure(go.Bar(
            x=c2_mal["active_c2"], y=c2_mal["malware_family"], orientation="h",
            marker_color=ACCENT_TEAL,
        ))
        fig.update_layout(title="By malware family", height=360, **CHART)
        fig.update_yaxes(autorange="reversed")
        st.plotly_chart(fig, use_container_width=True)
with cols[1]:
    if not c2_country.empty:
        fig = go.Figure(go.Bar(
            x=c2_country["active_c2"], y=c2_country["country"], orientation="h",
            marker_color=ACCENT_LAVENDER,
        ))
        fig.update_layout(title="By hosting country", height=360, **CHART)
        fig.update_yaxes(autorange="reversed")
        st.plotly_chart(fig, use_container_width=True)
st.markdown(
    "<div class='source'>Feodo Tracker is updated every few minutes. The &ldquo;unknown&rdquo; country entries are IPs abuse.ch has not geolocated yet.</div>",
    unsafe_allow_html=True,
)

st.markdown("<h3>A short field guide to the malware families above</h3>", unsafe_allow_html=True)
st.markdown(
    "<p>If you are not in security, the family names are just noise. Here is "
    "what each of them actually does, and why it shows up in the C2 list:</p>",
    unsafe_allow_html=True,
)
shown = set()
if not c2_mal.empty:
    for family in c2_mal["malware_family"].str.lower().head(10):
        if family in MALWARE_DESCRIPTIONS and family not in shown:
            shown.add(family)
            st.markdown(
                f"<div class='malware-card'><div class='name'>{family}</div>"
                f"<div class='desc'>{MALWARE_DESCRIPTIONS[family]}</div></div>",
                unsafe_allow_html=True,
            )
# Fill in any iconic family not in the C2 list today
for family in ("emotet", "qakbot", "cobaltstrike", "bumblebee"):
    if family not in shown:
        shown.add(family)
        st.markdown(
            f"<div class='malware-card'><div class='name'>{family}</div>"
            f"<div class='desc'>{MALWARE_DESCRIPTIONS[family]}</div></div>",
            unsafe_allow_html=True,
        )


st.markdown("<h3>Spamhaus DROP: hijacked IP ranges</h3>", unsafe_allow_html=True)
st.markdown(
    f"""
<p>
{tip('DROP')} and EDROP list IP {tip('CIDR')} blocks that Spamhaus considers
so heavily under criminal control that transit providers should not carry
traffic for them. Most of the volume is in small blocks (/24 and below),
because attackers prefer a splatter of freshly hijacked /24s to a single
easily blocklisted /16.
</p>
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
    fig.update_layout(height=320, **CHART)
    fig.update_xaxes(title_text="")
    fig.update_yaxes(title_text="Blocks on the list")
    st.plotly_chart(fig, use_container_width=True)
st.markdown(
    "<div class='source'>Source: Spamhaus DROP + EDROP, refreshed daily.</div>",
    unsafe_allow_html=True,
)


st.markdown("<div class='section-rule'></div>", unsafe_allow_html=True)
st.markdown("<h2>How this was built</h2>", unsafe_allow_html=True)
st.markdown(
    """
<p>
The streaming lane (certstream &rarr; Redpanda &rarr; Python detector &rarr;
MotherDuck) runs around the clock on Fly.io machines. The batch lane (five
<code>dlt</code> pipelines plus a dbt project) is orchestrated by a Kestra
instance that also lives on Fly.io and writes to the same MotherDuck database.
</p>
<p>
<span class='tag'>Redpanda Cloud</span>
<span class='tag'>MotherDuck</span>
<span class='tag'>Fly.io</span>
<span class='tag'>Streamlit Cloud</span>
<span class='tag'>dlt</span>
<span class='tag'>dbt</span>
<span class='tag'>Kestra</span>
<span class='tag'>Python 3.11 / uv</span>
<span class='tag'>PyFlink (reference)</span>
</p>
<p style='margin-top:1rem; color:var(--muted);'>
Source on <a href='https://github.com/pavel-kalmykov/phishing-radar'>GitHub</a>.
Data Engineering Zoomcamp 2026 capstone.
</p>
""",
    unsafe_allow_html=True,
)
