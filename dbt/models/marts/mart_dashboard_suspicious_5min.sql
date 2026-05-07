-- Per-5-minute, per-issuer volume of flagged certificates. Base grain for
-- the dashboard time-series chart; exact-range WHERE clauses on `minute`
-- naturally exclude buckets outside the filter instead of relying on
-- partial-hour markers. Rolled up to 1h by mart_dashboard_suspicious_1h.
{{ config(materialized='table') }}

select
    time_bucket(INTERVAL '5 minutes', seen_at_ts) as minute,
    coalesce(issuer_cn, '(unknown)') as issuer_cn,
    count(*) as flagged,
    count(distinct primary_domain) as unique_domains
from {{ ref('stg_suspicious_certs') }}
where seen_at_ts is not null
group by 1, 2
order by 1, 2
