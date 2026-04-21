-- Per-hour volume of flagged certificates. Pre-aggregated so the dashboard
-- doesn't rescan stg_suspicious_certs on every page load, and so we can
-- surface the `is_partial_hour` flag for the current incomplete hour without
-- recomputing it client-side.
{{ config(materialized='table') }}

select
    date_trunc('hour', seen_at_ts) as hour,
    cast(date_trunc('hour', seen_at_ts) as date) as day,
    count(*) as flagged,
    count(distinct primary_domain) as unique_domains,
    count(distinct issuer_cn) as distinct_issuers,
    date_trunc('hour', seen_at_ts) >= date_trunc('hour', now()) as is_partial_hour
from {{ ref('stg_suspicious_certs') }}
where seen_at_ts is not null
group by 1, 2
order by 1
