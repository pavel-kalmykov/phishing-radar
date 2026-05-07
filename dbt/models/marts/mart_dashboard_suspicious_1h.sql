-- Per-hour, per-issuer volume rolled up from mart_dashboard_suspicious_5min.
-- Used by the dashboard for top-issuers ranking and data-range discovery.
-- is_partial_hour marks the most recent hour when data may be incomplete.
-- NOTE: unique_domains is an upper bound (sum of 5-min distinct counts)
-- because a domain appearing in multiple 5-min buckets is double-counted.
-- Dashboard consumers do not use this column.
{{ config(materialized='table') }}

select
    date_trunc('hour', minute) as hour,
    issuer_cn,
    sum(flagged) as flagged,
    sum(unique_domains) as unique_domains,
    date_trunc('hour', minute) = (
        select date_trunc('hour', max(minute)) from {{ ref('mart_dashboard_suspicious_5min') }}
    ) as is_partial_hour
from {{ ref('mart_dashboard_suspicious_5min') }}
group by 1, 2
order by 1, 2
