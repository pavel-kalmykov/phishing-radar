-- Per-hour, per-issuer volume of flagged certificates. Pre-aggregated so the
-- dashboard never rescans stg_suspicious_certs. The issuer_cn grain lets the
-- dashboard filter by CA without hitting the staging table.
{{ config(materialized='table') }}

select
    date_trunc('hour', seen_at_ts) as hour,
    coalesce(issuer_cn, '(unknown)') as issuer_cn,
    count(*) as flagged,
    count(distinct primary_domain) as unique_domains,
    date_trunc('hour', seen_at_ts) >= date_trunc('hour', now()) as is_partial_hour
from {{ ref('stg_suspicious_certs') }}
where seen_at_ts is not null
group by 1, 2
order by 1, 2
