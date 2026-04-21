-- Daily summary of impersonation certificates, ready for the dashboard.
-- Expands the `detections` array so each (cert, brand) combo is one row,
-- then buckets by day. Partitioned on `day` for cheap date filters.
{{
    config(
        materialized='table',
        partition_by={'field': 'day', 'data_type': 'date'},
        cluster_by=['brand', 'category']
    )
}}

with exploded as (
    select
        s.seen_at_ts,
        date(s.seen_at_ts) as day,
        s.primary_domain,
        s.issuer_cn,
        s.issuer_o,
        s.fingerprint,
        s.max_score,
        json_value(det, '$.domain') as flagged_domain,
        json_value(det, '$.brand') as brand,
        json_value(det, '$.category') as category,
        json_value(det, '$.reason') as reason,
        cast(json_value(det, '$.score') as int64) as score
    from {{ ref('stg_suspicious_certs') }} s,
    unnest(s.detections_raw) as det
)

select
    day,
    brand,
    category,
    reason,
    count(*) as hits,
    count(distinct primary_domain) as unique_domains,
    count(distinct issuer_cn) as distinct_issuers
from exploded
group by 1, 2, 3, 4
