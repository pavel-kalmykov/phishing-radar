-- Daily summary of impersonation certificates, one row per (day, brand, category, reason).
-- `detections_raw` is a JSON array; DuckDB's json_each / unnest expand it.
{{ config(materialized='table') }}

with exploded as (
    select
        s.seen_at_ts,
        cast(s.seen_at_ts as date) as day,
        s.primary_domain,
        s.issuer_cn,
        s.issuer_o,
        s.fingerprint,
        s.max_score,
        json_extract_string(det.value, '$.domain') as flagged_domain,
        json_extract_string(det.value, '$.brand') as brand,
        json_extract_string(det.value, '$.category') as category,
        json_extract_string(det.value, '$.reason') as reason,
        cast(json_extract_string(det.value, '$.score') as integer) as score
    from {{ ref('stg_suspicious_certs') }} s,
    lateral (select unnest(from_json(s.detections_raw::varchar, '["json"]')) as value) det
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
