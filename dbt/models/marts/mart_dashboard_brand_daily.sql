-- Per-day, per-issuer, per-brand counts. Pre-aggregated so the dashboard
-- top-brands chart never touches stg_suspicious_certs or unnests JSON at
-- query time.  Grain: (day, issuer_cn, brand).
{{ config(materialized='table') }}

with exploded as (
    select
        cast(s.seen_at_ts as date) as day,
        s.issuer_cn,
        json_extract_string(det.value, '$.brand') as brand
    from {{ ref('stg_suspicious_certs') }} s,
    lateral (select unnest(from_json(s.detections_raw::varchar, '["json"]')) as value) det
)

select
    day,
    coalesce(issuer_cn, '(unknown)') as issuer_cn,
    brand,
    count(*) as hits
from exploded
where brand is not null
group by 1, 2, 3
