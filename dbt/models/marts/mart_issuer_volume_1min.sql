-- Per-minute suspicious-cert ratio per issuing CA. Driven by the detector's
-- tumbling-window output.
{{ config(materialized='table') }}

select
    window_end,
    cast(window_end as date) as window_date,
    issuer_cn,
    suspicious_count,
    total_count,
    case when total_count = 0 then null
         else suspicious_count * 1.0 / total_count
    end as suspicious_ratio
from {{ ref('stg_cert_stats') }}
where total_count > 0
