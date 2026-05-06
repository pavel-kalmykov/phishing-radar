-- Last 3 days of suspicious certs, pre-ordered by seen_at_ts DESC.
-- The dashboard uses this for the "Latest flagged certificates" table
-- so it never has to ORDER BY + LIMIT on the full 4.3M-row staging table.
-- Refreshed daily by dbt; the first hour of today is intentionally left
-- to a live fallback so the table doesn't miss certs issued since the last
-- dbt run.
{{ config(materialized='table') }}

select
    seen_at_ts,
    primary_domain,
    issuer_cn,
    max_score,
    detections_raw
from {{ ref('stg_suspicious_certs') }}
where seen_at_ts >= current_date - interval '7 days'
order by seen_at_ts desc
