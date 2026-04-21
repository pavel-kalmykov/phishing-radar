-- Recently added entries to the CISA Known Exploited Vulnerabilities catalog.
-- Drives the "hot CVEs right now" panel on the dashboard.
{{ config(materialized='table') }}

with recent as (
    select *
    from {{ ref('stg_cisa_kev') }}
    where date_added >= current_date - interval 365 day
)

select
    cve_id,
    vendor,
    product,
    vuln_name,
    date_added,
    due_date,
    known_ransomware_use,
    description,
    case
        when (current_date - date_added) < 7 then 'last_week'
        when (current_date - date_added) < 30 then 'last_month'
        when (current_date - date_added) < 90 then 'last_quarter'
        else 'last_year'
    end as freshness_bucket
from recent
