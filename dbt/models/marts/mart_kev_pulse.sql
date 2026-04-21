-- Recently added entries to the CISA Known Exploited Vulnerabilities catalog.
-- This powers the "hot CVEs right now" panel on the dashboard.
{{
    config(
        materialized='table',
        partition_by={'field': 'date_added', 'data_type': 'date'},
        cluster_by=['vendor', 'known_ransomware_use']
    )
}}

with recent as (
    select *
    from {{ ref('stg_cisa_kev') }}
    where date_added >= date_sub(current_date(), interval 365 day)
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
    -- Age bucket so the dashboard can render freshness bands
    case
        when date_diff(current_date(), date_added, day) < 7 then 'last_week'
        when date_diff(current_date(), date_added, day) < 30 then 'last_month'
        when date_diff(current_date(), date_added, day) < 90 then 'last_quarter'
        else 'last_year'
    end as freshness_bucket
from recent
