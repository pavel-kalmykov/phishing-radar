-- Headline numbers for the dashboard KPI strip. Single-row, refreshed on
-- every dbt run.
{{ config(materialized='table') }}

select
    (select count(*) from {{ ref('mart_kev_pulse') }}) as kev_total,
    (select count(*) filter (where known_ransomware_use = 'Known') from {{ ref('mart_kev_pulse') }}) as kev_ransomware,
    (select count(*) from {{ ref('mart_c2_active') }}) as c2_total,
    (select count(distinct country) from {{ ref('mart_c2_active') }} where country is not null) as c2_countries,
    (select count(*) from {{ ref('stg_spamhaus') }}) as spam_total,
    (select count(*) from {{ ref('mart_mitre_malware_catalog') }}) as malware_total,
    (select count(*) from {{ ref('stg_suspicious_certs') }}) as suspicious_total,
    (select count(distinct primary_domain) from {{ ref('stg_suspicious_certs') }}) as suspicious_unique_domains,
    now() as refreshed_at
