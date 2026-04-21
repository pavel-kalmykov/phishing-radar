-- Top-20 CAs by flagged-cert count, pre-aggregated for the dashboard.
{{ config(materialized='table') }}

select
    coalesce(issuer_cn, '(unknown)') as issuer,
    count(*) as hits,
    count(distinct primary_domain) as unique_domains,
    min(seen_at_ts) as first_seen,
    max(seen_at_ts) as last_seen
from {{ ref('stg_suspicious_certs') }}
where seen_at_ts is not null
group by 1
order by hits desc
limit 20
