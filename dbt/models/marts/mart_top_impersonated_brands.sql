-- 7-day ranking of the most impersonated brands.
{{ config(materialized='table') }}

with recent as (
    select *
    from {{ ref('mart_suspicious_certs_daily') }}
    where day >= current_date - interval 7 day
)

select
    brand,
    category,
    sum(hits) as hits_7d,
    sum(unique_domains) as unique_domains_7d,
    count(distinct day) as active_days
from recent
group by 1, 2
