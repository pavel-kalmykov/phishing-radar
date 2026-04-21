-- Ranking of the most-impersonated brands over the last 7 days.
-- Used for the "who's being targeted" panel on the dashboard.
{{ config(materialized='table', cluster_by=['brand']) }}

with recent as (
    select *
    from {{ ref('mart_suspicious_certs_daily') }}
    where day >= date_sub(current_date(), interval 7 day)
)

select
    brand,
    category,
    sum(hits) as hits_7d,
    sum(unique_domains) as unique_domains_7d,
    count(distinct day) as active_days
from recent
group by 1, 2
