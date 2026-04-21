-- C2 counts per country, split by source, for the scatter_geo map. One row
-- per country so the dashboard can plot a dot per country with size = count
-- and colour = dominant malware family. Unmapped IPs (no country block match)
-- are surfaced in a separate "unknown" bucket.
{{ config(materialized='table') }}

with per_country as (
    select
        coalesce(country, '(unknown)') as country,
        source,
        count(*) as active_c2,
        count(distinct malware_family) as distinct_families,
        mode() within group (order by malware_family) as top_family
    from {{ ref('mart_c2_active') }}
    group by 1, 2
)

select
    country,
    sum(active_c2) as active_c2,
    sum(distinct_families) as distinct_families,
    mode() within group (order by top_family) as top_family,
    string_agg(distinct source, ', ') as sources
from per_country
group by 1
order by active_c2 desc
