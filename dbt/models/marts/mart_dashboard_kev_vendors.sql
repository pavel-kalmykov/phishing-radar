-- KEV entries rolled up by vendor, with explicit ransomware ratio so the
-- dashboard can sort/colour by ratio without recomputing it.
{{ config(materialized='table') }}

select
    vendor,
    count(*) as cves,
    count(*) filter (where known_ransomware_use = 'Known') as ransomware_linked,
    round(
        100.0 * count(*) filter (where known_ransomware_use = 'Known')
        / nullif(count(*), 0),
    1) as ransomware_ratio_pct
from {{ ref('mart_kev_pulse') }}
where vendor is not null
group by 1
order by cves desc
limit 20
