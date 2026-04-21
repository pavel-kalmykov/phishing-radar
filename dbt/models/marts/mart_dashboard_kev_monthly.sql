-- KEV monthly additions with a partial-month flag so the dashboard can render
-- the in-progress month with a different visual treatment instead of
-- dropping it or letting it look spuriously low.
{{ config(materialized='table') }}

select
    date_trunc('month', date_added) as month,
    count(*) as additions,
    count(*) filter (where known_ransomware_use = 'Known') as ransomware_additions,
    date_trunc('month', date_added) >= date_trunc('month', current_date) as is_partial_month
from {{ ref('mart_kev_pulse') }}
where date_added is not null
group by 1
order by 1
