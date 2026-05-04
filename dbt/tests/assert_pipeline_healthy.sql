with latest as (
    select *
    from {{ ref('mart_pipeline_health') }}
    order by window_ts desc
    limit 1
)

select *
from latest
where is_healthy = false
   or sink_alive = false
