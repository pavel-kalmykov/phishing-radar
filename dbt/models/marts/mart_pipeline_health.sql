{{ config(materialized='view') }}

-- For each minute window, compare the number of certificates that entered
-- the firehose (volume counter) against the number that were processed by
-- the detector (SUM of cert_stats_1min.count). The difference is lost events.

with

volume as (
    select
        date_trunc('minute', event_at) as window_ts,
        cast(payload->>'cert_count' as bigint) as raw_count
    from {{ ref('stg_pipeline_events') }}
    where source = 'volume_counter' and event_type = 'volume'
),

processed as (
    select
        -- cert_stats_1min uses window_end as the boundary; we align to the
        -- minute bucket so we can join against the volume counter which
        -- writes at the end of each minute.
        date_trunc('minute', cast(payload->>'window_end' as timestamptz)) as window_ts,
        sum(cast(payload->>'total_count' as bigint)) as processed_count
    from {{ source('phishing_radar', 'raw_cert_stats_1min') }}
    group by 1
),

matched as (
    select
        v.window_ts,
        v.raw_count,
        coalesce(p.processed_count, 0) as processed_count,
        greatest(v.raw_count - coalesce(p.processed_count, 0), 0) as lost_events,
        case
            when v.raw_count > 0
                then round(100.0 * greatest(v.raw_count - coalesce(p.processed_count, 0), 0) / v.raw_count, 2)
            else 0
        end as loss_pct
    from volume v
    left join processed p on v.window_ts = p.window_ts
),

latest_heartbeat as (
    select
        source,
        max(event_at) as last_heartbeat_at
    from {{ ref('stg_pipeline_events') }}
    where event_type = 'heartbeat'
    group by 1
)

select
    m.*,
    lh.last_heartbeat_at,
    case
        when m.loss_pct <= 1.0 then true
        else false
    end as is_healthy,
    case
        when lh.last_heartbeat_at is null
            or lh.last_heartbeat_at < current_timestamp - interval '2 minutes'
        then false
        else true
    end as sink_alive
from matched m
cross join (
    -- collapse the latest-heartbeat rows into a single value (the oldest of
    -- the two workers, which is the first to signal trouble)
    select min(last_heartbeat_at) as last_heartbeat_at
    from latest_heartbeat
) lh
order by m.window_ts desc
