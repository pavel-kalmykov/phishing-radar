{{ config(materialized='view') }}

-- Pipeline health: single-hop event loss monitoring.
--
-- Hop — WebSocket → Detector: certstream_producer writes producer_volume events
-- with ws_cert_count (certs received from the CertStream firehose). The detector
-- consumes certstream_events and emits cert_stats_1min with total_count per window.
-- ws_to_detector_lost = ws_count - processed_count.
--
-- is_healthy requires loss percentage ≤ 1%.

with

producer_volume as (
    select
        date_trunc('minute', event_at) as window_ts,
        cast(payload->>'ws_cert_count' as bigint) as ws_count
    from {{ ref('stg_pipeline_events') }}
    where source = 'certstream_producer' and event_type = 'producer_volume'
),

processed as (
    select
        date_trunc('minute', cast(payload->>'window_end' as timestamptz)) as window_ts,
        sum(cast(payload->>'total_count' as bigint)) as processed_count
    from {{ source('phishing_radar', 'raw_cert_stats_1min') }}
    group by 1
),

matched as (
    select
        coalesce(pv.window_ts, pr.window_ts) as window_ts,
        pv.ws_count,
        coalesce(pr.processed_count, 0) as processed_count,
        greatest(coalesce(pv.ws_count, 0) - coalesce(pr.processed_count, 0), 0)
            as ws_to_detector_lost,
        case
            when pv.ws_count is not null and pv.ws_count > 0
                then round(
                    100.0 * greatest(coalesce(pv.ws_count, 0) - coalesce(pr.processed_count, 0), 0)
                    / pv.ws_count, 2
                )
        end as ws_to_detector_loss_pct
    from producer_volume pv
    full outer join processed pr on pv.window_ts = pr.window_ts
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
        when coalesce(m.ws_to_detector_loss_pct, 0) <= 1.0
        then true
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
    select min(last_heartbeat_at) as last_heartbeat_at
    from latest_heartbeat
) lh
order by m.window_ts desc
