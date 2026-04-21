-- Active botnet C2 IPs grouped by malware family. Drives the "who is talking to
-- whom" panel. Partitioned by first_seen so the dashboard can slice by week.
{{
    config(
        materialized='table',
        partition_by={'field': 'first_seen_date', 'data_type': 'date'},
        cluster_by=['malware_family', 'country']
    )
}}

with enriched as (
    select
        *,
        date(first_seen) as first_seen_date,
        timestamp_diff(current_timestamp(), last_online, hour) as hours_since_online,
        timestamp_diff(last_online, first_seen, day) as lifespan_days
    from {{ ref('stg_feodo') }}
)

select
    ip_address,
    port,
    hostname,
    as_number,
    as_name,
    country,
    malware_family,
    first_seen,
    first_seen_date,
    last_online,
    hours_since_online,
    lifespan_days,
    status
from enriched
where status = 'online'
