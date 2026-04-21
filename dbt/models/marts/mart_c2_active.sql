-- Active botnet C2 IPs with age metrics.
{{ config(materialized='table') }}

with enriched as (
    select
        *,
        cast(first_seen as date) as first_seen_date,
        date_diff('hour', last_online, now()) as hours_since_online,
        date_diff('day', first_seen, last_online) as lifespan_days
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
