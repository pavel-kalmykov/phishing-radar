-- Active botnet C2 IPs. Combines Feodo Tracker (curated, small, has country)
-- with ThreatFox (crowd-sourced, broader, IP only). Geolocation via MaxMind
-- GeoLite2 blocks for ThreatFox rows that lack country.
{{ config(materialized='table') }}

with feodo as (
    select
        'feodo' as source,
        ip_address,
        port,
        hostname,
        cast(as_number as varchar) as as_number,
        as_name,
        country,
        malware_family,
        first_seen,
        last_online as last_seen,
        status,
        cast(null as int) as confidence_level
    from {{ ref('stg_feodo') }}
    where status = 'online'
),

threatfox_ips as (
    select
        'threatfox' as source,
        ip_address,
        port,
        cast(null as varchar) as hostname,
        cast(null as varchar) as as_number,
        cast(null as varchar) as as_name,
        cast(null as varchar) as country,
        malware_family,
        first_seen,
        last_seen,
        'online' as status,
        confidence_level
    from {{ ref('stg_threatfox') }}
    where ioc_type = 'ip:port'
      and ip_address is not null
      and confidence_level >= 50
),

unioned as (
    select * from feodo
    union all
    select * from threatfox_ips
),

-- Integer form of the IP for a range join against stg_geoip_country
with_ip_int as (
    select
        *,
        try_cast(split_part(ip_address, '.', 1) as bigint) * 16777216
          + try_cast(split_part(ip_address, '.', 2) as bigint) * 65536
          + try_cast(split_part(ip_address, '.', 3) as bigint) * 256
          + try_cast(split_part(ip_address, '.', 4) as bigint) as ip_int
    from unioned
),

geolocated as (
    select
        u.source,
        u.ip_address,
        u.port,
        u.hostname,
        u.as_number,
        u.as_name,
        coalesce(u.country, g.country_iso_code) as country,
        g.country_name,
        g.continent_code,
        u.malware_family,
        u.first_seen,
        u.last_seen,
        u.status,
        u.confidence_level,
        date_diff('day', u.first_seen, u.last_seen) as lifespan_days,
        date_diff('hour', u.last_seen, now()) as hours_since_seen
    from with_ip_int u
    left join {{ ref('stg_geoip_country') }} g
      on u.ip_int between g.start_int and g.end_int
)

-- Dedupe: if Feodo and ThreatFox both report the same IP, keep Feodo (curated).
select distinct on (ip_address)
    source,
    ip_address,
    port,
    hostname,
    as_number,
    as_name,
    country,
    country_name,
    continent_code,
    malware_family,
    first_seen,
    cast(first_seen as date) as first_seen_date,
    last_seen,
    hours_since_seen,
    lifespan_days,
    status,
    confidence_level
from geolocated
order by ip_address, case when source = 'feodo' then 0 else 1 end
