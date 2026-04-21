-- GeoLite2-City IPv4 blocks flattened to (start_int, end_int, lat, lon, iso, city).
-- 3.7M rows; materialised as a table so the IP-to-location range join runs
-- against pre-computed integer bounds instead of parsing CIDR every time.
{{ config(materialized='table') }}

with blocks as (
    select
        network,
        geoname_id,
        latitude,
        longitude,
        accuracy_radius,
        cast(split_part(split_part(network, '/', 1), '.', 1) as bigint) * 16777216
          + cast(split_part(split_part(network, '/', 1), '.', 2) as bigint) * 65536
          + cast(split_part(split_part(network, '/', 1), '.', 3) as bigint) * 256
          + cast(split_part(split_part(network, '/', 1), '.', 4) as bigint) as start_int,
        cast(split_part(network, '/', 2) as int) as prefix
    from {{ source('phishing_radar', 'geoip_city_blocks') }}
    where latitude is not null
)

select
    blocks.start_int,
    blocks.start_int + cast(power(2, 32 - blocks.prefix) as bigint) - 1 as end_int,
    blocks.latitude,
    blocks.longitude,
    blocks.accuracy_radius,
    locs.country_iso_code,
    locs.country_name,
    locs.city_name,
    locs.subdivision_1_name as region_name,
    locs.continent_code
from blocks
join {{ source('phishing_radar', 'geoip_city_locations') }} locs
  on blocks.geoname_id = locs.geoname_id
where locs.country_iso_code is not null
