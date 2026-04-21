-- GeoLite2 IPv4 country blocks flattened to (start_int, end_int, iso).
-- Materialised as a table so downstream IP-to-country joins don't replay
-- the CIDR parsing on every run.
{{ config(materialized='table') }}

with blocks as (
    select
        network,
        geoname_id,
        cast(split_part(split_part(network, '/', 1), '.', 1) as bigint) * 16777216
          + cast(split_part(split_part(network, '/', 1), '.', 2) as bigint) * 65536
          + cast(split_part(split_part(network, '/', 1), '.', 3) as bigint) * 256
          + cast(split_part(split_part(network, '/', 1), '.', 4) as bigint) as start_int,
        cast(split_part(network, '/', 2) as int) as prefix
    from {{ source('phishing_radar', 'geoip_country_blocks') }}
)

select
    blocks.start_int,
    blocks.start_int + cast(power(2, 32 - blocks.prefix) as bigint) - 1 as end_int,
    locs.country_iso_code,
    locs.country_name,
    locs.continent_code
from blocks
join {{ source('phishing_radar', 'geoip_country_locations') }} locs
  on blocks.geoname_id = locs.geoname_id
where locs.country_iso_code is not null
