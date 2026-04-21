-- Aggregates Spamhaus hijacked CIDRs by prefix-length band.
{{ config(materialized='table') }}

with blocks as (
    select
        list,
        prefix_length,
        case
            when prefix_length <= 16 then 'huge (/8-/16)'
            when prefix_length <= 20 then 'large (/17-/20)'
            when prefix_length <= 24 then 'medium (/21-/24)'
            else 'small (/25+)'
        end as block_size_bucket,
        pow(2, 32 - prefix_length) as addresses_in_block
    from {{ ref('stg_spamhaus') }}
)

select
    list,
    block_size_bucket,
    count(*) as block_count,
    sum(addresses_in_block) as total_addresses
from blocks
group by 1, 2
