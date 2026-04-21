select
    list,
    cidr,
    sbl_ref,
    split_part(cidr, '/', 1) as network_ip,
    cast(split_part(cidr, '/', 2) as integer) as prefix_length
from {{ source('phishing_radar', 'spamhaus_drop') }}
