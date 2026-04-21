select
    list,
    cidr,
    sbl_ref,
    -- Extract the first IP of the CIDR for quick display
    split(cidr, '/')[offset(0)] as network_ip,
    cast(split(cidr, '/')[offset(1)] as int64) as prefix_length
from {{ source('phishing_radar', 'spamhaus_drop') }}
