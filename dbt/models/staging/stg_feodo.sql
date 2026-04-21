select
    ip_address,
    port,
    status,
    hostname,
    as_number,
    as_name,
    country,
    cast(first_seen as timestamp) as first_seen,
    cast(last_online as timestamp) as last_online,
    malware as malware_family
from {{ source('phishing_radar', 'feodo_c2') }}
