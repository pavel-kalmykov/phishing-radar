select
    ip_address,
    port,
    status,
    hostname,
    as_number,
    as_name,
    country,
    timestamp(first_seen) as first_seen,
    timestamp(last_online) as last_online,
    malware as malware_family
from {{ source('phishing_radar', 'feodo_c2') }}
