-- abuse.ch ThreatFox botnet C2 IoCs. Complement to Feodo Tracker: broader
-- malware family coverage but no country/ASN info (we geolocate via MaxMind
-- downstream).
select
    ioc_type,
    ioc_value,
    ip_address,
    port,
    malware as malware_family,
    malware_alias,
    threat_type,
    confidence_level,
    cast(first_seen_utc as timestamp) as first_seen,
    cast(last_seen_utc as timestamp) as last_seen,
    tags,
    reporter
from {{ source('phishing_radar', 'threatfox_iocs') }}
