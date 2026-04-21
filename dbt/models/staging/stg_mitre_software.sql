select
    id,
    attack_id,
    type as software_type,
    name,
    description,
    is_family,
    revoked
from {{ source('phishing_radar', 'mitre_software') }}
where not revoked
