select
    cve_id,
    vendor,
    product,
    name as vuln_name,
    cast(date_added as date) as date_added,
    cast(due_date as date) as due_date,
    description,
    required_action,
    known_ransomware_use,
    notes,
    date_released,
    catalog_version
from {{ source('phishing_radar', 'cisa_kev') }}
