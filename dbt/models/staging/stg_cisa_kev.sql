select
    cve_id,
    vendor,
    product,
    name as vuln_name,
    parse_date('%Y-%m-%d', date_added) as date_added,
    parse_date('%Y-%m-%d', due_date) as due_date,
    description,
    required_action,
    known_ransomware_use,
    notes,
    date_released,
    catalog_version
from {{ source('phishing_radar', 'cisa_kev') }}
