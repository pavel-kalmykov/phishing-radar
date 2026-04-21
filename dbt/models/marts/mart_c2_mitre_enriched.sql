-- Join Feodo C2 entries with MITRE ATT&CK software catalog on name.
{{ config(materialized='table') }}

select
    c.ip_address,
    c.port,
    c.country,
    c.as_name,
    c.malware_family,
    c.source,
    c.first_seen,
    c.first_seen_date,
    c.last_seen,
    c.hours_since_seen,
    m.attack_id as mitre_attack_id,
    m.description as mitre_description
from {{ ref('mart_c2_active') }} c
left join {{ ref('mart_mitre_malware_catalog') }} m
    on lower(c.malware_family) = m.name_lower
