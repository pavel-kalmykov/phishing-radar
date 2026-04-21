-- Join Feodo C2 entries with MITRE ATT&CK to give each malware family its
-- canonical ATT&CK ID and description. Fuzzy match on lowercased name so
-- "Heodo" -> "Emotet" and similar aliases resolve via MITRE's alias list upstream.
{{
    config(
        materialized='table',
        partition_by={'field': 'first_seen_date', 'data_type': 'date'},
        cluster_by=['malware_family']
    )
}}

select
    c.ip_address,
    c.port,
    c.country,
    c.as_name,
    c.malware_family,
    c.first_seen,
    c.first_seen_date,
    c.last_online,
    c.hours_since_online,
    m.attack_id as mitre_attack_id,
    m.description as mitre_description
from {{ ref('mart_c2_active') }} c
left join {{ ref('mart_mitre_malware_catalog') }} m
    on lower(c.malware_family) = m.name_lower
