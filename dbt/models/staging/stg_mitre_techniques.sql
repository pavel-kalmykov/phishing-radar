-- dlt extracts list fields (kill_chain_phases, platforms, data_sources) into
-- child tables with names like `mitre_techniques__kill_chain_phases`. For the
-- staging model we only expose the scalar fields; downstream marts that need
-- the arrays should join the child tables directly.
select
    id,
    attack_id,
    name,
    description,
    is_subtechnique,
    revoked
from {{ source('phishing_radar', 'mitre_techniques') }}
where not revoked
