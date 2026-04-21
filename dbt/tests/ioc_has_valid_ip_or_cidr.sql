-- Custom singular test: every Feodo C2 row must have a dotted IPv4.
-- Catches accidental schema shifts from upstream (abuse.ch API format drift).
select ip_address
from {{ ref('stg_feodo') }}
where not regexp_matches(ip_address, '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
