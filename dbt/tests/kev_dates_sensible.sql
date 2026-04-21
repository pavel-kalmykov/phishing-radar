-- Singular test: due_date should always be on or after date_added.
select cve_id, date_added, due_date
from {{ ref('stg_cisa_kev') }}
where due_date is not null and date_added is not null and due_date < date_added
