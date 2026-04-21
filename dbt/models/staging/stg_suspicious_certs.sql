-- Flattens the JSON payload written by the Kafka-to-BQ sink for the
-- `suspicious_certs` topic. The streaming layer wrote one row per flagged
-- certificate with a nested `detections` array; we keep the array for
-- downstream marts and expose a few top-level fields for filtering.
with parsed as (
    select
        received_at,
        key as primary_domain_key,
        json_value(payload, '$.seen_at') as seen_at,
        json_value(payload, '$.primary_domain') as primary_domain,
        json_value(payload, '$.issuer_cn') as issuer_cn,
        json_value(payload, '$.issuer_o') as issuer_o,
        json_value(payload, '$.fingerprint') as fingerprint,
        cast(json_value(payload, '$.max_score') as int64) as max_score,
        timestamp(json_value(payload, '$.not_before')) as not_before,
        timestamp(json_value(payload, '$.not_after')) as not_after,
        json_query_array(payload, '$.detections') as detections_raw
    from {{ source('phishing_radar', 'raw_suspicious_certs') }}
)

select
    *,
    timestamp(seen_at) as seen_at_ts
from parsed
