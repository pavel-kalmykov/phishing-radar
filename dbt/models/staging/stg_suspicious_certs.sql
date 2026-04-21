-- Flattens the JSON payload written by the Kafka-to-MotherDuck sink for the
-- `suspicious_certs` topic. Keeps the `detections` array for downstream marts
-- and exposes a few top-level fields for filtering.
with parsed as (
    select
        received_at,
        key as primary_domain_key,
        json_extract_string(payload, '$.seen_at') as seen_at,
        json_extract_string(payload, '$.primary_domain') as primary_domain,
        json_extract_string(payload, '$.issuer_cn') as issuer_cn,
        json_extract_string(payload, '$.issuer_o') as issuer_o,
        json_extract_string(payload, '$.fingerprint') as fingerprint,
        cast(json_extract_string(payload, '$.max_score') as integer) as max_score,
        cast(json_extract_string(payload, '$.not_before') as timestamp) as not_before,
        cast(json_extract_string(payload, '$.not_after') as timestamp) as not_after,
        json_extract(payload, '$.detections') as detections_raw
    from {{ source('phishing_radar', 'raw_suspicious_certs') }}
)

select
    *,
    cast(seen_at as timestamp) as seen_at_ts
from parsed
