-- Tumbling-window aggregates produced by the detector, one row per (issuer, minute).
with parsed as (
    select
        received_at,
        cast(json_extract_string(payload, '$.window_end') as timestamp) as window_end,
        json_extract_string(payload, '$.issuer_cn') as issuer_cn,
        cast(json_extract_string(payload, '$.suspicious_count') as integer) as suspicious_count,
        cast(json_extract_string(payload, '$.total_count') as integer) as total_count
    from {{ source('phishing_radar', 'raw_cert_stats_1min') }}
)

select * from parsed
