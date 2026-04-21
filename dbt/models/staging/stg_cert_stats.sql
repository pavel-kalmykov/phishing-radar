-- Tumbling-window aggregates produced by the Flink job, one row per (issuer, minute).
with parsed as (
    select
        received_at,
        timestamp(json_value(payload, '$.window_end')) as window_end,
        json_value(payload, '$.issuer_cn') as issuer_cn,
        cast(json_value(payload, '$.suspicious_count') as int64) as suspicious_count,
        cast(json_value(payload, '$.total_count') as int64) as total_count
    from {{ source('phishing_radar', 'raw_cert_stats_1min') }}
)

select * from parsed
