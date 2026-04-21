-- Per-minute suspicious-cert ratio per issuing CA. Driven by the Flink tumbling
-- window output. The dashboard uses it for the "who is signing the most
-- suspicious certs right now" heatmap.
{{
    config(
        materialized='table',
        partition_by={'field': 'window_date', 'data_type': 'date'},
        cluster_by=['issuer_cn']
    )
}}

with with_ratio as (
    select
        window_end,
        date(window_end) as window_date,
        issuer_cn,
        suspicious_count,
        total_count,
        safe_divide(suspicious_count, total_count) as suspicious_ratio
    from {{ ref('stg_cert_stats') }}
    where total_count > 0
)

select * from with_ratio
