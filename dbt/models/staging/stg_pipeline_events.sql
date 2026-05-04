with source as (
    select * from {{ source('phishing_radar', 'raw_pipeline_events') }}
),

renamed as (
    select
        event_at,
        source,
        event_type,
        payload
    from source
)

select * from renamed
