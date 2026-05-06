select *
from {{ ref('mart_pipeline_health') }}
where
    -- Loss percentages should never be negative
    coalesce(ws_to_detector_loss_pct, 0) < 0
    -- Counts should never be negative
    or coalesce(ws_count, 0) < 0
    or processed_count < 0
    -- Lost events should never exceed input (allow small rounding margin)
    or ws_to_detector_lost > coalesce(ws_count, 0) + 10
