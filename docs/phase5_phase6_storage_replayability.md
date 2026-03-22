# Phase 6: Storage Integrity And Replayability

Phase 6 adds a replay/integrity report to every cycle bundle.

## Integrity contract

`cycle_bundle.integrity_summary` now reports:

- `exact_cycle_replayable`
- `served_view_complete`
- `missing_artifacts`
- `warnings`
- `fallbacks_used`
- `produced_counts`
- `persisted_counts`
- `served_counts`
- `coverage`

## Exact replay rules

`exact_cycle_replayable` is true only when the cycle has:

- cycle-specific snapshot
- cycle metadata rows
- cycle-specific temporal state
- cycle-specific trust graph snapshot
- cycle-specific Layer 3 snapshot
- no latest-state fallback required for those artifacts

## Served-view rules

`served_view_complete` is true when the API can still serve a complete deep-dive view, even if one or more per-cycle artifacts had to fall back to latest-state copies for the current cycle.

## Storage risks now surfaced

- latest-state fallback hiding a missing per-cycle artifact
- Guardian rows referencing entities not present in the served snapshot
- telemetry entities outside the canonical snapshot
- flat Guardian rows where everything served is still zero/empty

