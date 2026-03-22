# Output Connector Usage

## `build_dashboard`

Use for lightweight tenant overviews:
- Health summary cards
- Risk distribution
- Endpoint table preview

Does not include full cycle artifacts.

## `build_cycle_artifact_bundle`

Use for single-cycle deep-dive views:
- Snapshot payload
- Cycle metadata rows
- Cycle telemetry rows (filter/paginated)
- Guardian records for the cycle
- Latest-state artifacts (`temporal_state`, `trust_graph_snapshot`, `layer3_state_snapshot`) when requested cycle is latest

Always returns stable keys. Missing sections are explicit (`null` / `[]`), not omitted.

## `get_cycle_telemetry`

Use for telemetry stream pagination and filtering:
- `record_type=all`
- `record_type=fingerprints`
- `record_type=posture_signals`
- `record_type=posture_findings`

## `list_simulations`

Use for simulation list views. Rows are built from simulation payload metadata
and deterministic file timestamps, not filename parsing heuristics.
