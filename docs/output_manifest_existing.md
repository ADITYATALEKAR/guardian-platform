# Output Manifest (Existing Backend Artifacts)

This manifest lists existing persisted/in-memory outputs without inventing new
data products.

## Runtime cycle artifacts

- `CycleResult.metadata` (in-memory return)
- `CycleResult.snapshot` (in-memory return + persisted snapshot file)
- `CycleResult.diff` (in-memory return)
- `CycleResult.rate_controller_stats` (in-memory return)
- `CycleResult.build_stats` (in-memory return)

Completed cycle metadata rows also persist existing runtime outputs:
- `cycle_metadata[].build_stats`
- `cycle_metadata[].diff`
- `cycle_metadata[].rate_controller_stats`

## Persisted tenant artifacts

- `cycle_metadata/metadata.jsonl`
- `snapshots/<cycle_id>.json`
- `telemetry/<cycle_id>.jsonl`
- `temporal_state/state.json`
- `layer0_baseline.json`
- `trust_graph/latest.json` (+ per-cycle graph snapshot)
- `layer3_state/layer3_state_snapshot.json`
- `guardian_records/metadata.jsonl`

## Simulator artifacts

- `simulation_storage/tenants/<tenant_id>/simulations/<sim_id>.json`

## Global identity overlay (phase-1 contract only)

Derived IDs are deterministic and tenant-scoped:

- `tenant_gid = sha256("gid_v1|tenant|{tenant_id}")`
- `cycle_gid = sha256("gid_v1|cycle|{tenant_id}|{cycle_id}")`
- `endpoint_gid = sha256("gid_v1|endpoint|{tenant_id}|{hostname}|{port}")`
