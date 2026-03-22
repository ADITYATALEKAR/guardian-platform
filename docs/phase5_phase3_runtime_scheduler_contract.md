# Phase 3: Runtime And Scheduler Contract

This document defines the runtime state expected for every tenant cycle.

## Runtime state machine

Expected orchestrator stage progression:

1. `initializing`
2. `discovery`
3. `snapshot_build`
4. `temporal_update`
5. `observation_processing`
6. `trust_graph_replay`
7. `layer_evaluation`
8. `artifact_persist`
9. terminal: `completed` or `failed`

The terminal metadata row must carry:

- `runtime_summary.status`
- `runtime_summary.total_runtime_ms`
- `runtime_summary.within_budget`
- `runtime_summary.stage_history`
- `runtime_summary.progress_snapshot`

## Scheduler contract

Per-tenant scheduler state lives in `scheduler_state.json` and should include:

- `last_run_unix_ms`
- `next_run_unix_ms`
- `last_status`
- `consecutive_failures`
- optional `last_error`

`EngineRuntime.get_scan_status()` surfaces that state in:

- `scheduler_last_run_unix_ms`
- `scheduler_next_run_unix_ms`
- `scheduler_last_status`
- `scheduler_consecutive_failures`
- `scheduler_last_error`

## Failure handling expectations

- active cycle lock blocks overlapping execution
- stale cycle locks are cleaned up
- corrupt scheduler state is treated as recoverable
- failed cycles append a failed metadata row instead of silently disappearing
- latest-state artifacts are written only after per-cycle artifacts are available

## Runtime checklist

- onboarding launches a cycle
- background scheduler keeps launching due cycles
- scan status shows stage and budget progress while a cycle is running
- completed/failed metadata rows preserve runtime trace after the lock is gone

