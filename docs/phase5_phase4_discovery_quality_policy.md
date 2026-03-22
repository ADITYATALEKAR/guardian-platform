# Phase 4: Discovery Quality And Budget Policy

This document defines the current first-scan discovery policy and how productivity is measured.

## Active first-scan strategy

The active expansion strategy is `two_phase_productive_exploitation`.

- Exploration phase:
  - all Category A modules run within the exploration budget
  - BCDE runs within the remaining exploration budget
- Exploitation phase:
  - only productive Category A modules rerun
  - only productive BCDE modules rerun

Current defaults are persisted in runtime/build stats:

- `exploration_budget_seconds`
- `exploitation_budget_seconds`
- `module_time_slice_seconds`

## Productivity scorecard contract

Cycle metadata `build_stats.expansion_summary.module_scorecard` contains one row per module:

- `category`
- `module_name`
- `invocation_count`
- `productive_runs`
- `produced_domain_count`
- `produced_endpoint_count`
- `produced_candidate_count`
- `total_elapsed_s`
- `avg_elapsed_s`
- `max_elapsed_s`
- `time_slice_exceeded_count`
- `productivity_rate_01`

## Scope-level diagnostics

Cycle metadata `build_stats.expansion_summary.scope_summaries` preserves per-scope diagnostics:

- scope name and root domain
- node/edge/candidate counts
- ceiling hit flag
- timing totals
- productive module lists
- raw module summaries

## Immediate policy decisions already encoded

- broad exploration first, productive exploitation second
- observation cap is independent from expansion cap
- module slice overruns are recorded, not ignored
- productivity is preserved in cycle artifacts for replay and tuning

## What this phase does not yet do

- persistent cross-cycle method ranking
- hard removal of weak methods from all tenants by default
- first-party attribution before every expansion decision

Those are Phase 6-9 hardening items, not Phase 4 completion blockers.

