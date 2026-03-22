# ADR: Simulation Execution Contract

## Status
Accepted (Phase 0 baseline)

## Context
Simulator consumes production artifacts and writes isolated simulation outputs. Determinism and isolation are non-negotiable.

## Decision
- Deterministic `sim_id` computed from tenant, baseline cycle, baseline hash, scenario, and mitigation params.
- Cache short-circuit is allowed only on exact `sim_id` match.
- Production artifacts are read-only during simulation; mutation triggers fail-loud.
- Scenario catalog and technique rules are config-driven with schema/version validation.

## Contract Points
- Simulation entry: `simulator/core/simulation_service.py`
- Persistence: `simulator/storage/simulation_storage.py`
- Scenario catalog: `simulator/scenarios/scenario_catalog.py`
- Baseline loading: `simulator/core/baseline_loader.py`

## Invariants
- Same request -> same `sim_id` -> same response payload.
- No writes into production tenant storage paths.
- Invalid scenario/rule config fails loud.
