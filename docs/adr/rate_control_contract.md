# ADR: Rate Control Contract

## Status
Accepted (Phase 0 baseline)

## Context
Discovery and expansion paths historically used local retry behavior and partial rate-controller usage.

## Decision
- `RateController` is the single retry/backoff authority for observation throttling.
- Discovery still enforces bounded retry to guarantee termination, but retry delay/cap can be sourced from `RateController`.
- Rate events are registered explicitly:
  - `register_attempt`
  - `register_success`
  - `register_timeout`
  - `register_error`
  - `register_rate_limited`

## Contract Points
- Controller: `infrastructure/unified_discovery_v2/rate_controller.py`
- Discovery consumer: `infrastructure/discovery/discovery_engine.py`
- Cycle stats sink: `infrastructure/unified_discovery_v2/unified_cycle_orchestrator.py`

## Invariants
- Retry loops are bounded.
- Missing optional rate-controller hooks must not crash discovery.
- Rate controller finalization remains deterministic.
