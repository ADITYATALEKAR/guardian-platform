# ADR: Policy Activation Contract

## Status
Accepted (Phase 0 baseline)

## Context
Policy authoring and update flows live under `infrastructure/policy_integration`, while runtime enforcement lives in Layer4 and cycle orchestration.

## Decision
- Policy updates are **authoritative only after runtime sync** through `PolicyRuntimeBridge`.
- Runtime guardian evaluation consumes policy mode via orchestrator wiring, never by direct reads from update executors.
- If policy storage is unavailable, cycle execution fails loud or falls back to explicitly logged `policy_mode=disabled` behavior.

## Contract Points
- Producer: `infrastructure/policy_integration/policies/updates/policy_update_executor.py`
- Runtime sync: `infrastructure/policy_integration/enforcement/policy_runtime_bridge.py`
- Consumer: `infrastructure/unified_discovery_v2/unified_cycle_orchestrator.py`
- Enforcement: `layers/layer4_decision_logic_guardian/core/guardian_core.py`

## Invariants
- No hidden policy source bypasses runtime bridge.
- Policy state transitions must be observable in cycle metadata.
- Legacy Layer4 path is compatibility-only and not authoritative.
