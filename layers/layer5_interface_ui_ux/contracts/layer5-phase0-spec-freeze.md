# Layer 5 Phase 0 Spec Freeze

This document is the phase-0 gate for Layer 5 implementation.
No Layer 5 API/UI implementation starts until all sections here are frozen.

## 1) Simulation Detail Source (Resolved)

Simulation detail is sourced from a dedicated endpoint:

- `GET /v1/tenants/{tenant_id}/simulations/{sim_id}`
- Source in backend adapter: simulation detail reader (not simulation list row expansion)

Rationale:
- Simulation list payload is summary-only.
- Detail page requires full simulation payload without overloading list responses.

## 2) Error Rendering Matrix (Resolved)

Layer 5 must render explicit error states:

- `401 Unauthorized`: clear session-expired state, force re-auth flow.
- `403 Forbidden`: tenant-scope violation message.
- `404 Not Found`: missing cycle/simulation message with context.
- `409 Conflict`: active-cycle/lock conflict state.
- `500 Server Error`: backend failure with request context.
- `timeout/network`: show last-known data + stale badge.

No blank-screen fallback is allowed.

## 3) Graph Rendering Contract (Resolved)

Graph tab consumes `trust_graph_snapshot` only and follows `graph-rendering-contract.md`.
Graph behavior, limits, and interactions are fixed before implementation.

## 4) Bundle vs Telemetry Responsibility Split (Resolved)

Bundle endpoint is snapshot-style:

- `GET /v1/tenants/{tenant_id}/cycles/{cycle_id}/bundle`
- Returns non-telemetry artifacts in full
- Returns telemetry summary only (`counts` + first page preview, no stream pagination contract)

Telemetry endpoint is stream-style:

- `GET /v1/tenants/{tenant_id}/cycles/{cycle_id}/telemetry`
- Owns telemetry filtering and pagination end-to-end

Bundle endpoint must not accept telemetry pagination/query controls.

## 5) Typography and Visual Semantics Locks

Frozen for implementation:

- Typography tiers: `11, 12, 13, 14, 18`.
- Primary font family: `IBM Plex Sans`.
- Data/ID font family: `IBM Plex Mono`.
- Unknown/not-observed alert line color: `#4A5568`.
- Quantum readiness badges:
  - ready: `#00C853`
  - not_ready: `#FF6D00`
  - unknown: `#546E7A`

## Phase 0 Exit Criteria

- Simulation detail endpoint contract is frozen.
- Error matrix is frozen.
- Graph rendering contract is frozen.
- Bundle vs telemetry split is frozen.
- Typography + semantic color locks are frozen.

When all are met:

- `L5_SPEC_FROZEN = True`
