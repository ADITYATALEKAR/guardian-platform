# Layer 5 API Contract v1 (Spec Freeze)

This contract defines Layer 5 API responsibilities and response ownership.

## Auth

- `POST /v1/auth/login`
- `POST /v1/auth/logout`
- `GET /v1/auth/me`

## Operator Admin (Phase 5)

- `POST /v1/admin/operators/register`
  - Bootstrap mode: allowed without session only when no operators exist.
  - Normal mode: requires authenticated session.
- `POST /v1/admin/tenants/register`
  - Requires authenticated session.
  - `operator_id` is derived from the authenticated session context.

## Runtime Read Endpoints

### Dashboard
- `GET /v1/tenants/{tenant_id}/dashboard`
- Source: `EngineRuntime.build_dashboard(...)`

### Cycle Bundle (snapshot-style)
- `GET /v1/tenants/{tenant_id}/cycles/{cycle_id}/bundle`
- Source: `EngineRuntime.build_cycle_artifact_bundle(...)`
- Contains:
  - snapshot
  - cycle metadata rows
  - guardian records
  - temporal/trust/layer3 latest-state payloads when applicable
  - telemetry summary only
- Must NOT accept:
  - `record_type`
  - `page`
  - `page_size`
  - `telemetry_page`
  - `telemetry_page_size`

### Cycle Telemetry (stream-style)
- `GET /v1/tenants/{tenant_id}/cycles/{cycle_id}/telemetry`
- Source: `EngineRuntime.get_cycle_telemetry(...)`
- Owns:
  - filter: `record_type`
  - pagination: `page`, `page_size`

### Simulation List
- `GET /v1/tenants/{tenant_id}/simulations`
- Source: `EngineRuntime.list_simulations(...)`
- Summary payload only

### Simulation Detail
- `GET /v1/tenants/{tenant_id}/simulations/{sim_id}`
- Source: simulation detail adapter (single-simulation payload)

## Tenant Scope

All tenant endpoints require authorized tenant scope from validated session.

Any tenant mismatch must return `403` with explicit error payload.
