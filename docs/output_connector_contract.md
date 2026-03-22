# Output Connector Contract

## Connector ownership

- `EngineRuntime` is the UI/API-facing connector.
- `AggregationEngine` is the data composition layer.
- `StorageManager` is persistence only and must not be called directly from UI.

## Authorization contract (phase-1)

- Connector/query methods must accept an authorization scope containing
  `authorized_tenant_ids`.
- Reads for tenant data must be rejected if the tenant is outside scope.
- EngineRuntime must enforce authz and AggregationEngine must independently
  enforce the same authz scope (defense in depth).

## Query contracts (phase-3)

- `build_dashboard(tenant_id, authz_scope=...)`
- `build_cycle_artifact_bundle(tenant_id, authz_scope=..., cycle_id=...)`
- `get_cycle_telemetry(tenant_id, cycle_id, authz_scope=..., record_type, page, page_size)`
- `list_simulations(tenant_id, authz_scope=..., page, page_size)`

Telemetry `record_type` values:
- `all`
- `fingerprints`
- `posture_signals`
- `posture_findings`

## Multi-tenant safety requirements

- All tenant reads are strict (`tenant must already exist`).
- Tenant IDs must reject path traversal sequences.
- Global IDs are tenant-scoped by contract.
