# Phase 8: Dead Paths And Redundancy Inventory

This phase removes duplicated read-model logic where it creates competing interpretations.

## Cleanups completed

- Ownership label formatting is now centralized in `src/lib/endpointContext.ts`.
  - removed duplicate page-local ownership helpers from dashboard, endpoints, graph, and endpoint detail.
- Discovery provenance summarization is now centralized in `src/lib/endpointContext.ts`.
- Alerts page no longer maintains separate duplicated grouped filtering logic and flat filtering logic for rendered cards.
  - one grouped display path is now authoritative.
- Terminal cycle selection is now centralized in `StorageManager`.
  - `AggregationEngine.list_cycles` no longer re-implements per-cycle terminal-row ranking.
- Cycle bundle state fallback resolution is now centralized in `CycleBundleBuilder`.
  - per-cycle temporal, trust-graph, and layer3 fallback rules no longer repeat three separate load paths.

## Intentional legacy paths retained

- `ArtifactMigrationEngine` keeps compatibility aliases for old stored artifacts.
- Cycle bundle builder still allows latest-state fallback for the current cycle, but Phase 6 integrity surfaces now flag when that happens.

## Remaining dead-path candidates for later cleanup

- any UI page still reading raw cycle metadata fields directly when an extractor/read-model exists
- any future duplicate endpoint-context formatting outside `endpointContext.ts`
- deprecated runtime facades that intentionally hard-fail, such as `EngineRuntime.evaluate_cycle`, can be removed once external callers are proven absent
