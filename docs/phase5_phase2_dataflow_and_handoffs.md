# Phase 2: Dataflow And Handoff Map

This document lists the active end-to-end paths that must stay wired.

## Primary execution path

1. `OperatorService` launches a cycle.
2. `UnifiedCycleOrchestrator.run_cycle()` creates cycle metadata and lock state.
3. `DiscoveryEngine.run_discovery()` expands scope, observes endpoints, persists telemetry.
4. `SnapshotBuilder.build_snapshot()` converts raw observations into canonical endpoints.
5. `TemporalStateEngine.update_state()` updates presence and volatility history.
6. Trust graph replay rebuilds Layer 1 from telemetry fingerprints.
7. Layer 2 consumes fingerprints, physics, baseline, graph slice, and posture findings.
8. Layer 3 predicts from Layer 2 plus posture prediction signals.
9. Guardian produces severity, confidence, alerts, and narrative records.
10. `StorageManager` persists snapshot, temporal, graph, Layer 3 state, guardian records, and completed metadata.
11. `AggregationEngine` reads persisted artifacts through `ArtifactMigrationEngine`.
12. `EngineRuntime` and Layer 5 API serve normalized payloads to the UI.

## Signal handoff matrix

| Signal | Produced by | Persisted in | Consumed by |
| --- | --- | --- | --- |
| discovery provenance | snapshot `discovered_by` | snapshot | dashboard, endpoints, relevance scoring |
| posture signals | `DiscoveryEngine` | telemetry | Layer 2/3 enrichment, telemetry UI |
| posture findings | `DiscoveryEngine` | telemetry | Layer 2/3 posture signal builders |
| weakness signals | Layer 2 | in-memory per cycle | Layer 3 |
| prediction signals | Layer 3 | in-memory per cycle | Guardian |
| Guardian severity/confidence | Guardian | guardian records | dashboard, findings, alerts, cycle detail |
| temporal presence history | Temporal engine | temporal state | dashboard, endpoints, cycle detail |
| trust dependencies | trust graph replay | trust graph snapshot | graph UI, Layer 2 hybrid mode |

## Broken handoffs closed in Phase 2

| Break | Previous symptom | Current path |
| --- | --- | --- |
| posture findings not fed to Layer 2/3/4 | Guardian stayed flat/zero-heavy | telemetry -> orchestrator posture builders -> Layer 2/3 |
| cycle detail bundle read raw guardian shape | non-zero backend output still looked empty | storage -> migration -> bundle -> extractor |
| endpoint detail read truncated dashboard subset | missing evidence and false emptiness | direct endpoint detail read model |
| telemetry pagination stopped at first page | findings pages silently incomplete | paginated telemetry connector |

## Current active contracts only

- No active page should parse storage files directly.
- No UI page should depend on legacy raw field names.
- No analytical output is considered valid unless it can be traced from producer -> storage -> API -> UI.

