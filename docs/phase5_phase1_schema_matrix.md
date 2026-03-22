# Phase 1: Canonical Schema Matrix

This document is the Phase 1 source of truth for runtime shapes consumed by storage, API, and UI.

## Canonical artifacts

| Artifact | Canonical version | Producer | Stored location | API/UI consumers |
| --- | --- | --- | --- | --- |
| Snapshot | `1.2` | `SnapshotBuilder` | `snapshots/cycle_*.json` | dashboard, endpoints, cycle bundle |
| Cycle metadata | `v2.6` | `UnifiedCycleOrchestrator` | `cycle_metadata/metadata.jsonl` | cycles, cycle detail, scan status |
| Telemetry | `v1` | `DiscoveryEngine` | `telemetry/cycle_*.jsonl` | telemetry API, cycle bundle |
| Temporal state | `v1` | `TemporalStateEngine` | `temporal_state/state.json`, `temporal_state/cycle_*.json` | dashboard, endpoints, cycle bundle |
| Trust graph snapshot | `1` | `TrustGraph` replay | `trust_graph/latest.json`, `trust_graph/cycle_*.json` | graph, cycle bundle |
| Layer 3 state | `v3` | `Layer3Engine` | `layer3_state/latest.json`, `layer3_state/cycle_*.json` | cycle bundle |
| Guardian records | `v1` | `GuardianCore` via orchestrator | `guardian_records/metadata.jsonl` | dashboard, findings, alerts, cycle bundle |

## Contract ownership

| Boundary | Canonicalizer | Notes |
| --- | --- | --- |
| persisted artifact -> runtime object | `ArtifactMigrationEngine` | compatibility aliases live only here |
| runtime object -> API payload | `AggregationEngine`, `EngineRuntime` | no page should parse raw storage quirks |
| API payload -> UI read model | `extractors.ts`, `master_data_connector_to_layer4.ts` | UI consumes normalized DTOs only |

## Canonical field rules

| Field family | Rule |
| --- | --- |
| severity / confidence | `0.0-1.0` canonical; legacy aliases allowed at read time only |
| status | lowercase in served payloads |
| timestamps | Unix milliseconds |
| endpoint identity | canonical `entity_id = hostname:port` |
| missing risk | do not coerce to low risk |
| temporal state | canonical storage shape is `endpoints` map; UI may derive arrays |

## Known compatibility aliases retained

| Canonical field | Legacy field(s) accepted |
| --- | --- |
| `overall_severity_01` | `severity` |
| `overall_confidence_01` | `confidence` |
| `snapshot_hash_sha256` | `snapshot_hash` |
| `status` | mixed-case persisted values, normalized at read time |

## Mismatch register closed in Phase 1

| Area | Previous mismatch | Current owner/fix |
| --- | --- | --- |
| Guardian bundle | UI expected `overall_*`; storage had `severity/confidence` | `ArtifactMigrationEngine` |
| Temporal bundle | UI expected rows; storage held `endpoints` map | `extractors.ts` |
| Endpoint detail | UI read dashboard subset instead of canonical row | `AggregationEngine.get_endpoint_detail` |
| Risk distribution | zero severity was counted as low | `AggregationEngine` |

