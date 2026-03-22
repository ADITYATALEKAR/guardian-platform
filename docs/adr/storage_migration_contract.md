# ADR: Storage Migration Contract

## Status
Accepted (Phase 0 baseline)

## Context
Artifacts across cycles can exist in mixed schema versions; destructive rewrites are risky for audit trails.

## Decision
- Migrations are **read-time overlays** through `ArtifactMigrationEngine`.
- Historical artifacts are not mutated in-place.
- Runtime/API consumers receive normalized payloads with stable keys.

## Contract Points
- Migration engine: `infrastructure/aggregation/artifact_migration.py`
- Bundle builder: `infrastructure/aggregation/cycle_bundle_builder.py`
- Dashboard/telemetry consumers: `infrastructure/aggregation/aggregation_engine.py`, `infrastructure/aggregation/telemetry_query.py`
- Version matrix: `infrastructure/aggregation/artifact_version_matrix.py`

## Invariants
- Backward compatibility for legacy artifact versions.
- Fail-loud on structurally invalid payloads.
- Deterministic normalization output for same input.
