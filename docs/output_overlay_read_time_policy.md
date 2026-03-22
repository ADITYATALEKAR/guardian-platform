# Global Identity Overlay Policy (Phase 2)

## Rule

Historical artifacts are immutable. Global identity fields are applied as a
read-time overlay when missing.

## Write behavior

For newly written artifacts, additive identity fields may be included at write
time (`tenant_id`, `tenant_gid`, `cycle_gid`, `endpoint_gid`) where source
fields are already present.

## Historical behavior

- No in-place mutation of historical snapshot/telemetry/metadata files.
- No destructive backfill.
- Overlay is deterministic and idempotent on every read.

