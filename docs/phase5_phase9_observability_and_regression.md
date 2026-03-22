# Phase 9: Observability And Regression

Phase 9 adds persisted and served counters plus replay-oriented regression checks.

## Observability counters

Cycle integrity now reports:

- produced counts
  - discovered candidates
  - observations
  - canonical endpoints
- persisted counts
  - metadata rows
  - snapshot endpoints
  - telemetry rows
  - guardian rows
  - temporal entries
  - graph nodes/edges
  - Layer 3 entities
- served counts
  - snapshot endpoints served
  - telemetry preview rows served
  - guardian rows served
  - temporal entries served
  - graph nodes/edges served
  - Layer 3 entities served

## Regression gates

Review tests now cover:

- expansion/runtime contract persistence
- replay integrity truth in cycle bundles
- latest-state fallback detection
- scheduler state surfacing in scan status

## Operational intent

When the system is flat or incomplete, operators should be able to tell whether the failure happened:

- before persistence
- during artifact persistence
- during API shaping
- during UI read-model rendering

