# Phase 5: Analytical Semantics Validation

This document captures the analytical expectations validated in the current pipeline.

## Layer contract

| Layer | Inputs | Required semantics |
| --- | --- | --- |
| Layer 2 | fingerprints, physics, baseline, graph slice, posture weakness signals | no field-contract fallthrough to zero |
| Layer 3 | Layer 2 bundle plus posture prediction signals | posture taxonomies must be accepted, not dropped |
| Guardian | Layer 3 prediction bundle | zero signal must not be mistaken for low risk |

## Phase 5 fixes already enforced

- real fingerprint momentum/transition fields are mapped
- posture findings are converted into Layer 2 weakness signals
- posture findings are converted into Layer 3 prediction signals
- Guardian records are normalized at read time for UI/API consumers
- zero-risk rows do not count as low-risk summaries

## Validation expectations

- risky endpoints produce non-flat Guardian output
- cycle bundle exposes guardian records plus narrative/alerts when available
- UI receives canonical severity/confidence fields even for legacy stored rows
- cycle detail pages show the same artifact truth as dashboard pages

## Phase 5 regression focus

- artifact migration compatibility
- discovery/runtime outputs persisted into cycle metadata
- runtime trace preserved on completed and failed cycles
- bundle exposure of build stats, diff, rate controller stats, and runtime summary

