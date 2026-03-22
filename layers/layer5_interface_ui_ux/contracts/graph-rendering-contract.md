# Graph Rendering Contract (Layer 5)

## Data Source

- Endpoint source: cycle artifact bundle (`trust_graph_snapshot`) for selected cycle.
- No alternate graph source is allowed in Phase 1.

## Expected Payload Shape

`trust_graph_snapshot` must include:

- `version: int`
- `created_at_ms: int`
- `nodes: list`
- `edges: list`

Unknown or missing graph payload renders an explicit empty-state panel.

## Rendering Semantics

- Layout: deterministic force-directed layout with fixed seed.
- Node size: fixed in Phase 1 (no risk-driven scaling yet).
- Node color: monochrome baseline.
- Edge style: thin neutral stroke, optional hover highlight.
- Density guardrails:
  - if node/edge count exceeds client threshold, switch to sampled/clustered view
  - no unbounded DOM node rendering

## Interaction Semantics

- Node click:
  - opens side panel with node metadata
  - no route change required
- Edge click:
  - opens relation metadata panel
- Hover:
  - highlight node/edge only; no animated pulses
- Zoom/pan:
  - enabled with bounds

## Failure/Unknown Handling

- Graph fetch error uses interaction error matrix.
- Missing graph for cycle:
  - explicit `Graph unavailable for this cycle` state
- Corrupt graph payload:
  - explicit `Graph payload invalid` state

## Accessibility

- Keyboard navigation for node selection required.
- Tooltips/panels must expose text alternatives.
