# Phase 7: UI Evidence Audit

The UI now exposes endpoint context more consistently across investigation surfaces.

## Evidence surfaces

- Endpoint detail:
  - ownership
  - ownership confidence
  - relevance score
  - relevance narrative
  - discovery provenance
  - graph context
- Alerts:
  - ownership label
  - relevance score
  - discovery provenance summary
  - why-it-matters narrative above each alert card
- Findings:
  - endpoint ownership
  - relevance score
  - discovery provenance summary
  - why-it-matters narrative in expanded finding detail
- Cycle detail:
  - runtime trace
  - expansion productivity
  - replay integrity

## UI read-model rule

Pages should summarize different aspects of the same backend truth, not invent independent defaults.

