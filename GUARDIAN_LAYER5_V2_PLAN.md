# Guardian Layer 5 — v2 Implementation Plan

**Status**: FINAL — Ready for execution review
**Date**: 2026-03-08
**Scope**: Complete rebuild of Layer 5 UI/UX from monolithic MVP to enterprise-grade cybersecurity investigation platform

---

## 1. Executive Summary

Guardian Layer 5 is a working but architecturally brittle frontend. The current UI is a 2,224-line monolithic React component with 45 state variables, 237 inline style blocks, no routing, no session persistence, and no component decomposition. It works as an MVP console but cannot scale to the investigation-grade experience Guardian's backend deserves.

The backend is strong: 16 API routes, deterministic analytical pipeline (L0-L4), 40+ field EndpointDTO, full cycle bundle access, simulation support, and solid tenant isolation. The UI does not yet surface this richness.

**This plan prescribes a shell-first rebuild** using a strangler-fig migration pattern. We build a new app shell (sidebar + topbar + React Router), then extract each tab from the monolith into a standalone page component, connect it to the existing data connectors (which are solid and preserved), and delete the monolith when empty. The rebuild is 4 phases over ~4-5 weeks of focused work.

**Key corrections from v1 plan:**
- The frontend EXISTS — this is a migration, not greenfield
- 3 of 4 "missing APIs" from v1 are not actually missing — data is derivable from existing endpoints
- Endpoint Detail is elevated to the single most important page
- Notes/Tasks are included with a clear persistence strategy
- Visual system is fully specified, not hand-waved
- Migration order is explicit: what to keep, what to kill, what order to move

**Recommendation: Proceed. The rebuild is justified, achievable, and the backend is ready.**

---

## 2. Final Product Philosophy for Layer 5

Layer 5 is an **operational investigation workspace for cybersecurity posture analysts at banks and institutions**. It is not a generic SaaS dashboard. It is not a monitoring tool. It is not a settings panel with charts.

**The UI must answer these questions, in this order:**
1. What is the current risk posture of my institution's external attack surface?
2. Which endpoints are most at risk and why?
3. What specific weaknesses and findings exist?
4. What has changed since the last scan?
5. What does the Guardian's analytical engine recommend I worry about?
6. Can I simulate what would happen if conditions change?
7. Can I export evidence for compliance and reporting?

**The UI must feel:**
- Operational (analyst sits in this tool during working hours)
- Credible (an auditor or CISO looking over the analyst's shoulder should feel confidence)
- Dense but clear (high information per pixel, no visual waste)
- Investigation-ready (every data point is clickable, drillable, traceable)
- Compliant (exportable evidence, provenance visible everywhere)

---

## 3. Core Design Principles

1. **Object-centric**: The endpoint is the primary entity. Everything orbits it.
2. **Risk-first**: Lead with severity, not system health. Show what's broken before what's fine.
3. **Evidence-on-demand**: Show summary immediately, raw evidence on click/expand. Never dump.
4. **Cross-surface drill-down**: Every entity (endpoint, finding, alert, cycle) links to its detail and related surfaces.
5. **Provenance everywhere**: Cycle ID, snapshot hash, first/last seen, discovery source visible on every view.
6. **Stable shell**: Fixed sidebar + topbar. Only content scrolls. No layout shifts.
7. **Left-filter / right-content**: Filters on the left rail, data on the right. F-shaped scan pattern.
8. **Compact density**: 36-40px table rows, 16px consistent padding, no decorative whitespace.
9. **Progressive disclosure**: Important first, detail on demand. Expandable rows, tabbed detail views.
10. **No decoration**: No pie charts, no gradients, no animations except functional transitions.

---

## 4. Current-State Audit of Existing Layer 5 Frontend

### File Inventory
| File | Lines | Role |
|------|-------|------|
| src/App.tsx | 2,224 | Monolithic app — all 10 tabs, all state, all rendering |
| src/components/GraphViewer.tsx | 433 | Force-directed trust graph viewer (SVG) |
| src/app-shell.css | 424 | Layout classes (.g-shell, .g-sidebar, .g-topbar, etc.) |
| src/main.tsx | 11 | React DOM entry |
| data_source/data_connector_to_ui.ts | 336 | HTTP API client (Layer5ApiConnector) |
| data_source/master_data_connector_to_layer4.ts | 183 | Session-aware data source (Layer5DataSource) |
| data_source/mock_data_master.ts | 28 | Test fixtures (unused) |
| contracts/design-tokens.css | 57 | CSS custom properties (colors, fonts, spacing) |
| contracts/tailwind.config.ts | 80 | Tailwind theme (not actively used) |
| contracts/global.css | 26 | Base styles + font imports |

**Total**: ~3,800 lines across ~10 source files.

### Structural Problems
1. **Monolith**: All 10 tabs rendered as conditional blocks inside one 2,224-line component
2. **45 state variables**: Auth, data, UI, form inputs — all in one useState soup
3. **237 inline style objects**: CSSProperties scattered throughout, not using Tailwind
4. **No routing**: Tab switching via `useState<ConsoleTab>` — no URLs, no back button, no bookmarks
5. **No session persistence**: Session stored in React state — lost on page refresh
6. **Dual design systems**: design-tokens.css defines one color scheme, tailwind.config.ts defines another — neither is enforced consistently
7. **React Router installed but unused**: Dead dependency
8. **No empty states, no skeleton loaders, no error boundaries**
9. **No component decomposition**: Only GraphViewer is extracted

### What Works
1. **Data connectors are solid**: Clean HTTP client + session wrapper, 14 API methods, proper error handling
2. **GraphViewer is well-built**: Self-contained, deterministic layout, SVG rendering, zoom/pan, node selection
3. **app-shell.css is a good foundation**: 286px sidebar, 52px topbar, proper layout grid
4. **Design tokens exist**: Color palette, typography scale, spacing rhythm — just not enforced
5. **Vite proxy config works**: API calls properly proxied to backend

---

## 5. Keep / Replace / Refactor / Remove Matrix

| Asset | Decision | Rationale |
|-------|----------|-----------|
| **GraphViewer.tsx** | **KEEP** | Well-architected, 433 lines, SVG graph with interaction. Import directly into new Graph page. |
| **Layer5ApiConnector** (data_connector_to_ui.ts) | **KEEP** | Solid HTTP client with 14 methods, proper error handling, configurable. No changes needed. |
| **Layer5DataSource** (master_data_connector_to_layer4.ts) | **KEEP** | Clean session wrapper. Extend with new extraction methods, don't rewrite. |
| **app-shell.css** | **REFACTOR** | Good layout classes (.g-shell, .g-sidebar, .g-topbar). Clean up, remove unused rules, consolidate with tokens. |
| **design-tokens.css** | **REFACTOR** | Migrate CSS custom properties into Tailwind theme config as single source of truth. Keep as CSS vars for non-Tailwind usage. |
| **contracts/tailwind.config.ts** | **REFACTOR** | Merge with design-tokens.css values. Make it the canonical theme. |
| **vite.config.ts** | **KEEP** | Proxy config works. No changes needed. |
| **package.json** | **KEEP** | Dependencies correct. Add: zustand, @tanstack/react-table. React Router already installed. |
| **App.tsx** | **REPLACE** | Cannot be refactored. Too monolithic. Extract tab logic into page components, then delete. |
| **Inline styles (237 instances)** | **REPLACE** | Migrate to Tailwind utility classes during page extraction. |
| **Tab navigation pattern** | **REPLACE** | Replace with React Router + sidebar navigation. |
| **Session state management** | **REPLACE** | Move from useState to Zustand store with localStorage persistence. |
| **mock_data_master.ts** | **REMOVE** | Unused, outdated test fixtures. |
| **Root tailwind.config.js** | **REMOVE** | Duplicate of contracts/tailwind.config.ts with empty theme. |

---

## 6. Final Top-Level Navigation Model

**Pattern**: Fixed left sidebar (286px) + fixed top bar (52px) + scrollable content area.

### Sidebar Navigation (9 items, grouped)

```
[GUARDIAN LOGO]
[Tenant: {institution_name}]
────────────────────
OPERATIONS
  Dashboard          /dashboard
  Endpoints          /endpoints          badge: total count
  Findings           /findings           badge: critical+high count
  Alerts             /alerts             badge: alert count

ANALYSIS
  Cycles             /cycles
  Trust Graph        /graph
  Simulator          /simulator

────────────────────
  Settings           /settings           (gear icon, bottom-pinned)
  {operator_email}                       (avatar + logout, bottom-pinned)
```

### Top Bar (persistent, 52px)
Left: Page title + breadcrumb (e.g., "Endpoints > api.example.com:443")
Right: Tenant health dot (green/yellow/red) | Last scan: "2h ago" | Onboarding state (if pending)

### Why This Grouping
- **Operations** = daily analyst workflow (risk assessment, investigation, triage)
- **Analysis** = deeper investigation (cycle history, graph exploration, simulation)
- Settings and operator identity pinned to bottom — always accessible, out of the way

### Navigation Behavior
- Sidebar items highlight active route
- Sidebar is always visible (no collapse on desktop)
- Content area scrolls independently
- Clicking logo or "Dashboard" returns to /dashboard
- Breadcrumbs appear only on detail pages (Endpoint Detail, Cycle Detail, Simulation Detail)

---

## 7. Final Page List

| # | Page | Route | New/Existing |
|---|------|-------|--------------|
| 1 | Login | /login | Exists (extracted from App.tsx admin tab) |
| 2 | Register | /register | Exists (extracted) |
| 3 | Dashboard | /dashboard | Exists (extracted + enhanced) |
| 4 | Endpoints | /endpoints | Exists (extracted + enhanced) |
| 5 | Endpoint Detail | /endpoints/:entityId | **NEW** — most important new page |
| 6 | Findings | /findings | Exists (extracted + enhanced) |
| 7 | Alerts | /alerts | **NEW** — extracted from guardian tab + bundle |
| 8 | Cycles | /cycles | **NEW** — extracted from bundle tab |
| 9 | Cycle Detail | /cycles/:cycleId | Exists (extracted from bundle tab) |
| 10 | Trust Graph | /graph | Exists (GraphViewer migration) |
| 11 | Simulator | /simulator | Exists (extracted) |
| 12 | Simulation Detail | /simulator/:simulationId | Exists (extracted) |
| 13 | Telemetry | /cycles/:cycleId/telemetry | Exists (extracted) |
| 14 | Settings | /settings/* | Exists (extracted from admin tab) |
| 15 | Onboarding | /onboarding | Exists (extracted from scan tab) |
| 16 | 404 | * | **NEW** |

---

## 8. Final Page Hierarchy and Drill-Down Model

```
/login ──────────────────────────────────────┐
/register ───────────────────────────────────┤
                                              │
[AUTHENTICATED SHELL] ◄──────────────────────┘
├── /dashboard
│     ├── click risk card ──────► /findings?severity=critical
│     ├── click drift card ─────► /endpoints?filter=new
│     ├── click endpoint row ───► /endpoints/:entityId
│     └── click alert count ────► /alerts
│
├── /endpoints
│     └── click row ────────────► /endpoints/:entityId
│           ├── tab: Risk ──────► inline (alerts, campaign, narrative)
│           ├── tab: TLS/Crypto ► inline (cert chain, cipher, entropy)
│           ├── tab: Temporal ──► inline (volatility, visibility, history)
│           ├── tab: Findings ──► inline (posture findings for this endpoint)
│           ├── tab: Graph ─────► /graph?focus=:entityId
│           └── tab: History ───► /cycles?endpoint=:entityId
│
├── /findings
│     ├── click finding ────────► /endpoints/:entityId (finding's endpoint)
│     └── click severity card ──► filter table
│
├── /alerts
│     ├── click alert ──────────► /endpoints/:entityId
│     └── expand alert ─────────► inline evidence, narrative, advisory
│
├── /cycles
│     └── click cycle ──────────► /cycles/:cycleId
│           ├── tab: Overview ──► metadata, stats, duration
│           ├── tab: Snapshot ──► endpoint snapshot summary
│           ├── tab: Guardian ──► guardian records for this cycle
│           ├── tab: Temporal ──► temporal state delta
│           ├── tab: Graph ─────► trust graph snapshot
│           └── tab: Telemetry ─► /cycles/:cycleId/telemetry
│
├── /graph
│     └── click node ───────────► side panel with endpoint summary
│           └── "Open Detail" ──► /endpoints/:entityId
│
├── /simulator
│     ├── click simulation ─────► /simulator/:simulationId
│     └── simulation detail ────► compare pane (baseline vs simulated)
│
├── /cycles/:cycleId/telemetry
│     └── expand row ───────────► inline JSON tree
│
└── /settings
      ├── /settings/profile
      ├── /settings/security
      ├── /settings/workspace
      └── /settings/admin
```

**Cross-linking principle**: Every entity_id, cycle_id, severity badge, and finding reference is a clickable link to its canonical detail surface. No dead ends.

---

## 9. Page-by-Page Specifications

### 9.1 Login Page

**Purpose**: Authenticate operator and establish session.
**Primary user**: All users.
**Key question**: "Can I access my workspace?"

**Backend contracts**: POST /v1/auth/login → SessionState
**Immediately visible**: Email/operator_id input, password input, login button, link to register
**Progressive disclosure**: Error messages on failure
**Layout**: Centered card on dark background, Guardian logo above
**Interactions**: Enter submits, tab between fields, error shake on invalid
**Empty state**: N/A
**Loading state**: Button shows spinner, inputs disabled
**Error state**: Inline error below form ("Invalid credentials", "Account not found")

**Implementation notes**:
- Login supports operator_id, email, or tenant_id as identifier (backend resolves)
- On success: store session in Zustand + localStorage, redirect to /dashboard
- On failure: show error, keep form populated

---

### 9.2 Register Page

**Purpose**: Create first operator account + workspace.
**Primary user**: New institution setup.
**Key question**: "Can I create my Guardian workspace?"

**Backend contracts**: POST /v1/auth/register → {operator_id, tenant_id, onboarding_status}
**Immediately visible**: Email, password, institution name (optional), master password (if not first user)
**Progressive disclosure**: Registration success → redirect to /onboarding
**Layout**: Centered card, same as login
**Interactions**: Validation on blur, submit on enter
**Empty state**: N/A
**Loading state**: Button spinner
**Error state**: Inline errors (email taken, invalid password, bad master password)

---

### 9.3 Dashboard

**Purpose**: Risk posture overview — the analyst's home screen.
**Primary user**: Security analyst, CISO.
**Key question**: "What is my current risk posture and what changed?"

**Backend contracts**: GET /v1/tenants/{id}/dashboard → {health_summary, risk_distribution, drift_report, endpoints[]}
**Immediately visible**:
1. Health summary bar: total endpoints, max severity badge, last cycle timestamp, cycle duration
2. Risk distribution: 4 metric cards (critical/high/medium/low) with counts, clickable
3. Drift report: 3 cards (new endpoints, removed endpoints, risk increased flag)
4. Top 10 riskiest endpoints table (sorted by guardian_risk desc)

**Progressive disclosure**:
- Click risk card → navigate to /findings?severity={level}
- Click endpoint row → navigate to /endpoints/{entity_id}
- Click "View All Endpoints" → navigate to /endpoints
- Click drift "new" card → /endpoints?filter=new

**Layout**: Single column, stacked sections. Health bar full-width at top, then 4-column metric grid, then 3-column drift grid, then table.
**Interactions**: Cards are clickable with hover state. Table rows are clickable. No drag/drop.
**Empty state**: "No scan data yet. Run your first scan to see your risk posture." + CTA button to /onboarding
**Loading state**: Skeleton cards (4 metric placeholders) + skeleton table (5 row placeholders)
**Error state**: Error banner at top of content area with retry button

---

### 9.4 Endpoints

**Purpose**: Full endpoint inventory with filtering, sorting, and search.
**Primary user**: Security analyst.
**Key question**: "Which of my endpoints need attention?"

**Backend contracts**: GET /v1/tenants/{id}/dashboard → endpoints[] (up to 2000 EndpointDTOs with 40+ fields)
**Immediately visible**:
- Filter rail (left, 240px): severity checkboxes, TLS version filter, discovery source filter, cluster filter, search box
- Data table (right): entity_id, hostname, port, guardian_risk (color-coded), confidence, alert_count, tls_version, first_seen, last_seen
- Default sort: guardian_risk descending
- Default columns: 8 visible (entity_id, hostname, port, risk, confidence, alerts, tls_version, last_seen)

**Progressive disclosure**:
- Column toggle: show/hide additional columns (IP, ASN, cipher, cert_issuer, volatility, visibility, absence, clusters, discovery_source, cert_expiry, entropy)
- Click row → /endpoints/{entity_id}
- CSV export button in toolbar

**Layout**: Left filter rail (240px) + right table surface. Toolbar above table (search, column toggle, export, result count).
**Interactions**: Sort by clicking column headers. Filter checkboxes apply immediately. Search is debounced (300ms). Pagination (50 rows/page).
**Empty state**: "No endpoints discovered yet. Run a scan to discover your attack surface."
**Loading state**: Skeleton filter rail + skeleton table
**Error state**: Error banner with retry

**Implementation notes**:
- Data comes from dashboard endpoint, cached in Zustand store
- Filtering/sorting/pagination is client-side (max 2000 endpoints is manageable)
- Use TanStack Table for column management, sorting, filtering

---

### 9.5 Endpoint Detail (THE MOST IMPORTANT PAGE)

**Purpose**: Deep investigation view for a single endpoint — identity, risk, crypto posture, temporal behavior, findings, graph context.
**Primary user**: Security analyst (primary), compliance officer.
**Key question**: "What exactly is happening with this endpoint and should I be worried?"

**Backend contracts**:
- Primary: GET /v1/tenants/{id}/dashboard → filter endpoints[] by entity_id (client-side)
- Guardian records: GET /v1/tenants/{id}/cycles/{latest}/bundle → guardian_records filtered by entity_id
- Telemetry: GET /v1/tenants/{id}/cycles/{latest}/telemetry?record_type=posture_findings → filter by entity_id
- Trust graph: from bundle → trust_graph_snapshot

**Immediately visible** (above the fold, no scroll):
- **Identity header**: entity_id (monospace), hostname, port, URL, IP, ASN, discovery_source
- **Risk summary**: guardian_risk (large, color-coded), confidence score, alert_count, campaign_phase (if present)
- **Provenance bar**: first_seen, last_seen, cycle_id, snapshot_hash

**Progressive disclosure** (tabbed content below header):
- **Tab 1: Risk & Alerts** (default): Guardian alerts for this endpoint, severity, narrative, advisory, justification, pattern labels, sync_index. Each alert expandable to show evidence_refs.
- **Tab 2: TLS & Crypto**: tls_version, cipher, cert_issuer, cert_sha256, cert_expiry, entropy_score. Crypto health assessment. Quantum readiness indicator.
- **Tab 3: Temporal**: volatility_score chart/indicator, visibility_score, consecutive_absence, change history across cycles.
- **Tab 4: Findings**: Posture findings (WAF/TLS) specific to this endpoint with compliance control mappings.
- **Tab 5: Graph Context**: Mini trust graph centered on this endpoint (reuse GraphViewer with focus filter). Show cluster memberships (shared_cert, lb, identity clusters).
- **Tab 6: History**: This endpoint's appearance across recent cycles — when it was first discovered, risk trend over time.

**Layout**: Full-width page. Identity header (sticky, 120px). Below: tabbed content area filling remaining space. No sidebar filter rail on this page — the header IS the context.
**Interactions**: Tab switching (no page reload). Alerts are expandable accordions. Evidence refs are linkable. "Export Endpoint Report" button in header. "View in Graph" link → /graph?focus={entity_id}.
**Empty state**: "Endpoint not found in current scan data." with back link to /endpoints
**Loading state**: Skeleton header + skeleton tab content
**Error state**: Error banner with retry

**Implementation notes**:
- entity_id is URL-encoded in route param (contains colons: "hostname:port")
- EndpointDTO from dashboard provides identity + risk + temporal + crypto fields
- Guardian alerts require loading latest cycle bundle and filtering guardian_records by entity_id
- Findings require loading telemetry with record_type=posture_findings and filtering
- This page does 2-3 API calls on mount: dashboard (if not cached) + bundle + telemetry

---

### 9.6 Findings

**Purpose**: Aggregated security posture findings across all endpoints.
**Primary user**: Security analyst, compliance officer.
**Key question**: "What security weaknesses exist across my attack surface?"

**Backend contracts**: GET /v1/tenants/{id}/cycles/{latest}/telemetry?record_type=posture_findings → paginated rows
**Immediately visible**:
- Summary cards: total findings count, count by category (WAF, TLS, crypto), count by severity
- Findings table: finding_type, severity, affected_endpoint(s), compliance_control, description

**Progressive disclosure**:
- Click finding row → expand to show full evidence, compliance mapping
- Click endpoint link → /endpoints/{entity_id}
- Group-by toggle: by finding type (default) or by endpoint

**Layout**: Left filter rail (severity, finding type, compliance framework) + right table/card surface.
**Interactions**: Filter, sort, group-by toggle, export CSV
**Empty state**: "No findings detected. Your endpoints have a clean posture." (positive state)
**Loading state**: Skeleton cards + skeleton table
**Error state**: Error banner

**Implementation notes**:
- Findings are extracted from telemetry posture_findings records
- May need to paginate through all telemetry to build complete findings list — cache aggressively
- Client-side grouping and filtering

---

### 9.7 Alerts

**Purpose**: Triage Guardian analytical alerts (L4 output).
**Primary user**: Security analyst.
**Key question**: "What is the Guardian's engine warning me about right now?"

**Backend contracts**: GET /v1/tenants/{id}/cycles/{latest}/bundle → guardian_records[]
**Immediately visible**:
- Alert count by severity (tabs or filter chips: All / Critical / High / Medium / Low)
- Alert cards: entity_id (linked), severity badge, alert_kind, title, campaign_phase, pattern_labels as chips

**Progressive disclosure**:
- Expand alert → full body, narrative, advisory, justification, evidence_refs, sync_index, metrics
- Click entity_id → /endpoints/{entity_id}
- Click campaign_phase → filter by phase

**Layout**: Full-width card list with severity left-border color coding. Filter tabs at top.
**Interactions**: Expand/collapse alerts. Filter by severity, campaign_phase, pattern_labels. Sort by severity (default) or confidence.
**Empty state**: "No active alerts. Guardian has not flagged any concerning patterns."
**Loading state**: Skeleton alert cards
**Error state**: Error banner

**Implementation notes**:
- Guardian records come from cycle bundle
- Each GuardianQueryResponse contains per-entity alerts
- Flatten to alert-level list: one card per AlertResponse, grouped by entity
- guardian_records may contain up to 50k records — use virtualized list if > 100

---

### 9.8 Cycles

**Purpose**: History of discovery/analysis cycles.
**Primary user**: Operator, analyst.
**Key question**: "When did scans run, and what did each cycle find?"

**Backend contracts**: GET /v1/tenants/{id}/cycles/{latest}/bundle → cycle_metadata[] (contains all cycle records)
**Immediately visible**:
- Timeline list: cycle_number, date/time, duration_ms, endpoint_count, new_endpoints, removed_endpoints, status, snapshot_hash (truncated)

**Progressive disclosure**:
- Click cycle row → /cycles/{cycle_id}
- Compare button: select two cycles for diff view (future enhancement)

**Layout**: Single-column timeline list. Most recent at top.
**Interactions**: Click row to drill down. Pagination if > 50 cycles.
**Empty state**: "No cycles have run yet. Start a scan from the onboarding page."
**Loading state**: Skeleton timeline rows
**Error state**: Error banner

**Implementation notes**:
- Cycle metadata comes from bundle endpoint
- cycle_metadata is a list of all cycle execution records
- Extract cycle_id, timestamps, endpoint counts from metadata entries

---

### 9.9 Cycle Detail

**Purpose**: Deep dive into a single cycle's outputs — snapshot, guardian decisions, temporal state, trust graph.
**Primary user**: Analyst, operator.
**Key question**: "What exactly happened in this scan cycle?"

**Backend contracts**: GET /v1/tenants/{id}/cycles/{cycle_id}/bundle → full CycleArtifactBundle
**Immediately visible**:
- Cycle header: cycle_id, timestamp, duration, endpoint count, snapshot hash
- Tab 1 (Overview): Cycle metadata, execution stats

**Progressive disclosure** (tabs):
- Tab 2: Snapshot — endpoint summary table from this cycle
- Tab 3: Guardian — guardian_records for this cycle
- Tab 4: Temporal — temporal_state for this cycle
- Tab 5: Trust Graph — trust_graph_snapshot (rendered via GraphViewer)
- Tab 6: Layer 3 — layer3_state_snapshot (EWMA state, co-occurrence)
- Tab 7: Telemetry — link to /cycles/{cycle_id}/telemetry

**Layout**: Header (sticky) + tabbed content below.
**Interactions**: Tab switching. Download bundle as JSON. Export button.
**Empty state**: "Cycle not found."
**Loading state**: Skeleton header + skeleton tabs
**Error state**: Error banner

---

### 9.10 Trust Graph

**Purpose**: Visual exploration of endpoint relationships and clustering.
**Primary user**: Analyst.
**Key question**: "How are my endpoints related, and where are the clusters?"

**Backend contracts**: GET /v1/tenants/{id}/cycles/{latest}/bundle → trust_graph_snapshot, endpoints[]
**Immediately visible**:
- Full-canvas SVG graph (GraphViewer component)
- Nodes colored by risk severity
- Edges by relationship type (shared cert, load balancer, identity)

**Progressive disclosure**:
- Click node → side panel with endpoint summary (entity_id, risk, alert_count, clusters)
- "Open Detail" button in side panel → /endpoints/{entity_id}
- Left filter panel: filter by cluster type, risk threshold, show/hide edge types

**Layout**: Full-width canvas with left filter panel (collapsible) and right detail panel (on node selection).
**Interactions**: Pan, zoom, node selection, edge hover. Max initial render: 200 nodes (with "Show All" option).
**Empty state**: "No trust graph data. Run a scan to build the graph."
**Loading state**: Skeleton canvas placeholder
**Error state**: Error banner

**Implementation notes**:
- GraphViewer.tsx is preserved as-is
- Wrap in a page component that handles data loading and filter state
- Add optional `focusEntity` prop for deep-linking from Endpoint Detail

---

### 9.11 Simulator

**Purpose**: List and explore what-if simulations.
**Primary user**: Analyst.
**Key question**: "What would happen to my risk posture under different scenarios?"

**Backend contracts**:
- GET /v1/tenants/{id}/simulations → SimulationPage (paginated list)
- GET /v1/tenants/{id}/simulations/{sim_id} → full simulation payload

**Immediately visible**:
- Simulation list: simulation_id, scenario_id, baseline_cycle_id, status, created_at

**Progressive disclosure**:
- Click row → /simulator/{simulation_id}
- Simulation detail: tabbed view mirroring Cycle Detail structure
- Compare mode: side-by-side baseline vs simulated snapshot

**Layout**: List view (default) or detail view (on selection).
**Interactions**: Click to drill down. Pagination (100 per page).
**Empty state**: "No simulations have been run yet."
**Loading state**: Skeleton list
**Error state**: Error banner

**Implementation notes**:
- No API to trigger simulations from UI currently — list is read-only
- Simulation trigger endpoint (POST) is a Phase 5 backend enhancement if needed

---

### 9.12 Telemetry Browser

**Purpose**: Raw telemetry record browser for a specific cycle.
**Primary user**: Analyst (advanced), developer.
**Key question**: "What raw discovery/posture data was collected in this cycle?"

**Backend contracts**: GET /v1/tenants/{id}/cycles/{cycle_id}/telemetry?record_type={type}&page={p}&page_size={ps}
**Immediately visible**:
- Record type tabs: All | Fingerprints | Posture Signals | Posture Findings
- Record count per type
- Paginated table: record summary columns

**Progressive disclosure**:
- Expand row → full JSON tree view of record
- Pagination controls (500 per page default)

**Layout**: Tabs at top, then full-width table.
**Interactions**: Tab filtering, pagination, row expand/collapse.
**Empty state**: "No telemetry records for this cycle."
**Loading state**: Skeleton table
**Error state**: Error banner

---

### 9.13 Settings

**Purpose**: Operator profile, security, workspace configuration, admin operations.
**Primary user**: Operator, admin.
**Key question**: "How do I manage my account and workspace?"

**Backend contracts**:
- POST /v1/admin/profile/update
- POST /v1/admin/credentials/change-password
- POST /v1/admin/operators/register
- POST /v1/admin/tenants/register
- GET /v1/auth/me

**Sub-pages**:
- /settings/profile — email, institution name (editable)
- /settings/security — change password
- /settings/workspace — tenant info, onboarding status, seed endpoints (read-only)
- /settings/admin — register new operators, register new tenants

**Layout**: Left tab rail (vertical) + right content form.
**Interactions**: Form submission with validation. Success/error toasts.

---

### 9.14 Onboarding

**Purpose**: First-time workspace setup — configure seed endpoints and trigger first scan.
**Primary user**: New operator.
**Key question**: "How do I get my first scan running?"

**Backend contracts**: POST /v1/tenants/{id}/onboard-and-scan
**Immediately visible**:
- Institution name (pre-filled if set during register)
- Main URL input
- Seed endpoints textarea (one per line)
- "Start Scan" button

**Layout**: Centered card, wizard-style (single step for now).
**Interactions**: Validation on submit. On success → redirect to /dashboard with "Scan started" toast.
**Empty state**: N/A
**Loading state**: Button spinner, inputs disabled during scan trigger
**Error state**: Inline form errors

---

## 10. Workflow Designs

### 10.1 Login Flow
1. User visits / → redirected to /login (if no session)
2. Enter email/operator_id + password
3. POST /v1/auth/login
4. On success → session stored in Zustand + localStorage → redirect to /dashboard
5. On failure → inline error, form stays populated

### 10.2 Registration Flow
1. User visits /register
2. Enter email, password, institution name (optional)
3. If first user: no master password needed
4. If subsequent user: master password required
5. POST /v1/auth/register
6. On success → auto-login → redirect to /onboarding

### 10.3 Onboarding Flow
1. Redirected from registration or via sidebar "Onboarding pending" indicator
2. Enter institution name, main URL, seed endpoints
3. POST /v1/tenants/{id}/onboard-and-scan
4. On success → redirect to /dashboard with "First scan started" notification
5. Dashboard shows data after scan completes (poll or manual refresh)

### 10.4 Dashboard Use
1. Analyst logs in → lands on /dashboard
2. Scans risk distribution cards — identifies critical/high counts
3. Clicks critical card → /findings?severity=critical
4. OR scans top-10 endpoint table → clicks riskiest endpoint → /endpoints/{entity_id}
5. OR checks drift report — sees 3 new endpoints → clicks → /endpoints?filter=new

### 10.5 Endpoint Investigation
1. From dashboard or /endpoints, analyst clicks an endpoint
2. /endpoints/{entity_id} loads — identity header shows risk immediately
3. Risk & Alerts tab (default) shows Guardian's assessment
4. Analyst expands alert → reads narrative, advisory, evidence
5. Switches to TLS tab → checks cert expiry, cipher strength
6. Switches to Findings tab → sees specific WAF/TLS posture findings
7. Clicks "View in Graph" → /graph?focus={entity_id} to see cluster relationships
8. Returns to endpoint detail → clicks "Export Endpoint Report"

### 10.6 Findings Review
1. Analyst navigates to /findings
2. Filters by severity=critical
3. Reviews each finding type — identifies systemic issues (e.g., weak TLS across 12 endpoints)
4. Clicks endpoint link on a finding → drills to /endpoints/{entity_id}
5. Exports findings as CSV for compliance report

### 10.7 Alert Triage
1. Analyst navigates to /alerts (or clicks alert badge from dashboard)
2. Filters to Critical severity
3. Expands top alert → reads narrative, campaign phase, pattern labels
4. Clicks entity_id → /endpoints/{entity_id} for full context
5. Returns to alerts → works through remaining high-severity alerts
6. Marks as reviewed via Notes (Phase 4)

### 10.8 Simulator Use
1. Analyst navigates to /simulator
2. Selects a completed simulation from list
3. Reviews simulation detail — compares baseline vs simulated risk
4. Identifies endpoints with increased risk under scenario
5. Exports simulation comparison for risk committee

### 10.9 Export/Compliance Use
1. Compliance officer navigates to /endpoints or /findings
2. Applies filters for compliance scope
3. Clicks "Export CSV" in toolbar
4. Downloads endpoint inventory or findings report
5. From Cycle Detail → downloads full cycle bundle as JSON
6. From Endpoint Detail → exports single endpoint report

### 10.10 Admin/Account Management
1. Admin navigates to /settings
2. Profile: update email, institution name
3. Security: change password
4. Admin: register new operator (with master password), register new tenant
5. Workspace: view tenant configuration, onboarding status

---

## 11. Endpoint-Detail-First Investigation Model

Endpoint Detail is the **convergence point** of all investigation surfaces. Every other page ultimately drives toward it:

```
Dashboard ────────► Endpoint Detail ◄──────── Findings
     │                    ▲                        │
     ▼                    │                        ▼
  Alerts ─────────────────┘              Endpoint Detail
     │                                         ▲
     ▼                                         │
  Graph ──────────────────────────────────────┘
```

**Design implications:**
1. Endpoint Detail must load fast — critical data (identity, risk) from cached dashboard, supplementary data (alerts, findings) loaded in tabs on demand.
2. Every entity_id displayed anywhere in the app must be a clickable link to /endpoints/{entity_id}.
3. Endpoint Detail must show provenance: when was this endpoint first seen, which cycle, what source discovered it.
4. Endpoint Detail must support export: "Export Endpoint Report" generates a complete evidence bundle for this specific endpoint.
5. Endpoint Detail's tab structure must mirror the analyst's mental model: risk first, then posture, then temporal behavior, then findings, then context.

---

## 12. Notes and Tasks

### Justification
Analysts investigating endpoints need to record observations, flag items for follow-up, and track remediation. Without Notes/Tasks, analysts resort to external tools (spreadsheets, Jira tickets), breaking the investigation flow.

Notes and Tasks are justified because:
1. Investigation is iterative — analysts return to endpoints across sessions
2. Remediation tracking needs to stay close to the evidence
3. Compliance requires documented review trails

### Notes Design
- **Attached to**: endpoint, finding, alert, cycle, simulation
- **Fields**: text content, created_at, created_by (operator_id), attached_object_type, attached_object_id
- **Display**: Notes section at bottom of Endpoint Detail, Finding expansion, Alert expansion
- **Interaction**: "Add Note" text input, saved immediately
- **Storage (Phase 4)**: localStorage keyed by tenant_id + object_type + object_id
- **Storage (future)**: Backend persistence endpoint (not currently available)

### Tasks Design
- **Attached to**: endpoint, finding
- **Fields**: title, description, status (open/in_progress/done), priority (critical/high/medium/low), due_date, assigned_to, linked_object_type, linked_object_id, created_at, created_by
- **Display**: Tasks page (sidebar item under Settings or dedicated), inline task list on Endpoint Detail
- **Interaction**: Create task from any endpoint/finding context menu. Mark done with checkbox.
- **Storage**: Same as Notes — localStorage initially, backend persistence later

### Why Not Earlier
Notes/Tasks require persistence. The backend has no Notes/Tasks API. Implementing localStorage persistence is reasonable for Phase 4 but does not justify delaying the core investigation workflow (Phases 1-3).

---

## 13. Visual System Plan

### 13.1 Density Rules
- Table rows: 36-40px height (compact, not cramped)
- Card padding: 16px internal, 12px gap between cards
- Section spacing: 24px between major sections
- Page padding: 24px from content edges
- No decorative whitespace — every pixel carries information or provides necessary separation
- Sidebar: 286px fixed width
- Topbar: 52px fixed height

### 13.2 Typography Hierarchy
| Level | Font | Size | Weight | Use |
|-------|------|------|--------|-----|
| Page title | IBM Plex Sans | 24px | 600 | One per page, in topbar |
| Section header | IBM Plex Sans | 18px | 600 | Section divisions within page |
| Subsection | IBM Plex Sans | 15px | 500 | Card titles, tab labels |
| Body text | IBM Plex Sans | 13px | 400 | Descriptions, table cells, form labels |
| Secondary text | IBM Plex Sans | 12px | 400 | Muted descriptions, timestamps |
| Caption/micro | IBM Plex Sans | 11px | 400 | Badges, status labels, footnotes |
| Monospace data | IBM Plex Mono | 13px | 400 | entity_id, hashes, IPs, scores, JSON |
| Brand only | Syne | 18px | 700 | Logo text "GUARDIAN" — nowhere else |

### 13.3 Spacing Rhythm
Base unit: 4px. All spacing is a multiple of 4.
- xs: 4px (inline spacing, tight gaps)
- sm: 8px (between related items)
- md: 16px (card padding, section padding, standard gap)
- lg: 24px (between sections, page padding)
- xl: 32px (major section separation)

### 13.4 Color System
```
Background:    #0a0a0a  (app background)
Panel:         #141414  (cards, sidebar, panels)
Surface:       #1a1a1a  (elevated surfaces, hover states)
Border:        #232323  (all borders — subtle, consistent)
Text primary:  #e0e0e0  (main content)
Text muted:    #999999  (secondary labels, timestamps)
Text ghost:    #666666  (disabled, placeholder)
White:         #ffffff  (high emphasis only — page titles, risk scores)

Severity:
  Critical:    #ee5555  (red)
  High:        #ee9933  (orange)
  Medium:      #eeaa33  (amber)
  Low:         #66aa66  (green)
  Unknown:     #888888  (gray)

Accent:        #2b95d6  (links, active states, focus rings — used sparingly)
Success:       #2ea043  (confirmations)
Warning:       #d4a017  (caution states)
Danger:        #da3633  (destructive actions)
```

### 13.5 Navigation Behavior
- Sidebar: always visible, never collapses on desktop
- Active nav item: left border accent (3px), slightly lighter background
- Hover: surface color background
- Badges: right-aligned, monospace count, pill-shaped
- Topbar: breadcrumb appears on detail pages only
- No page transition animations — instant route switches

### 13.6 Table Behavior
- Default columns: 6-8 visible, rest behind column toggle
- Column headers: uppercase, 11px, ghost color, clickable for sort
- Sort indicator: chevron up/down next to active sort column
- Row hover: surface color background
- Row click: navigate to detail (cursor: pointer)
- Pagination: bottom-right, "Showing 1-50 of 347" + prev/next
- No horizontal scrolling — use column toggle to manage width
- Monospace for: entity_id, IP, hash, score columns
- Severity column: color-coded badge (text + background)

### 13.7 Side Panel / Detail Panel Usage
- Used in: Trust Graph (node selection), future table row preview
- Width: 360px, slides in from right
- Contains: entity summary, key metrics, action buttons ("Open Detail")
- Close: X button or click outside
- NOT used for: Endpoint Detail (full page), Cycle Detail (full page)

### 13.8 Graph / Timeline Usage
- Trust Graph: full-canvas SVG via GraphViewer (preserved)
- Timeline: cycle history as vertical list (not a chart)
- No line charts, bar charts, or pie charts — metric cards with numbers are sufficient
- If temporal trending is needed later: sparkline (tiny inline line chart) next to risk score — not in v2 scope

### 13.9 Animation Rules
- **Justified**: Skeleton loader shimmer (data loading), toast notification slide-in/out, side panel slide-in/out, expandable row height transition (150ms ease)
- **Not justified**: Page transitions, card entrance animations, number counting up, hover scale transforms, parallax, any animation > 200ms
- **Rule**: If removing the animation would not reduce usability, remove it.

---

## 14. Component Architecture Plan

### 14.1 Directory Structure
```
src/
├── main.tsx                          # ReactDOM.createRoot + <App/>
├── App.tsx                           # ~30 lines: <AuthProvider> + <RouterProvider>
│
├── providers/
│   └── AuthProvider.tsx              # Session context + localStorage sync
│
├── stores/
│   └── useSessionStore.ts            # Zustand: session, tenant_id, login/logout
│   └── useDashboardStore.ts          # Zustand: cached dashboard data
│
├── layouts/
│   └── AppShell.tsx                  # Sidebar + Topbar + <Outlet/>
│   └── AuthLayout.tsx                # Centered card layout for login/register
│
├── pages/
│   ├── LoginPage.tsx
│   ├── RegisterPage.tsx
│   ├── OnboardingPage.tsx
│   ├── DashboardPage.tsx
│   ├── EndpointsPage.tsx
│   ├── EndpointDetailPage.tsx        # Most important page
│   ├── FindingsPage.tsx
│   ├── AlertsPage.tsx
│   ├── CyclesPage.tsx
│   ├── CycleDetailPage.tsx
│   ├── GraphPage.tsx
│   ├── SimulatorPage.tsx
│   ├── SimulationDetailPage.tsx
│   ├── TelemetryPage.tsx
│   ├── SettingsPage.tsx              # Sub-routes: profile/security/workspace/admin
│   └── NotFoundPage.tsx
│
├── components/
│   ├── graph/
│   │   └── GraphViewer.tsx           # PRESERVED from current codebase
│   ├── data/
│   │   ├── DataTable.tsx             # TanStack Table wrapper (sort, filter, paginate, column toggle)
│   │   └── JsonTree.tsx              # Expandable JSON viewer for telemetry/evidence
│   ├── layout/
│   │   ├── Sidebar.tsx               # Navigation items + tenant + operator
│   │   ├── Topbar.tsx                # Page title + breadcrumb + health + freshness
│   │   ├── FilterRail.tsx            # Left-side filter panel (checkboxes, search)
│   │   └── SidePanel.tsx             # Right slide-out panel (graph node detail)
│   ├── feedback/
│   │   ├── EmptyState.tsx            # Icon + message + CTA button
│   │   ├── SkeletonLoader.tsx        # Shimmer placeholders (card, table, text variants)
│   │   ├── ErrorBanner.tsx           # Inline error with retry button
│   │   └── Toast.tsx                 # Success/error notifications (auto-dismiss)
│   ├── display/
│   │   ├── SeverityBadge.tsx         # Color-coded severity indicator
│   │   ├── MetricCard.tsx            # Stat card (label + value + optional delta)
│   │   ├── ProvenanceBar.tsx         # cycle_id + hash + timestamp strip
│   │   └── ExportButton.tsx          # CSV/JSON export trigger
│   └── forms/
│       ├── FormInput.tsx             # Labeled text input with validation
│       └── FormTextarea.tsx          # Labeled textarea
│
├── hooks/
│   ├── useAuth.ts                    # Login/logout/session from Zustand
│   ├── useDashboard.ts              # Fetch + cache dashboard data
│   ├── useCycleBundle.ts            # Fetch cycle bundle
│   ├── useTelemetry.ts             # Paginated telemetry fetch
│   ├── useSimulations.ts           # Simulation list + detail
│   ├── useAlerts.ts                # Extract alerts from guardian_records
│   ├── useFindings.ts              # Extract findings from telemetry
│   └── useEndpointDetail.ts        # Composite hook: dashboard + bundle + telemetry for one endpoint
│
├── lib/
│   ├── api.ts                       # Re-export Layer5ApiConnector (PRESERVED)
│   ├── dataSource.ts               # Re-export Layer5DataSource (PRESERVED)
│   ├── extractors.ts               # Client-side data extraction functions
│   │                                 # extractAlerts(guardianRecords, entityId?)
│   │                                 # extractFindings(telemetryRows, entityId?)
│   │                                 # extractCycleList(cycleMetadata)
│   ├── formatters.ts               # formatTimestamp, formatSeverity, formatScore, formatHash
│   └── routes.ts                   # Route path constants
│
├── data_source/                     # PRESERVED — existing data layer
│   ├── data_connector_to_ui.ts      # Layer5ApiConnector (KEEP)
│   └── master_data_connector_to_layer4.ts  # Layer5DataSource (KEEP)
│
└── styles/
    ├── tokens.css                   # Consolidated design tokens (from design-tokens.css)
    └── app-shell.css                # Preserved layout classes (cleaned up)
```

### 14.2 Route Structure
```typescript
// src/App.tsx
<Routes>
  <Route element={<AuthLayout />}>
    <Route path="/login" element={<LoginPage />} />
    <Route path="/register" element={<RegisterPage />} />
  </Route>

  <Route element={<RequireAuth><AppShell /></RequireAuth>}>
    <Route index element={<Navigate to="/dashboard" />} />
    <Route path="/dashboard" element={<DashboardPage />} />
    <Route path="/onboarding" element={<OnboardingPage />} />
    <Route path="/endpoints" element={<EndpointsPage />} />
    <Route path="/endpoints/:entityId" element={<EndpointDetailPage />} />
    <Route path="/findings" element={<FindingsPage />} />
    <Route path="/alerts" element={<AlertsPage />} />
    <Route path="/cycles" element={<CyclesPage />} />
    <Route path="/cycles/:cycleId" element={<CycleDetailPage />} />
    <Route path="/cycles/:cycleId/telemetry" element={<TelemetryPage />} />
    <Route path="/graph" element={<GraphPage />} />
    <Route path="/simulator" element={<SimulatorPage />} />
    <Route path="/simulator/:simulationId" element={<SimulationDetailPage />} />
    <Route path="/settings/*" element={<SettingsPage />} />
    <Route path="*" element={<NotFoundPage />} />
  </Route>
</Routes>
```

### 14.3 State Boundaries
| State | Location | Persistence | Scope |
|-------|----------|-------------|-------|
| Session (token, operator, tenants) | Zustand store | localStorage | Global |
| Active tenant_id | Zustand store | localStorage | Global |
| Dashboard data | Zustand store | Memory (cache) | Per-session |
| Cycle bundle | React Query or hook state | Memory | Per-page |
| Telemetry | Hook state | Memory | Per-page |
| Simulations | Hook state | Memory | Per-page |
| Filter/sort state | URL search params | URL | Per-page |
| Notes/Tasks | localStorage | localStorage | Per-tenant |
| Form inputs | Local useState | Memory | Per-component |

### 14.4 Data Connector Preservation Strategy
The existing data connectors (Layer5ApiConnector + Layer5DataSource) are preserved in `data_source/`. New hooks in `hooks/` wrap them:

```
Page Component
  └── useHook (hooks/useDashboard.ts)
        └── dataSource.getDashboard() (data_source/master_data_connector_to_layer4.ts)
              └── connector.getDashboard() (data_source/data_connector_to_ui.ts)
                    └── fetch("/v1/tenants/{id}/dashboard")
```

The new `extractors.ts` layer handles client-side data transformation:
- `extractAlerts(guardianRecords)` → flattened alert list from GuardianQueryResponse[]
- `extractFindings(telemetryRows)` → posture findings from telemetry records
- `extractCycleList(cycleMetadata)` → cycle summary list from metadata entries
- `extractEndpoint(endpoints, entityId)` → single EndpointDTO from dashboard list

This avoids rewriting the API client while adding the extraction logic the old plan identified as "missing APIs."

---

## 15. Backend Fit Analysis

### 15.1 Existing APIs — Sufficient for Immediate Build

| Page | API Endpoint | Sufficient? | Notes |
|------|-------------|-------------|-------|
| Login | POST /v1/auth/login | Yes | Full session creation |
| Register | POST /v1/auth/register | Yes | Bootstrap + workspace creation |
| Dashboard | GET /v1/tenants/{id}/dashboard | Yes | Health, risk, drift, endpoints (up to 2000) |
| Endpoints | GET /v1/tenants/{id}/dashboard | Yes | Same endpoint — endpoints[] array |
| Endpoint Detail | GET /v1/tenants/{id}/dashboard + GET /.../bundle + GET /.../telemetry | Yes | Composite: filter from dashboard + bundle + telemetry |
| Findings | GET /v1/tenants/{id}/cycles/{cid}/telemetry?record_type=posture_findings | Yes | Client-side extraction from telemetry |
| Alerts | GET /v1/tenants/{id}/cycles/{cid}/bundle | Yes | Extract from guardian_records in bundle |
| Cycles | GET /v1/tenants/{id}/cycles/{cid}/bundle | Yes | Extract cycle_metadata from bundle |
| Cycle Detail | GET /v1/tenants/{id}/cycles/{cid}/bundle | Yes | Full bundle with all artifacts |
| Telemetry | GET /v1/tenants/{id}/cycles/{cid}/telemetry | Yes | Paginated, filtered by record_type |
| Trust Graph | GET /v1/tenants/{id}/cycles/{cid}/bundle | Yes | trust_graph_snapshot in bundle |
| Simulator | GET /v1/tenants/{id}/simulations | Yes | List + detail endpoints |
| Settings | POST /v1/admin/* | Yes | Profile, password, operators, tenants |
| Onboarding | POST /v1/tenants/{id}/onboard-and-scan | Yes | Triggers discovery cycle |

**Result: ALL pages can be built with existing APIs. Zero backend changes required to ship the complete UI.**

### 15.2 v1 Plan "Missing APIs" — Reassessment

| v1 "Missing API" | v2 Assessment | Action |
|-------------------|---------------|--------|
| GET /endpoints/{entity_id} | **Not needed** — filter from dashboard endpoints[] | Client-side extraction |
| GET /alerts | **Not needed** — extract from guardian_records in bundle | Client-side extraction |
| GET /findings | **Not needed** — extract from telemetry posture_findings | Client-side extraction |
| GET /cycles | **Not needed** — extract from cycle_metadata in bundle | Client-side extraction |

### 15.3 Truly Missing APIs (Optional Optimizations Only)

| API | Purpose | Priority | When |
|-----|---------|----------|------|
| GET /v1/tenants/{id}/cycles | Dedicated cycle list without full bundle load | Low | Only if cycle_metadata in bundle proves too heavy |
| POST /v1/tenants/{id}/simulations | Trigger simulation from UI | Medium | Phase 5 — only if analysts need self-service simulation |
| POST /v1/tenants/{id}/notes | Server-side Notes persistence | Low | After localStorage proves the feature is used |
| POST /v1/tenants/{id}/tasks | Server-side Tasks persistence | Low | After localStorage proves the feature is used |

### 15.4 Pages Buildable Immediately (No Backend Work)

**All 16 pages.** The entire UI rebuild is frontend-only work.

---

## 16. Migration Strategy

### 16.1 Approach: Shell-First Strangler Fig

The monolith (App.tsx) cannot be refactored incrementally — it has 45 interleaved state variables and no component boundaries. Instead:

1. **Build new shell** alongside old App.tsx (temporarily both exist)
2. **Extract tabs one-by-one** into new page components
3. **Connect to preserved data connectors** (no API client rewrite)
4. **Delete App.tsx** when all tabs have been migrated

### 16.2 Migration Steps (in order)

```
Step 1: Create new app shell
  - New App.tsx (30 lines: Router + AuthProvider)
  - AppShell.tsx (Sidebar + Topbar + Outlet)
  - AuthLayout.tsx (centered card)
  - useSessionStore.ts (Zustand + localStorage)
  - Route definitions
  → Old App.tsx temporarily renamed to LegacyApp.tsx (not deleted yet)

Step 2: Extract auth pages
  - LoginPage.tsx (from admin tab auth section)
  - RegisterPage.tsx (from admin tab register section)
  → Delete auth-related state from LegacyApp

Step 3: Extract Dashboard
  - DashboardPage.tsx (from dashboard tab)
  - useDashboard.ts hook
  - MetricCard, SeverityBadge components
  → Delete dashboard-related state from LegacyApp

Step 4: Extract Endpoints + Endpoint Detail
  - EndpointsPage.tsx (from dashboard tab endpoint table)
  - EndpointDetailPage.tsx (NEW — built from EndpointDTO + bundle data)
  - DataTable.tsx, FilterRail.tsx components
  → Delete endpoint-related renders from LegacyApp

Step 5: Extract Alerts + Findings
  - AlertsPage.tsx (from guardian tab + guardian_records extraction)
  - FindingsPage.tsx (from findings tab + telemetry extraction)
  - extractors.ts functions
  → Delete guardian and findings tabs from LegacyApp

Step 6: Extract Cycles + Telemetry
  - CyclesPage.tsx (from bundle tab cycle metadata)
  - CycleDetailPage.tsx (from bundle tab)
  - TelemetryPage.tsx (from telemetry tab)
  → Delete bundle and telemetry tabs from LegacyApp

Step 7: Extract Graph + Simulator
  - GraphPage.tsx (wrap existing GraphViewer)
  - SimulatorPage.tsx (from simulations tab)
  - SimulationDetailPage.tsx (from simulations tab)
  → Delete graph and simulations tabs from LegacyApp

Step 8: Extract Settings + Onboarding
  - SettingsPage.tsx (from admin tab non-auth sections)
  - OnboardingPage.tsx (from scan tab)
  → Delete admin and scan tabs from LegacyApp

Step 9: Delete LegacyApp.tsx
  - All tabs extracted. LegacyApp should be empty.
  - Delete file. Delete mock_data_master.ts. Delete root tailwind.config.js.
  - Clean up unused CSS from app-shell.css.
```

### 16.3 What Is Preserved
- `data_source/data_connector_to_ui.ts` — untouched
- `data_source/master_data_connector_to_layer4.ts` — untouched
- `src/components/GraphViewer.tsx` — moved to `src/components/graph/GraphViewer.tsx`
- `contracts/design-tokens.css` — refactored into `src/styles/tokens.css`
- `src/app-shell.css` — preserved and cleaned, moved to `src/styles/app-shell.css`
- `vite.config.ts` — untouched
- `package.json` — add zustand, @tanstack/react-table; remove unused deps

### 16.4 What Is Retired
- `src/App.tsx` (2,224-line monolith) — fully replaced
- `data_source/mock_data_master.ts` — unused
- Root `tailwind.config.js` — duplicate
- 237 inline style objects — replaced with Tailwind classes

---

## 17. Final Phased Implementation Roadmap

### Phase 1: Foundation (Shell + Auth + Dashboard)
**Scope**: New app shell, routing, session persistence, auth pages, dashboard page, design system consolidation.

**Deliverables**:
1. New App.tsx with React Router
2. AppShell.tsx (Sidebar + Topbar)
3. AuthLayout.tsx (login/register)
4. useSessionStore.ts (Zustand + localStorage)
5. LoginPage.tsx
6. RegisterPage.tsx
7. DashboardPage.tsx
8. Consolidated design tokens (Tailwind theme + CSS vars)
9. Shared components: MetricCard, SeverityBadge, EmptyState, SkeletonLoader, ErrorBanner
10. OnboardingPage.tsx

**Dependencies**: None (frontend-only)
**API usage**: /auth/login, /auth/register, /auth/me, /tenants/{id}/dashboard, /tenants/{id}/onboard-and-scan

---

### Phase 2: Core Investigation (Endpoints + Endpoint Detail + Findings + Alerts)
**Scope**: The pages where analysts spend 80% of their time.

**Deliverables**:
1. EndpointsPage.tsx with DataTable, FilterRail
2. EndpointDetailPage.tsx (tabbed: Risk, TLS, Temporal, Findings, Graph, History)
3. AlertsPage.tsx with expandable alert cards
4. FindingsPage.tsx with filtering and grouping
5. DataTable.tsx (TanStack Table wrapper)
6. FilterRail.tsx
7. JsonTree.tsx (for evidence expansion)
8. extractors.ts (extractAlerts, extractFindings, extractEndpoint)
9. ProvenanceBar.tsx
10. ExportButton.tsx (CSV export)

**Dependencies**: Phase 1 complete
**API usage**: /dashboard (endpoints), /cycles/{cid}/bundle (alerts, graph), /cycles/{cid}/telemetry (findings)

---

### Phase 3: Deep Dive (Cycles + Telemetry + Trust Graph)
**Scope**: Cycle history, raw telemetry, and graph visualization.

**Deliverables**:
1. CyclesPage.tsx (cycle timeline list)
2. CycleDetailPage.tsx (tabbed: Overview, Snapshot, Guardian, Temporal, Graph, L3, Telemetry)
3. TelemetryPage.tsx (paginated record browser with JSON tree expansion)
4. GraphPage.tsx (wrap GraphViewer with filter panel + side detail panel)
5. SidePanel.tsx (for graph node selection)
6. extractCycleList() in extractors.ts

**Dependencies**: Phase 2 complete
**API usage**: /cycles/{cid}/bundle, /cycles/{cid}/telemetry

---

### Phase 4: Advanced (Simulator + Settings + Notes/Tasks + Polish)
**Scope**: Simulation, admin, notes/tasks, and UX polish.

**Deliverables**:
1. SimulatorPage.tsx (list view)
2. SimulationDetailPage.tsx (detail + compare mode)
3. SettingsPage.tsx (profile, security, workspace, admin sub-pages)
4. Notes system (localStorage-backed, attached to endpoints/findings/alerts)
5. Tasks system (localStorage-backed, simple list with status)
6. NotFoundPage.tsx
7. Toast notification system
8. Empty states on all pages
9. Skeleton loaders on all data sections
10. Delete LegacyApp.tsx (monolith should be fully replaced by now)
11. Final CSS cleanup — remove unused rules from app-shell.css

**Dependencies**: Phase 3 complete
**API usage**: /simulations, /simulations/{id}, /admin/*

---

## 18. Phase-by-Phase Acceptance Criteria

### Phase 1 — PASS if:
- [ ] Login page: can log in with valid credentials, session persists across page refresh
- [ ] Register page: can create first operator account, redirects to onboarding
- [ ] Session: stored in localStorage, auto-restored on reload, logout clears storage
- [ ] Sidebar: all 9 nav items visible, active route highlighted, routes navigate correctly
- [ ] Topbar: shows page title, tenant name, health indicator, last scan timestamp
- [ ] Dashboard: health summary cards render with real data, risk distribution cards are clickable (navigate to /findings), top-10 endpoint table renders and rows are clickable (navigate to /endpoints/{id}), drift cards render
- [ ] Onboarding: can submit seed endpoints, triggers scan, redirects to dashboard
- [ ] Empty state: dashboard shows empty state with CTA if no scan data
- [ ] Loading state: skeleton loaders show while dashboard loads
- [ ] Error state: error banner shows on API failure with retry button
- [ ] Design system: Tailwind classes used (no inline styles), design tokens applied, typography hierarchy visible

### Phase 2 — PASS if:
- [ ] Endpoints page: full table renders with 8 default columns, sortable, filterable, searchable, paginated
- [ ] Endpoints page: column toggle works for additional columns
- [ ] Endpoints page: filter rail works (severity, TLS version, discovery source)
- [ ] Endpoints page: CSV export generates valid file
- [ ] Endpoint Detail: identity header shows entity_id, hostname, port, IP, risk, confidence
- [ ] Endpoint Detail: Risk tab shows Guardian alerts for this endpoint with expandable evidence
- [ ] Endpoint Detail: TLS tab shows cert info, cipher, entropy
- [ ] Endpoint Detail: Findings tab shows posture findings for this endpoint
- [ ] Endpoint Detail: all entity_id references across app are clickable links
- [ ] Endpoint Detail: provenance bar shows cycle_id, first_seen, last_seen
- [ ] Alerts page: renders alert cards from guardian_records, filterable by severity
- [ ] Alerts page: alerts expandable to show narrative, advisory, evidence
- [ ] Findings page: renders findings from telemetry, filterable by type and severity
- [ ] Cross-linking: dashboard → endpoints → endpoint detail → graph all work

### Phase 3 — PASS if:
- [ ] Cycles page: lists all cycles with metadata (number, date, duration, endpoint count)
- [ ] Cycle Detail: tabbed view renders all 7 tabs with real data
- [ ] Cycle Detail: download bundle as JSON works
- [ ] Telemetry: record type tabs filter correctly, pagination works, JSON tree expansion works
- [ ] Graph page: renders GraphViewer with real trust graph data
- [ ] Graph page: node click opens side panel with endpoint summary
- [ ] Graph page: "Open Detail" button navigates to /endpoints/{entityId}
- [ ] Graph page: left filter panel controls node/edge visibility

### Phase 4 — PASS if:
- [ ] Simulator: list page renders with pagination
- [ ] Simulation Detail: renders full simulation payload, compare mode works
- [ ] Settings: profile update, password change, operator registration, tenant registration all work
- [ ] Notes: can add note to endpoint/finding/alert, notes persist in localStorage across refresh
- [ ] Tasks: can create task, mark done, task persists in localStorage
- [ ] LegacyApp.tsx deleted — no old code remains
- [ ] 404 page renders for unknown routes
- [ ] All pages have empty states, skeleton loaders, error banners
- [ ] No inline styles remain in codebase
- [ ] Export button available on all data tables and detail pages

---

## 19. Risks and Anti-Patterns to Avoid

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Dashboard API returns too many endpoints (>2000) for client-side filtering | Low (capped at 2000) | Medium | Already capped by backend. If cap increases, implement server-side pagination. |
| Cycle bundle too large (50k guardian_records) | Medium | High | Virtualize alert lists. Only load guardian_records on Alerts/Endpoint Detail tabs. Lazy-load bundle data. |
| Session token expires during long investigation session | Medium | Medium | Check expiry in Zustand store, show "Session expired" modal with re-login. |
| Notes/Tasks in localStorage lost on browser clear | Medium | Low | Clearly communicate localStorage limitation. Plan backend persistence API. |
| GraphViewer performance with large graphs (>600 nodes) | Low (already capped) | Low | Existing 600-node cap is sufficient. Add "Show more" progressive loading. |
| Design system drift — Tailwind classes becoming inconsistent | Medium | Medium | Lint with eslint-plugin-tailwindcss (already installed). Standardize in component library. |
| Scope creep — adding features beyond plan | High | High | Gate each phase. Do not start Phase N+1 until Phase N acceptance criteria pass. |

### Anti-Patterns to Avoid

1. **Do not add charts**: Risk posture is better communicated by severity-colored numbers than by pie/bar charts. If you feel the urge to add a chart, use a metric card instead.
2. **Do not add WebSockets/real-time**: Guardian runs periodic scans. Polling/manual refresh is appropriate. Real-time adds complexity for no benefit.
3. **Do not use Material UI or any component library**: Tailwind + custom components match the design doctrine. Component libraries impose their own visual language.
4. **Do not add GraphQL**: The REST API is sufficient and well-structured. GraphQL adds a translation layer for no gain.
5. **Do not use Next.js/SSR**: This is a client-side SPA behind authentication. SSR adds complexity, build tooling, and deployment concerns for zero user benefit.
6. **Do not build a "design system package"**: Shared components in `src/components/` are sufficient. Do not over-abstract into a separate library.
7. **Do not pre-optimize**: Build the feature first, optimize if performance is measurably poor. React 18 concurrent features and TanStack Table handle most performance needs.
8. **Do not skip empty states**: Every page must handle zero-data gracefully. An empty table with no message looks broken.
9. **Do not use modals for primary content**: Modals are for confirmations and small forms. Endpoint detail, cycle detail, simulation detail are full pages, not modals.
10. **Do not add feature flags or toggles**: This is a fresh rebuild. Ship complete features per phase. No partial rollouts needed.

---

## 20. Final Recommendation

### Should we proceed with this rebuild?

**Yes. Proceed.**

The rebuild is justified because:
1. The current monolith (2,224 lines, 45 state variables, no routing, no persistence) cannot scale to the investigation experience Guardian's backend deserves.
2. The backend is complete and well-structured — all 16 pages can be built with existing APIs, zero backend changes needed.
3. The data connectors and GraphViewer are solid and preserved — this is not a full rewrite.
4. The migration strategy (shell-first strangler fig) is safe — we build the new shell, extract tabs one-by-one, and delete the old code only when everything is migrated.

### How aggressively?

**Moderately aggressive.** Phase 1 (Foundation) should be built first and verified. If Phase 1 passes acceptance criteria, proceed directly through Phases 2-4 without pause. The risk of the rebuild is front-loaded in Phase 1 (getting the shell, routing, and session right). Once that's stable, the remaining phases are tab-extraction with known APIs.

### Execution gates

| Gate | Condition to Proceed |
|------|---------------------|
| Phase 1 → Phase 2 | Shell renders, auth works with session persistence, dashboard shows real data |
| Phase 2 → Phase 3 | Endpoint Detail page is complete with all tabs, cross-linking works end-to-end |
| Phase 3 → Phase 4 | Cycle/telemetry/graph pages work with real data, GraphViewer integration verified |
| Phase 4 → Done | LegacyApp.tsx deleted, all acceptance criteria pass, no inline styles remain |

---

## How the Palantir Reference Changed This v2 Plan

The Palantir UI/UX analysis (from EverythingAboutPalentir.pdf, palentirUi2.pdf, palentirUIPhil1.pdf) directly shaped 10 structural decisions in this plan:

### 1. Object-Centric Investigation → Endpoint Detail as the Hub
**Palantir principle**: Gotham/Foundry organize around objects, not screens. Every entity is a first-class investigation target with its own detail surface.
**Where it appears**: Endpoint Detail (Section 9.5) is the single most important page. The entire drill-down hierarchy (Section 8) converges on it. Every entity_id in the app is a clickable link to its detail page. This was a weakness in the old v1 plan where Endpoint Detail was listed as "NEW" but treated as secondary.

### 2. Risk-First Workflow → Dashboard and Sort Order
**Palantir principle**: Surface what's dangerous first. Severity drives visual hierarchy.
**Where it appears**: Dashboard (Section 9.3) leads with risk distribution, not system health. Endpoints table defaults to guardian_risk descending sort. Alert cards use severity left-border coloring. Severity badges are the most visually prominent element on every data surface.

### 3. Evidence-on-Demand → Progressive Disclosure Model
**Palantir principle**: Summary first, raw evidence available but never dumped upfront. Three-tier disclosure: immediate → secondary → advanced.
**Where it appears**: Visual hierarchy rules (Section 3, principle 9). Endpoint Detail tabs reveal deeper data progressively. Alert cards are expandable — title/severity visible, narrative/evidence on demand. Telemetry records expand to JSON tree on click.

### 4. Cross-Surface Drill-Down → Page Hierarchy Design
**Palantir principle**: Every view links to related investigation surfaces. No dead ends.
**Where it appears**: Full drill-down hierarchy (Section 8). Dashboard → Endpoints → Endpoint Detail → Graph → back. Every severity badge, entity_id, cycle_id, and finding is a link. The cross-linking diagram (Section 8) explicitly maps all navigation paths.

### 5. Strong Provenance → ProvenanceBar Component
**Palantir principle**: Institutions need audit trails. Every data point must show where it came from and when.
**Where it appears**: ProvenanceBar component (Section 14.1) shows cycle_id, snapshot_hash, first_seen, last_seen on every detail page. Topbar shows last scan timestamp. Endpoint identity header shows discovery_source. Cycle detail shows full metadata and hash.

### 6. Stable Shell + Left-Filter/Right-Content → Layout Architecture
**Palantir principle (from palentirUIPhil1)**: Persistent left navigation, pinned top bar, only content scrolls. F-shaped scan pattern. Filter rail on the left of data surfaces.
**Where it appears**: Navigation model (Section 6) with 286px fixed sidebar, 52px topbar, scrollable content. FilterRail component (Section 14.1) on Endpoints, Findings, Graph pages. Layout rules (Section 13) explicitly prohibit horizontal scrolling and require pinned navigation.

### 7. Compact, Serious, Enterprise Density → Visual System
**Palantir principle (from palentirUIPhil1)**: Information density is not "cramped." It means compact spacing, clear group boundaries, consistent rhythm, restrained highlights.
**Where it appears**: Full visual system (Section 13). 36-40px table rows. 4px base spacing unit. IBM Plex Sans/Mono typography. Muted color palette (#0a0a0a background, #232323 borders). No decorative elements. Animation rules (Section 13.9) explicitly ban non-functional animations.

### 8. Notes and Tasks Tied to Real Objects → Investigation Persistence
**Palantir principle (Dossier/Inbox thinking)**: Notes attach to investigation objects. Tasks track remediation. Both are object-scoped, not free-floating.
**Where it appears**: Notes and Tasks design (Section 12). Notes attach to endpoint/finding/alert/cycle/simulation by object_type + object_id. Tasks link to endpoints and findings with status tracking. Explicitly NOT a standalone notes app — always scoped to a real backend entity.

### 9. Admin as Control Plane → Settings Architecture
**Palantir principle (from Apollo)**: Admin is resource-scoped management. Explicit roles, explicit status. Structured permission views.
**Where it appears**: Settings page (Section 9.13) with sub-pages for profile/security/workspace/admin. Admin sub-page handles operator registration and tenant registration as explicit operations with master password gating. Workspace shows tenant configuration read-only. Not treated as an afterthought tab.

### 10. Progressive Disclosure Instead of Data Dumping → Entire UI Architecture
**Palantir principle**: Show what matters first. Detail on demand. Three levels: immediate risk → operational detail → raw evidence.
**Where it appears**: Every page spec (Section 9) explicitly defines "Immediately visible" vs "Progressive disclosure" content. Dashboard shows summary cards, not raw endpoint tables. Endpoint Detail uses tabs to stage information. Alerts use accordion expansion. Telemetry uses expandable JSON trees.

### What Was NOT Copied from Palantir

1. **No ontology/graph-first navigation**: Palantir's Foundry revolves around a generic object graph. Guardian's primary entity is the endpoint — not an abstract ontology node. The Trust Graph page exists but is not the primary navigation surface.
2. **No military/intelligence workflows**: No mission planning, no target packages, no SIGINT workflows. Guardian's workflows are cybersecurity posture assessment and compliance.
3. **No visual complexity for its own sake**: Palantir uses sophisticated visualizations (timeline rulers, geospatial maps, activity networks). Guardian uses simple metric cards, data tables, and one force-directed graph — because that's what the backend outputs warrant.
4. **No collaboration features beyond Notes/Tasks**: Palantir has real-time collaboration, shared workspaces, role-based dashboards. Guardian serves single-operator investigation with localStorage-backed notes. Collaboration is a future concern.
5. **No product sprawl**: Palantir has dozens of interconnected products. Guardian stays tight: one backend, one UI, one analytical pipeline, one investigation surface.

---

*End of plan. Ready for execution review.*
