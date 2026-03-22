import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useSessionStore } from "../stores/useSessionStore";
import { ProvenanceBar } from "../components/display/ProvenanceBar";
import { SeverityBadge } from "../components/display/SeverityBadge";
import { ErrorBanner } from "../components/feedback/ErrorBanner";
import { SkeletonLoader } from "../components/feedback/SkeletonLoader";
import { GraphViewer } from "../components/GraphViewer";
import {
  extractEndpointSnapshot,
  extractGuardianRecords,
  extractTemporalState,
  extractTrustGraph,
  extractLayer3State,
} from "../lib/extractors";
import { dataSource } from "../lib/api";
import {
  asObject, asString, asNumber, formatTimestamp, formatScore,
  formatHash, severityBand, downloadJson,
} from "../lib/formatters";
import { endpointDetailPath, telemetryPath } from "../lib/routes";

type TabKey = "overview" | "snapshot" | "guardian" | "temporal" | "graph" | "layer3" | "telemetry";

const TABS: { key: TabKey; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "snapshot", label: "Snapshot" },
  { key: "guardian", label: "Guardian" },
  { key: "temporal", label: "Temporal" },
  { key: "graph", label: "Trust Graph" },
  { key: "layer3", label: "Layer 3" },
  { key: "telemetry", label: "Telemetry" },
];

export function CycleDetailPage() {
  const { cycleId: rawCycleId } = useParams<{ cycleId: string }>();
  const cycleId = rawCycleId ? decodeURIComponent(rawCycleId) : "";
  const navigate = useNavigate();
  const tenantId = useSessionStore((s) => s.activeTenantId);

  const [bundle, setBundle] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>("overview");

  useEffect(() => {
    if (!tenantId || !cycleId) return;
    setLoading(true);
    setError(null);
    dataSource
      .getCycleBundle(tenantId, cycleId)
      .then((b) => setBundle(b))
      .catch((err) => setError(String(err)))
      .finally(() => setLoading(false));
  }, [tenantId, cycleId]);

  if (loading) {
    return (
      <div>
        <div className="g-section-label">Cycle: {cycleId}</div>
        <SkeletonLoader variant="card" count={3} />
      </div>
    );
  }

  if (error) {
    return <ErrorBanner message={error} onRetry={() => window.location.reload()} />;
  }

  if (!bundle) {
    return (
      <div className="g-empty">
        Cycle "{cycleId}" not found.{" "}
        <button className="btn btn-small btn-neutral" onClick={() => navigate("/cycles")}>Back to Cycles</button>
      </div>
    );
  }

  const meta = asObject(bundle.cycle_metadata ? (Array.isArray(bundle.cycle_metadata) ? bundle.cycle_metadata[0] : bundle.cycle_metadata) : bundle);
  const endpointSnapshot = extractEndpointSnapshot(bundle);
  const guardianRecords = extractGuardianRecords(bundle);
  const temporalState = extractTemporalState(bundle);
  const trustGraph = extractTrustGraph(bundle);
  const layer3State = extractLayer3State(bundle);

  return (
    <div>
      {/* Cycle header */}
      <div style={{ marginBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
          <button className="btn btn-small btn-neutral" onClick={() => navigate("/cycles")}>Back</button>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-h2)", fontWeight: 600, color: "var(--pure)" }}>
            Scan #{asNumber(meta.cycle_number || meta.sequence) || "—"}
          </span>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)" }}>
            {formatTimestamp(meta.timestamp_ms || meta.started_at_ms || meta.created_at_ms)}
          </span>
          <div style={{ flex: 1 }} />
          <button className="btn btn-small btn-neutral" onClick={() => downloadJson(`cycle_${cycleId}.json`, bundle)}>
            Export Raw
          </button>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 1, background: "var(--border)", border: "1px solid var(--border)" }}>
          {[
            { label: "Duration", value: asNumber(meta.duration_ms || meta.execution_time_ms) ? `${(asNumber(meta.duration_ms || meta.execution_time_ms) / 1000).toFixed(1)}s` : "-" },
            { label: "Endpoints", value: String(endpointSnapshot.length || asNumber(meta.endpoint_count)) },
            { label: "Guardian Records", value: String(guardianRecords.length) },
            { label: "Temporal Entries", value: String(temporalState.length) },
          ].map((item) => (
            <div key={item.label} style={{ background: "var(--panel)", padding: "10px 14px" }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.15em", marginBottom: 4 }}>{item.label}</div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-h3)", color: "var(--white)", fontWeight: 600 }}>{item.value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", borderBottom: "1px solid var(--border)", marginBottom: 16 }}>
        {TABS.map((tab) => (
          <button
            key={tab.key}
            onClick={() => {
              if (tab.key === "telemetry") {
                navigate(telemetryPath(cycleId));
                return;
              }
              setActiveTab(tab.key);
            }}
            style={{
              background: "none", border: "none",
              borderBottom: activeTab === tab.key ? "2px solid var(--pure)" : "2px solid transparent",
              padding: "10px 16px",
              fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)",
              letterSpacing: "0.08em", textTransform: "uppercase",
              color: activeTab === tab.key ? "var(--pure)" : "var(--muted)",
              cursor: "pointer",
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {activeTab === "overview" && <OverviewTab meta={meta} bundle={bundle} snapshotCount={endpointSnapshot.length} guardianCount={guardianRecords.length} temporalCount={temporalState.length} />}
      {activeTab === "snapshot" && <SnapshotTab endpoints={endpointSnapshot} navigate={navigate} />}
      {activeTab === "guardian" && <GuardianTab records={guardianRecords} navigate={navigate} />}
      {activeTab === "temporal" && <TemporalTab state={temporalState} />}
      {activeTab === "graph" && <GraphTab snapshot={trustGraph} />}
      {activeTab === "layer3" && <Layer3Tab state={layer3State} />}
    </div>
  );
}

function KV({ label, value }: { label: string; value: string }) {
  return (
    <span style={{ display: "inline-flex", gap: 6 }}>
      <span style={{ color: "var(--muted)", fontSize: "var(--font-size-label)", letterSpacing: "0.15em", textTransform: "uppercase", fontFamily: "var(--font-mono)" }}>{label}</span>
      <span style={{ color: "var(--ghost)", fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)" }}>{value}</span>
    </span>
  );
}

function OverviewTab({ meta, bundle, snapshotCount, guardianCount, temporalCount }: {
  meta: Record<string, unknown>; bundle: Record<string, unknown>;
  snapshotCount: number; guardianCount: number; temporalCount: number;
}) {
  const keys = Object.keys(bundle).filter((k) => k !== "cycle_metadata");
  const buildStats = asObject(meta.build_stats);
  const postureSummary = asObject(buildStats.posture_summary);
  const expansionSummary = asObject(buildStats.expansion_summary);
  const runtimeSummary = asObject(meta.runtime_summary);
  const integritySummary = asObject(bundle.integrity_summary);
  const moduleScorecard = Array.isArray(expansionSummary.module_scorecard)
    ? expansionSummary.module_scorecard.map((row) => asObject(row)).filter((row) => Object.keys(row).length > 0)
    : [];
  const stageHistory = Array.isArray(runtimeSummary.stage_history)
    ? runtimeSummary.stage_history.map((row) => asObject(row)).filter((row) => Object.keys(row).length > 0)
    : [];
  const integrityWarnings = Array.isArray(integritySummary.warnings)
    ? integritySummary.warnings.map((row) => asString(row)).filter(Boolean)
    : [];
  const productiveCategoryAModules = Array.isArray(expansionSummary.productive_category_a_modules)
    ? expansionSummary.productive_category_a_modules
    : [];
  const productiveBcdeModules = Array.isArray(expansionSummary.productive_bcde_modules)
    ? expansionSummary.productive_bcde_modules
    : [];

  // Pick only user-meaningful metadata fields
  const displayFields: { label: string; value: string }[] = [
    { label: "Status", value: asString(meta.status) || "completed" },
    { label: "Started", value: formatTimestamp(meta.timestamp_ms || meta.started_at_ms || meta.created_at_ms) },
    { label: "Duration", value: asNumber(meta.duration_ms || meta.execution_time_ms) ? `${(asNumber(meta.duration_ms || meta.execution_time_ms) / 1000).toFixed(1)}s` : "-" },
    { label: "Endpoints Scanned", value: String(snapshotCount || asNumber(meta.endpoint_count)) },
    { label: "New Endpoints", value: String(asNumber(meta.new_endpoints || meta.discovered)) },
    { label: "Removed Endpoints", value: String(asNumber(meta.removed_endpoints || meta.removed)) },
  ].filter((f) => f.value && f.value !== "0" && f.value !== "-" ? true : true);

  return (
    <div>
      <div className="g-section-label">Scan Summary</div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 1, background: "var(--border)", border: "1px solid var(--border)", marginBottom: 16 }}>
        {displayFields.map((item) => (
          <div key={item.label} style={{ background: "var(--panel)", padding: 12 }}>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.15em", marginBottom: 4 }}>{item.label}</div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)" }}>
              {item.value}
            </div>
          </div>
        ))}
      </div>

      {Object.keys(buildStats).length > 0 && (
        <>
          <div className="g-section-label">Reporting Metrics</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 1, background: "var(--border)", border: "1px solid var(--border)", marginBottom: 16 }}>
            {[
              { label: "Discovered Related", value: String(asNumber(buildStats.discovered_related_endpoints || buildStats.total_discovered_domains)) },
              { label: "Observation Attempts", value: String(asNumber(buildStats.observation_attempts || buildStats.total_observations)) },
              { label: "Observation Success", value: String(asNumber(buildStats.observation_successes || buildStats.total_successful_observations || buildStats.successful_observations)) },
              { label: "Observation Failed", value: String(asNumber(buildStats.observation_failures || buildStats.total_failed_observations || buildStats.failed_observations)) },
              { label: "Recorded In Snapshot", value: String(asNumber(buildStats.recorded_endpoints || buildStats.endpoints_canonical)) },
              { label: "Unverified / Historical", value: String(asNumber(buildStats.unverified_historical_endpoints)) },
              { label: "TLS Findings", value: String(asNumber(postureSummary.tls_findings_count)) },
              { label: "WAF Findings", value: String(asNumber(postureSummary.waf_findings_count)) },
              { label: "Avg Crypto Health", value: formatScore(postureSummary.avg_cryptographic_health_score) },
              { label: "Avg Protection Posture", value: formatScore(postureSummary.avg_protection_posture_score) },
              { label: "Duplicates Merged", value: String(asNumber(buildStats.duplicates_merged)) },
            ].map((item) => (
              <div key={item.label} style={{ background: "var(--panel)", padding: 12 }}>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.15em", marginBottom: 4 }}>{item.label}</div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)" }}>
                  {item.value}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {Object.keys(expansionSummary).length > 0 && (
        <>
          <div className="g-section-label">Expansion Strategy</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 1, background: "var(--border)", border: "1px solid var(--border)", marginBottom: 16 }}>
            {[
              { label: "Strategy", value: asString(expansionSummary.strategy) || "-" },
              { label: "Scopes", value: String(asNumber(expansionSummary.scope_count)) },
              { label: "Expanded Candidates", value: String(asNumber(expansionSummary.total_expanded_candidates)) },
              { label: "Visible Discovered Surface", value: String(asNumber(expansionSummary.discovered_surface_count)) },
              { label: "Observation Target", value: String(asNumber(expansionSummary.observation_target_count)) },
              { label: "A Productive Modules", value: String(productiveCategoryAModules.length) },
              { label: "BCDE Productive Modules", value: String(productiveBcdeModules.length) },
              { label: "Ceiling Hits", value: String(asNumber(expansionSummary.ceilings_hit_scope_count)) },
              { label: "Time Slice", value: asNumber(expansionSummary.module_time_slice_seconds) ? `${asNumber(expansionSummary.module_time_slice_seconds)}s` : "-" },
            ].map((item) => (
              <div key={item.label} style={{ background: "var(--panel)", padding: 12 }}>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.15em", marginBottom: 4 }}>{item.label}</div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)" }}>{item.value}</div>
              </div>
            ))}
          </div>

          {moduleScorecard.length > 0 && (
            <div style={{ border: "1px solid var(--border)", marginBottom: 16 }}>
              <div style={{
                display: "grid", gridTemplateColumns: "1.8fr 0.8fr 0.8fr 0.8fr 0.9fr 0.9fr",
                gap: 8, padding: "8px 12px", background: "var(--panel)", borderBottom: "1px solid var(--border)",
                fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)",
                letterSpacing: "0.2em", textTransform: "uppercase", color: "var(--muted)",
              }}>
                <span>Module</span><span>Cat</span><span>Runs</span><span>Productive</span><span>Candidates</span><span>Avg Time</span>
              </div>
              {moduleScorecard.slice(0, 16).map((row, idx) => (
                <div key={`${asString(row.module_name)}-${idx}`} style={{
                  display: "grid", gridTemplateColumns: "1.8fr 0.8fr 0.8fr 0.8fr 0.9fr 0.9fr",
                  gap: 8, padding: "8px 12px", borderBottom: "1px solid var(--border)",
                  fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)",
                }}>
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{asString(row.module_name) || "-"}</span>
                  <span style={{ color: "var(--ghost)" }}>{asString(row.category) || "-"}</span>
                  <span>{asNumber(row.invocation_count)}</span>
                  <span>{asNumber(row.productive_runs)}</span>
                  <span>{asNumber(row.produced_candidate_count)}</span>
                  <span style={{ color: "var(--ghost)" }}>{asNumber(row.avg_elapsed_s) ? `${asNumber(row.avg_elapsed_s).toFixed(2)}s` : "-"}</span>
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {Object.keys(runtimeSummary).length > 0 && (
        <>
          <div className="g-section-label">Runtime Trace</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 1, background: "var(--border)", border: "1px solid var(--border)", marginBottom: 16 }}>
            {[
              { label: "Runtime", value: asNumber(runtimeSummary.total_runtime_ms) ? `${(asNumber(runtimeSummary.total_runtime_ms) / 1000).toFixed(1)}s` : "-" },
              { label: "Within Budget", value: runtimeSummary.within_budget ? "YES" : "NO" },
              { label: "Stage Count", value: String(stageHistory.length) },
              { label: "Observed Completed", value: String(asNumber(asObject(runtimeSummary.progress_snapshot).observed_completed_count)) },
            ].map((item) => (
              <div key={item.label} style={{ background: "var(--panel)", padding: 12 }}>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.15em", marginBottom: 4 }}>{item.label}</div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)" }}>{item.value}</div>
              </div>
            ))}
          </div>

          {stageHistory.length > 0 && (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 16 }}>
              {stageHistory.map((row, idx) => (
                <span key={`${asString(row.stage)}-${idx}`} style={{
                  padding: "6px 10px",
                  background: "var(--panel)",
                  border: "1px solid var(--border)",
                  fontFamily: "var(--font-mono)",
                  fontSize: "var(--font-size-caption)",
                  color: "var(--ghost)",
                }}>
                  {asString(row.stage) || "-"} · {asNumber(row.duration_ms) ? `${(asNumber(row.duration_ms) / 1000).toFixed(1)}s` : "0.0s"}
                </span>
              ))}
            </div>
          )}
        </>
      )}

      {Object.keys(integritySummary).length > 0 && (
        <>
          <div className="g-section-label">Replay Integrity</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 1, background: "var(--border)", border: "1px solid var(--border)", marginBottom: 16 }}>
            {[
              { label: "Exact Replay", value: integritySummary.exact_cycle_replayable ? "YES" : "NO" },
              { label: "Served Complete", value: integritySummary.served_view_complete ? "YES" : "NO" },
              { label: "Guardian Non-Zero Rate", value: formatScore(asNumber(asObject(integritySummary.coverage).guardian_nonzero_rate_01)) },
              { label: "Telemetry Outside Snapshot", value: String(asNumber(asObject(integritySummary.coverage).telemetry_entities_not_in_snapshot_count)) },
              { label: "Guardian Outside Snapshot", value: String(asNumber(asObject(integritySummary.coverage).guardian_entities_not_in_snapshot_count)) },
              { label: "Persisted Telemetry", value: String(asNumber(asObject(integritySummary.persisted_counts).telemetry_records)) },
              { label: "Persisted Guardian", value: String(asNumber(asObject(integritySummary.persisted_counts).guardian_records)) },
              { label: "Latest Match", value: integritySummary.latest_cycle_match ? "YES" : "NO" },
            ].map((item) => (
              <div key={item.label} style={{ background: "var(--panel)", padding: 12 }}>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.15em", marginBottom: 4 }}>{item.label}</div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)" }}>{item.value}</div>
              </div>
            ))}
          </div>

          {integrityWarnings.length > 0 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 4, marginBottom: 16 }}>
              {integrityWarnings.map((warning, idx) => (
                <div key={`${warning}-${idx}`} style={{
                  background: "var(--panel)",
                  border: "1px solid var(--border)",
                  borderLeft: "3px solid var(--color-severity-high)",
                  padding: "10px 12px",
                  fontFamily: "var(--font-mono)",
                  fontSize: "var(--font-size-caption)",
                  color: "var(--ghost)",
                }}>
                  {warning}
                </div>
              ))}
            </div>
          )}
        </>
      )}

      <div className="g-section-label">Available Data</div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
        {keys.map((k) => {
          const count = k === "endpoint_snapshot" || k === "endpoints" ? snapshotCount
            : k === "guardian_records" ? guardianCount
            : k === "temporal_state" || k === "temporal_state_snapshot" ? temporalCount
            : Array.isArray(bundle[k]) ? (bundle[k] as unknown[]).length : null;
          // Format key names to be human-readable
          const label = k.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
          return (
            <span key={k} style={{
              padding: "6px 12px", background: "var(--panel)", border: "1px solid var(--border)",
              fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)",
              borderRadius: 2,
            }}>
              {label}{count != null ? ` · ${count}` : ""}
            </span>
          );
        })}
      </div>
    </div>
  );
}

function SnapshotTab({ endpoints, navigate }: { endpoints: Record<string, unknown>[]; navigate: ReturnType<typeof import("react-router-dom").useNavigate> }) {
  if (endpoints.length === 0) return <div className="g-empty">No endpoint snapshot in this bundle.</div>;

  return (
    <div style={{ border: "1px solid var(--border)" }}>
      <div style={{
        display: "grid", gridTemplateColumns: "2fr 1fr 80px 80px 80px 100px",
        gap: 8, padding: "8px 12px", background: "var(--panel)", borderBottom: "1px solid var(--border)",
        fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)",
        letterSpacing: "0.2em", textTransform: "uppercase", color: "var(--muted)",
      }}>
        <span>Endpoint</span><span>Hostname</span><span>Risk</span><span>Conf</span><span>Alerts</span><span>TLS</span>
      </div>
      {endpoints.slice(0, 200).map((ep, idx) => {
        const entityId = asString(ep.entity_id);
        const risk = asNumber(ep.guardian_risk);
        const band = severityBand(risk);
        return (
          <div key={entityId || idx}
            onClick={() => entityId && navigate(endpointDetailPath(entityId))}
            style={{
              display: "grid", gridTemplateColumns: "2fr 1fr 80px 80px 80px 100px",
              gap: 8, padding: "8px 12px", borderBottom: "1px solid var(--border)",
              cursor: entityId ? "pointer" : "default", fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)",
            }}
            onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface)")}
            onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
          >
            <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{entityId || "-"}</span>
            <span style={{ color: "var(--ghost)" }}>{asString(ep.hostname) || "-"}</span>
            <span style={{ color: `var(--color-severity-${band})` }}>{formatScore(risk)}</span>
            <span style={{ color: "var(--ghost)" }}>{formatScore(asNumber(ep.confidence))}</span>
            <span>{asNumber(ep.alert_count)}</span>
            <span style={{ color: "var(--ghost)" }}>{asString(ep.tls_version) || "-"}</span>
          </div>
        );
      })}
      {endpoints.length > 200 && <div className="g-empty">Showing 200 of {endpoints.length} endpoints.</div>}
    </div>
  );
}

function GuardianTab({ records, navigate }: { records: Record<string, unknown>[]; navigate: ReturnType<typeof import("react-router-dom").useNavigate> }) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  if (records.length === 0) return <div className="g-empty">No guardian records in this bundle.</div>;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--muted)", marginBottom: 4 }}>
        {records.length} guardian record{records.length !== 1 ? "s" : ""}
      </div>
      {records.slice(0, 200).map((rec, idx) => {
        const entityId = asString(rec.entity_id);
        const severity = asNumber(rec.overall_severity_01) * 10;
        const band = severityBand(severity);
        const confidence = asNumber(rec.overall_confidence_01);
        const narrative = typeof rec.narrative === "string" ? rec.narrative : "";
        const advisory = typeof rec.advisory === "string" ? rec.advisory : "";
        const campaignPhase = asString(rec.campaign_phase);
        const alerts = Array.isArray(rec.alerts) ? rec.alerts : [];
        const isExp = expanded.has(idx);
        return (
          <div key={idx} style={{
            background: "var(--panel)", border: "1px solid var(--border)",
            borderLeft: `3px solid var(--color-severity-${band})`,
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "12px 14px", cursor: "pointer" }}
              onClick={() => { const next = new Set(expanded); isExp ? next.delete(idx) : next.add(idx); setExpanded(next); }}>
              <SeverityBadge band={band} label={formatScore(severity)} />
              <span onClick={(e) => { e.stopPropagation(); entityId && navigate(endpointDetailPath(entityId)); }}
                style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)", cursor: "pointer", textDecoration: "underline", textUnderlineOffset: 2, fontWeight: 600 }}>
                {entityId}
              </span>
              {campaignPhase && (
                <span style={{
                  padding: "2px 8px", background: "var(--surface)", border: "1px solid var(--border)",
                  fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--ghost)",
                  borderRadius: 2,
                }}>
                  {campaignPhase}
                </span>
              )}
              <span style={{ flex: 1 }} />
              {alerts.length > 0 && (
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)" }}>
                  {alerts.length} alert{alerts.length !== 1 ? "s" : ""}
                </span>
              )}
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--muted)" }}>{isExp ? "▾" : "▸"}</span>
            </div>
            {isExp && (
              <div style={{ padding: "0 14px 14px 14px", borderTop: "1px solid var(--border)" }}>
                {/* Metrics row */}
                <div style={{ display: "flex", gap: 24, padding: "10px 0", flexWrap: "wrap" }}>
                  <KV label="Severity" value={formatScore(severity)} />
                  <KV label="Confidence" value={formatScore(confidence, 2)} />
                  {asNumber(rec.sync_index) > 0 && <KV label="Sync Index" value={formatScore(asNumber(rec.sync_index))} />}
                </div>

                {/* Narrative */}
                {narrative && (
                  <div style={{ padding: 10, background: "var(--black)", border: "1px solid var(--border)", marginBottom: 8, borderRadius: 2 }}>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.2em" }}>Narrative</div>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", whiteSpace: "pre-wrap", lineHeight: 1.5 }}>
                      {narrative}
                    </div>
                  </div>
                )}

                {/* Advisory */}
                {advisory && (
                  <div style={{ padding: 10, background: "var(--black)", border: "1px solid var(--border)", marginBottom: 8, borderRadius: 2 }}>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.2em" }}>Advisory</div>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", whiteSpace: "pre-wrap", lineHeight: 1.5 }}>
                      {advisory}
                    </div>
                  </div>
                )}

                {/* Individual alerts */}
                {alerts.length > 0 && (
                  <div style={{ marginTop: 4 }}>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.2em" }}>Alerts</div>
                    {alerts.map((alert, ai) => {
                      const a = asObject(alert);
                      const aBand = severityBand(asNumber(a.severity_01) * 10);
                      return (
                        <div key={ai} style={{ padding: "8px 10px", borderLeft: `2px solid var(--color-severity-${aBand})`, background: "var(--black)", marginBottom: 4, borderRadius: 2 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                            <SeverityBadge band={aBand} label={asString(a.alert_kind)} />
                            <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)" }}>{asString(a.title)}</span>
                          </div>
                          {asString(a.body) && (
                            <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", lineHeight: 1.5 }}>
                              {asString(a.body)}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function TemporalTab({ state }: { state: Record<string, unknown>[] }) {
  if (state.length === 0) return <div className="g-empty">No temporal state data in this bundle.</div>;

  return (
    <div style={{ border: "1px solid var(--border)" }}>
      <div style={{
        display: "grid", gridTemplateColumns: "2fr 80px 80px 80px 140px",
        gap: 8, padding: "8px 12px", background: "var(--panel)", borderBottom: "1px solid var(--border)",
        fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)",
        letterSpacing: "0.2em", textTransform: "uppercase", color: "var(--muted)",
      }}>
        <span>Entity ID</span><span>Volatility</span><span>Visibility</span><span>Absence</span><span>Last Seen</span>
      </div>
      {state.slice(0, 200).map((row, idx) => (
        <div key={idx} style={{
          display: "grid", gridTemplateColumns: "2fr 80px 80px 80px 140px",
          gap: 8, padding: "8px 12px", borderBottom: "1px solid var(--border)",
          fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)",
        }}>
          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{asString(row.entity_id) || "-"}</span>
          <span style={{ color: "var(--ghost)" }}>{formatScore(asNumber(row.volatility_score))}</span>
          <span style={{ color: "var(--ghost)" }}>{formatScore(asNumber(row.visibility_score))}</span>
          <span>{asNumber(row.consecutive_absence)}</span>
          <span style={{ color: "var(--ghost)" }}>{formatTimestamp(row.last_seen_ms)}</span>
        </div>
      ))}
      {state.length > 200 && <div className="g-empty">Showing 200 of {state.length} entries.</div>}
    </div>
  );
}

function GraphTab({ snapshot }: { snapshot: unknown }) {
  if (!snapshot) return <div className="g-empty">No trust graph snapshot in this bundle.</div>;
  return <GraphViewer snapshot={snapshot} width={920} height={520} />;
}

function Layer3Tab({ state }: { state: unknown }) {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set());

  if (!state) return <div className="g-empty">No Layer 3 state snapshot in this bundle.</div>;

  const stateObj = asObject(state as Record<string, unknown>);
  const sections = Object.keys(stateObj);

  // If it's not an object with sections, render formatted
  if (sections.length === 0) {
    const raw = typeof state === "string" ? state : JSON.stringify(state, null, 2);
    return (
      <div style={{ padding: 12, background: "var(--black)", border: "1px solid var(--border)", borderRadius: 2 }}>
        <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.2em" }}>
          Analytical State
        </div>
        <pre style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 500, overflow: "auto", lineHeight: 1.6 }}>
          {raw}
        </pre>
      </div>
    );
  }

  function toggleSection(key: string) {
    setExpandedSections((prev) => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--muted)", marginBottom: 4 }}>
        Analytical state — {sections.length} section{sections.length !== 1 ? "s" : ""}
      </div>
      {sections.map((key) => {
        const value = stateObj[key];
        const isExpanded = expandedSections.has(key);
        const itemCount = Array.isArray(value) ? value.length : typeof value === "object" && value ? Object.keys(value).length : null;
        const label = key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

        return (
          <div key={key} style={{ background: "var(--panel)", border: "1px solid var(--border)", borderRadius: 2 }}>
            <div
              style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", cursor: "pointer" }}
              onClick={() => toggleSection(key)}
            >
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)", fontWeight: 600 }}>
                {label}
              </span>
              {itemCount != null && (
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", padding: "1px 6px", background: "var(--surface)", borderRadius: 2 }}>
                  {itemCount} {Array.isArray(value) ? "entries" : "fields"}
                </span>
              )}
              <span style={{ flex: 1 }} />
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--muted)" }}>{isExpanded ? "▾" : "▸"}</span>
            </div>
            {isExpanded && (
              <div style={{ padding: "0 14px 14px 14px", borderTop: "1px solid var(--border)" }}>
                {Array.isArray(value) && value.length > 0 && typeof asObject(value[0]) === "object" && Object.keys(asObject(value[0])).length > 0 ? (
                  /* Render array of objects as a mini-table */
                  <div style={{ maxHeight: 400, overflow: "auto", marginTop: 8 }}>
                    {value.slice(0, 100).map((item, i) => {
                      const row = asObject(item);
                      const rowKeys = Object.keys(row).filter((k) => !k.includes("id") && !k.includes("hash"));
                      return (
                        <div key={i} style={{ display: "flex", gap: 16, padding: "6px 0", borderBottom: "1px solid var(--border)", flexWrap: "wrap" }}>
                          {rowKeys.slice(0, 6).map((rk) => (
                            <span key={rk} style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)" }}>
                              <span style={{ color: "var(--muted)", fontSize: "var(--font-size-label)", textTransform: "uppercase", letterSpacing: "0.1em" }}>{rk.replace(/_/g, " ")} </span>
                              <span style={{ color: "var(--ghost)" }}>{typeof row[rk] === "number" ? formatScore(row[rk] as number) : String(row[rk] ?? "-")}</span>
                            </span>
                          ))}
                        </div>
                      );
                    })}
                    {value.length > 100 && <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", padding: "8px 0" }}>Showing 100 of {value.length} entries</div>}
                  </div>
                ) : (
                  <pre style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", margin: "8px 0 0 0", whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 400, overflow: "auto", lineHeight: 1.6 }}>
                    {JSON.stringify(value, null, 2)}
                  </pre>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
