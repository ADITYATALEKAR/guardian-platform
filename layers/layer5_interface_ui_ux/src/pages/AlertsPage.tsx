import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useSessionStore } from "../stores/useSessionStore";
import { useDashboardStore, type EndpointDTO } from "../stores/useDashboardStore";
import { ProvenanceBar } from "../components/display/ProvenanceBar";
import { MetricCard } from "../components/display/MetricCard";
import { AlertCard } from "../components/display/AlertCard";
import { ErrorBanner } from "../components/feedback/ErrorBanner";
import { SkeletonLoader } from "../components/feedback/SkeletonLoader";
import { EmptyState } from "../components/feedback/EmptyState";
import { extractAlerts, flattenAlerts, type FlatAlert, type ExtractedAlert } from "../lib/extractors";
import { dataSource } from "../lib/api";
import { formatOwnershipLabel, summarizeDiscoverySources } from "../lib/endpointContext";
import { severityBand, severityColor } from "../lib/formatters";
import { endpointDetailPath } from "../lib/routes";

type SeverityFilter = "all" | "critical" | "high" | "medium" | "low";
type SortKey = "severity" | "confidence";

export function AlertsPage() {
  const navigate = useNavigate();
  const tenantId = useSessionStore((s) => s.activeTenantId);
  const { data: dashData, fetchDashboard } = useDashboardStore();

  const [alerts, setAlerts] = useState<FlatAlert[]>([]);
  const [groupedAlerts, setGroupedAlerts] = useState<ExtractedAlert[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [phaseFilter, setPhaseFilter] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("severity");

  useEffect(() => {
    if (tenantId && !dashData) fetchDashboard(tenantId);
  }, [tenantId, dashData, fetchDashboard]);

  useEffect(() => {
    if (!tenantId || !dashData?.cycle_id) return;
    setLoading(true);
    setError(null);
    dataSource
      .getCycleBundle(tenantId, dashData.cycle_id)
      .then((bundle) => {
        const records = extractAlerts(bundle);
        setGroupedAlerts(records);
        setAlerts(flattenAlerts(records));
      })
      .catch((err) => setError(String(err)))
      .finally(() => setLoading(false));
  }, [tenantId, dashData?.cycle_id]);

  const phases = useMemo(() => {
    const set = new Set<string>();
    for (const a of alerts) {
      if (a.campaign_phase) set.add(a.campaign_phase);
    }
    return [...set].sort();
  }, [alerts]);
  const endpointById = useMemo(
    () => new Map((dashData?.endpoints ?? []).map((endpoint) => [endpoint.entity_id, endpoint])),
    [dashData?.endpoints],
  );
  const meaningfulRecords = groupedAlerts;

  const counts = useMemo(() => {
    const c = { total: meaningfulRecords.length, critical: 0, high: 0, medium: 0, low: 0 };
    for (const record of meaningfulRecords) {
      const band = severityBand(record.overall_severity_01 * 10);
      if (band === "critical") c.critical++;
      else if (band === "high") c.high++;
      else if (band === "medium") c.medium++;
      else c.low++;
    }
    return c;
  }, [meaningfulRecords]);
  const displayRecords = useMemo(() => {
    let list = meaningfulRecords;
    if (severityFilter !== "all") {
      list = list.filter((record) => severityBand(record.overall_severity_01 * 10) === severityFilter);
    }
    if (phaseFilter) {
      list = list.filter((record) => record.campaign_phase === phaseFilter);
    }
    return [...list].sort((a, b) => {
      if (sortKey === "severity") return b.overall_severity_01 - a.overall_severity_01;
      return b.overall_confidence_01 - a.overall_confidence_01;
    });
  }, [meaningfulRecords, severityFilter, phaseFilter, sortKey]);
  const visibleAlertSignalCount = useMemo(
    () => displayRecords.reduce((total, record) => total + Math.max(record.alerts.length, 1), 0),
    [displayRecords],
  );



  if (loading && groupedAlerts.length === 0) {
    return (
      <div>
        <div className="g-section-label">Alerts</div>
        <SkeletonLoader variant="metric" count={4} />
        <div style={{ marginTop: 12 }}><SkeletonLoader variant="card" count={6} /></div>
      </div>
    );
  }

  if (error) {
    return <ErrorBanner message={error} onRetry={() => window.location.reload()} />;
  }

  if (meaningfulRecords.length === 0 && !loading) {
    return (
      <EmptyState
        message="No Guardian alerts yet. Guardian has not flagged any concerning related endpoint patterns in the current cycle."
        action="Go to Dashboard"
        onAction={() => navigate("/dashboard")}
      />
    );
  }

  return (
    <div className="g-scroll-page">
      <div className="g-scroll-page__header">
        <div className="g-section-label">Guardian Alerts</div>

        <div className="g-metric-grid" style={{ gridTemplateColumns: "repeat(5, minmax(100px, 1fr))", marginBottom: 16 }}>
        <MetricCard label="Total" value={counts.total} onClick={() => setSeverityFilter("all")} />
        <MetricCard label="Critical" value={counts.critical} color="var(--color-severity-critical)" onClick={() => setSeverityFilter("critical")} />
        <MetricCard label="High" value={counts.high} color="var(--color-severity-high)" onClick={() => setSeverityFilter("high")} />
        <MetricCard label="Medium" value={counts.medium} color="var(--color-severity-medium)" onClick={() => setSeverityFilter("medium")} />
        <MetricCard label="Low" value={counts.low} color="var(--color-severity-low)" onClick={() => setSeverityFilter("low")} />
      </div>

        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
        {/* Severity filter chips */}
        <div style={{ display: "flex", gap: 4 }}>
          {(["all", "critical", "high", "medium", "low"] as const).map((s) => (
            <button
              key={s}
              onClick={() => setSeverityFilter(s)}
              className="btn btn-small"
              style={{
                background: severityFilter === s ? "var(--surface)" : "transparent",
                borderColor: severityFilter === s ? "var(--pure)" : "var(--border)",
                color: s === "all" ? "var(--white)" : severityColor(s),
                textTransform: "uppercase",
              }}
            >
              {s}
            </button>
          ))}
        </div>

        {/* Campaign phase filter */}
        {phases.length > 0 && (
          <select
            value={phaseFilter}
            onChange={(e) => setPhaseFilter(e.target.value)}
            style={{
              padding: "4px 8px", background: "var(--panel)", border: "1px solid var(--border)",
              color: "var(--white)", fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)",
            }}
          >
            <option value="">All Phases</option>
            {phases.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
        )}

        {/* Sort toggle */}
        <div style={{ display: "flex", gap: 4 }}>
          <button className={`btn btn-small ${sortKey === "severity" ? "btn-primary" : "btn-neutral"}`} onClick={() => setSortKey("severity")}>By Severity</button>
          <button className={`btn btn-small ${sortKey === "confidence" ? "btn-primary" : "btn-neutral"}`} onClick={() => setSortKey("confidence")}>By Confidence</button>
        </div>

        <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--muted)", marginLeft: "auto" }}>
          {displayRecords.length} affected endpoint{displayRecords.length !== 1 ? "s" : ""} | {visibleAlertSignalCount} alert signal{visibleAlertSignalCount !== 1 ? "s" : ""}
        </span>
      </div>
      </div>

      <div className="g-scroll-page__body g-scroll-page__body--stack">
        {displayRecords.map((record, idx) => (
          <div key={idx} style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <AlertEvidenceStrip endpoint={endpointById.get(record.entity_id) ?? null} />
            <AlertCard
              entityId={record.entity_id}
              overallSeverity01={record.overall_severity_01}
              overallConfidence01={record.overall_confidence_01}
              campaignPhase={record.campaign_phase}
              narrative={record.narrative}
              advisory={record.advisory}
              syncIndex={record.sync_index}
              alerts={record.alerts}
              trend={record.overall_severity_01 >= 0.7 ? "escalating" : record.overall_severity_01 >= 0.4 ? "stable" : "declining"}
              onEntityClick={() => navigate(endpointDetailPath(record.entity_id))}
            />
          </div>
        ))}
      </div>

      {dashData && (
        <div className="g-scroll-page__footer">
          <ProvenanceBar cycleId={dashData.cycle_id} timestamp={dashData.timestamp_ms} />
        </div>
      )}
    </div>
  );
}

function AlertEvidenceStrip({ endpoint }: { endpoint: EndpointDTO | null }) {
  if (!endpoint) return null;
  return (
    <div
      style={{
        background: "var(--panel)",
        border: "1px solid var(--border)",
        padding: "8px 12px",
        display: "flex",
        flexWrap: "wrap",
        gap: 12,
        fontFamily: "var(--font-mono)",
        fontSize: "var(--font-size-label)",
        color: "var(--ghost)",
        textTransform: "uppercase",
        letterSpacing: "0.08em",
      }}
    >
      <span>{formatOwnershipLabel(endpoint.ownership_category)}</span>
      <span>Rel {endpoint.relevance_score.toFixed(2)}</span>
      <span>{summarizeDiscoverySources(endpoint.discovery_sources, endpoint.discovery_source, 2)}</span>
      <span style={{ color: "var(--muted)", textTransform: "none", letterSpacing: "normal" }}>
        {endpoint.relevance_reason}
      </span>
    </div>
  );
}
