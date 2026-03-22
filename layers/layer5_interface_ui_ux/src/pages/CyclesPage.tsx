import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useSessionStore } from "../stores/useSessionStore";
import { useDashboardStore } from "../stores/useDashboardStore";
import { ProvenanceBar } from "../components/display/ProvenanceBar";
import { ErrorBanner } from "../components/feedback/ErrorBanner";
import { SkeletonLoader } from "../components/feedback/SkeletonLoader";
import { EmptyState } from "../components/feedback/EmptyState";
import { extractCycleList, type ExtractedCycle } from "../lib/extractors";
import { dataSource } from "../lib/api";
import { formatTimestamp } from "../lib/formatters";
import { cycleDetailPath } from "../lib/routes";

export function CyclesPage() {
  const navigate = useNavigate();
  const tenantId = useSessionStore((s) => s.activeTenantId);
  const { data: dashData, fetchDashboard } = useDashboardStore();

  const [cycles, setCycles] = useState<ExtractedCycle[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (tenantId && !dashData) fetchDashboard(tenantId);
  }, [tenantId, dashData, fetchDashboard]);

  useEffect(() => {
    if (!tenantId) return;
    setLoading(true);
    setError(null);
    dataSource
      .listCycles(tenantId, { pageSize: 200 })
      .then((payload) => setCycles(extractCycleList(payload)))
      .catch((err) => setError(String(err)))
      .finally(() => setLoading(false));
  }, [tenantId]);

  if (loading && cycles.length === 0) {
    return (
      <div>
        <div className="g-section-label">Cycles</div>
        <SkeletonLoader variant="table" count={8} />
      </div>
    );
  }

  if (error) {
    return <ErrorBanner message={error} onRetry={() => window.location.reload()} />;
  }

  if (cycles.length === 0 && !loading) {
    return (
      <EmptyState
        message="No cycles have run yet. Start a scan from the onboarding page."
        action="Go to Onboarding"
        onAction={() => navigate("/onboarding")}
      />
    );
  }

  return (
    <div className="g-scroll-page">
      <div className="g-scroll-page__header">
        <div className="g-section-label">Scan Cycles</div>
        <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--muted)", marginBottom: 12 }}>
        {cycles.length} cycle{cycles.length !== 1 ? "s" : ""} recorded
      </div>
      </div>

      <div className="g-scroll-page__body">
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {cycles.map((cycle, idx) => (
          <div
            key={cycle.cycle_id}
            onClick={() => navigate(cycleDetailPath(cycle.cycle_id))}
            style={{
              background: "var(--panel)",
              border: "1px solid var(--border)",
              borderLeft: `3px solid ${cycle.status === "completed" ? "var(--color-severity-low)" : "var(--color-severity-medium)"}`,
              padding: "14px 16px",
              cursor: "pointer",
              transition: "background 0.15s",
            }}
            onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface)")}
            onMouseLeave={(e) => (e.currentTarget.style.background = "var(--panel)")}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
              <span style={{
                fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)",
                fontWeight: 600, color: "var(--pure)",
              }}>
                Scan #{cycle.cycle_number || (cycles.length - idx)}
              </span>
              <span style={{
                padding: "2px 8px",
                background: cycle.status === "completed" ? "rgba(34,197,94,0.1)" : "rgba(250,204,21,0.1)",
                border: `1px solid ${cycle.status === "completed" ? "rgba(34,197,94,0.3)" : "rgba(250,204,21,0.3)"}`,
                borderRadius: 2,
                fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)",
                color: cycle.status === "completed" ? "var(--color-severity-low)" : "var(--color-severity-medium)",
                textTransform: "uppercase", letterSpacing: "0.1em",
              }}>
                {cycle.status}
              </span>
              {cycle.new_endpoints > 0 && (
                <span style={{
                  padding: "2px 8px",
                  background: "rgba(59,130,246,0.1)",
                  border: "1px solid rgba(59,130,246,0.3)",
                  borderRadius: 2,
                  fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)",
                  color: "var(--color-severity-medium)",
                }}>
                  +{cycle.new_endpoints} new
                </span>
              )}
            </div>
            <div style={{ display: "flex", gap: 24, fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)" }}>
              <span style={{ color: "var(--ghost)" }}>
                {cycle.timestamp_ms ? formatTimestamp(cycle.timestamp_ms) : "-"}
              </span>
              <span style={{ color: "var(--ghost)" }}>
                Duration: {cycle.duration_ms ? `${(cycle.duration_ms / 1000).toFixed(1)}s` : "-"}
              </span>
              <span style={{ color: "var(--white)" }}>
                {cycle.endpoint_count || 0} endpoints
              </span>
            </div>
          </div>
        ))}
      </div>
      </div>

      {dashData && (
        <div className="g-scroll-page__footer">
          <ProvenanceBar cycleId={dashData.cycle_id} timestamp={dashData.timestamp_ms} />
        </div>
      )}
    </div>
  );
}
