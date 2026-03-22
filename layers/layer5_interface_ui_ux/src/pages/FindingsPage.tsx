import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useSessionStore } from "../stores/useSessionStore";
import { useDashboardStore } from "../stores/useDashboardStore";
import { SeverityBadge } from "../components/display/SeverityBadge";
import { ProvenanceBar } from "../components/display/ProvenanceBar";
import { MetricCard } from "../components/display/MetricCard";
import { ErrorBanner } from "../components/feedback/ErrorBanner";
import { SkeletonLoader } from "../components/feedback/SkeletonLoader";
import { EmptyState } from "../components/feedback/EmptyState";
import { extractFindings, type ExtractedFinding } from "../lib/extractors";
import { dataSource } from "../lib/api";
import { formatOwnershipLabel, summarizeDiscoverySources } from "../lib/endpointContext";
import { severityColor, formatTimestamp, formatScore, downloadCsv } from "../lib/formatters";
import { endpointDetailPath } from "../lib/routes";

type GroupBy = "type" | "endpoint";
type SeverityFilter = "all" | "critical" | "high" | "medium" | "low";

export function FindingsPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const tenantId = useSessionStore((s) => s.activeTenantId);
  const { data: dashData, fetchDashboard } = useDashboardStore();

  const [findings, setFindings] = useState<ExtractedFinding[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [groupBy, setGroupBy] = useState<GroupBy>("type");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>(
    (searchParams.get("severity") as SeverityFilter) || "all"
  );
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");

  useEffect(() => {
    if (tenantId && !dashData) fetchDashboard(tenantId);
  }, [tenantId, dashData, fetchDashboard]);

  useEffect(() => {
    if (!tenantId || !dashData?.cycle_id) return;
    setLoading(true);
    setError(null);
    dataSource
      .getAllCycleTelemetry(tenantId, dashData.cycle_id, { recordType: "posture_findings", pageSize: 1000, maxPages: 20 })
      .then((res) => setFindings(extractFindings(res)))
      .catch((err) => setError(String(err)))
      .finally(() => setLoading(false));
  }, [tenantId, dashData?.cycle_id]);

  const filtered = useMemo(() => {
    let list = findings;
    if (severityFilter !== "all") {
      list = list.filter((f) => f.severity === severityFilter);
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(
        (f) =>
          f.entity_id.toLowerCase().includes(q) ||
          f.finding_type.toLowerCase().includes(q) ||
          f.description.toLowerCase().includes(q) ||
          f.category.toLowerCase().includes(q)
      );
    }
    return list;
  }, [findings, severityFilter, search]);

  const grouped = useMemo(() => {
    const map = new Map<string, ExtractedFinding[]>();
    for (const f of filtered) {
      const key = groupBy === "type" ? (f.finding_type || "Unknown") : f.entity_id;
      const arr = map.get(key) ?? [];
      arr.push(f);
      map.set(key, arr);
    }
    return [...map.entries()].sort((a, b) => {
      const scoreA = a[1].filter((f) => f.severity === "critical" || f.severity === "high").length;
      const scoreB = b[1].filter((f) => f.severity === "critical" || f.severity === "high").length;
      return scoreB - scoreA;
    });
  }, [filtered, groupBy]);
  const endpointById = useMemo(
    () => new Map((dashData?.endpoints ?? []).map((endpoint) => [endpoint.entity_id, endpoint])),
    [dashData?.endpoints],
  );

  const counts = useMemo(() => {
    const c = { total: findings.length, critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
      if (f.severity === "critical") c.critical++;
      else if (f.severity === "high") c.high++;
      else if (f.severity === "medium") c.medium++;
      else c.low++;
    }
    return c;
  }, [findings]);

  function toggleExpand(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  function handleExport() {
    const headers = ["Entity ID", "Finding Type", "Category", "Severity", "Score", "Description", "Compliance", "Timestamp"];
    const rows = filtered.map((f) => [
      f.entity_id, f.finding_type, f.category, f.severity,
      formatScore(f.severity_score), f.description, f.compliance_control,
      formatTimestamp(f.timestamp_ms),
    ]);
    downloadCsv("guardian_findings.csv", headers, rows);
  }

  if (loading && findings.length === 0) {
    return (
      <div>
        <div className="g-section-label">Findings</div>
        <SkeletonLoader variant="metric" count={4} />
        <div style={{ marginTop: 12 }}><SkeletonLoader variant="table" count={8} /></div>
      </div>
    );
  }

  if (error) {
    return <ErrorBanner message={error} onRetry={() => window.location.reload()} />;
  }

  const expectedFindings = (dashData?.observation_summary.tls_findings_count ?? 0) + (dashData?.observation_summary.waf_findings_count ?? 0);

  if (findings.length === 0 && !loading) {
    if (expectedFindings > 0) {
      return (
        <EmptyState
          message={`Cycle artifacts report ${expectedFindings} findings, but the findings view did not load them yet. Refresh and retry.`}
          action="Retry Findings"
          onAction={() => window.location.reload()}
        />
      );
    }
    return (
      <EmptyState
        message="No findings detected. Your endpoints have a clean posture."
        action="Go to Dashboard"
        onAction={() => navigate("/dashboard")}
      />
    );
  }

  return (
    <div className="g-scroll-page">
      <div className="g-scroll-page__header">
        <div className="g-section-label">Posture Findings</div>

        <div className="g-metric-grid" style={{ gridTemplateColumns: "repeat(5, minmax(100px, 1fr))", marginBottom: 16 }}>
        <MetricCard label="Total" value={counts.total} onClick={() => setSeverityFilter("all")} />
        <MetricCard label="Critical" value={counts.critical} color="var(--color-severity-critical)" onClick={() => setSeverityFilter("critical")} />
        <MetricCard label="High" value={counts.high} color="var(--color-severity-high)" onClick={() => setSeverityFilter("high")} />
        <MetricCard label="Medium" value={counts.medium} color="var(--color-severity-medium)" onClick={() => setSeverityFilter("medium")} />
        <MetricCard label="Low" value={counts.low} color="var(--color-severity-low)" onClick={() => setSeverityFilter("low")} />
      </div>

        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
        <input
          type="text"
          placeholder="Search findings..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{
            flex: 1, maxWidth: 320, padding: "6px 10px",
            background: "var(--panel)", border: "1px solid var(--border)",
            color: "var(--white)", fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)",
          }}
        />
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
        <div style={{ display: "flex", gap: 4 }}>
          <button className={`btn btn-small ${groupBy === "type" ? "btn-primary" : "btn-neutral"}`} onClick={() => setGroupBy("type")}>By Type</button>
          <button className={`btn btn-small ${groupBy === "endpoint" ? "btn-primary" : "btn-neutral"}`} onClick={() => setGroupBy("endpoint")}>By Endpoint</button>
        </div>
        <button className="btn btn-small btn-neutral" onClick={handleExport}>Export CSV</button>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--muted)" }}>
          {filtered.length} finding{filtered.length !== 1 ? "s" : ""}
        </span>
      </div>
      </div>

      <div className="g-scroll-page__body g-scroll-page__body--stack">
        {grouped.map(([groupKey, items]) => {
          const groupCritHigh = items.filter((f) => f.severity === "critical" || f.severity === "high").length;
          return (
            <div key={groupKey} style={{ border: "1px solid var(--border)", marginBottom: 4 }}>
              <div
                style={{ display: "flex", alignItems: "center", gap: 12, padding: "8px 12px", background: "var(--panel)", cursor: "pointer" }}
                onClick={() => toggleExpand(`group-${groupKey}`)}
              >
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)", flex: 1 }}>
                  {groupBy === "endpoint" ? (
                    <span
                      style={{ cursor: "pointer", textDecoration: "underline", textUnderlineOffset: 2 }}
                      onClick={(e) => { e.stopPropagation(); navigate(endpointDetailPath(groupKey)); }}
                    >
                      {groupKey}
                    </span>
                  ) : groupKey}
                </span>
                {groupCritHigh > 0 && (
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--color-severity-critical)" }}>
                    {groupCritHigh} critical/high
                  </span>
                )}
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--muted)" }}>
                  {items.length} finding{items.length !== 1 ? "s" : ""} {expanded.has(`group-${groupKey}`) ? "[-]" : "[+]"}
                </span>
              </div>

              {expanded.has(`group-${groupKey}`) && (
                <div>
                  {items.map((f, idx) => {
                    const fKey = f.record_id || `finding-${idx}`;
                    return (
                      <div key={fKey} style={{ padding: "8px 12px", borderTop: "1px solid var(--border)" }}>
                        {(() => {
                          const endpoint = endpointById.get(f.entity_id);
                          if (!endpoint) return null;
                          return (
                            <div style={{
                              display: "flex",
                              flexWrap: "wrap",
                              gap: 10,
                              marginBottom: 8,
                              fontFamily: "var(--font-mono)",
                              fontSize: "var(--font-size-label)",
                              color: "var(--ghost)",
                            }}>
                              <span>{formatOwnershipLabel(endpoint.ownership_category)}</span>
                              <span>Rel {endpoint.relevance_score.toFixed(2)}</span>
                              <span>{summarizeDiscoverySources(endpoint.discovery_sources, endpoint.discovery_source, 2)}</span>
                            </div>
                          );
                        })()}
                        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                          <SeverityBadge band={f.severity} />
                          <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)", flex: 1 }}>
                            {f.description || f.finding_type || "Finding"}
                          </span>
                          {groupBy !== "endpoint" && f.entity_id && (
                            <span
                              onClick={() => navigate(endpointDetailPath(f.entity_id))}
                              style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", cursor: "pointer", textDecoration: "underline", textUnderlineOffset: 2 }}
                            >
                              {f.entity_id}
                            </span>
                          )}
                          <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)" }}>
                            {formatScore(f.severity_score)}
                          </span>
                        </div>
                        <div style={{ cursor: "pointer", marginTop: 4 }} onClick={() => toggleExpand(fKey)}>
                          {expanded.has(fKey) ? (
                            <div>
                              {f.category && <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", marginBottom: 4 }}>Category: {f.category}</div>}
                              {endpointById.get(f.entity_id)?.relevance_reason && (
                                <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", marginBottom: 4 }}>
                                  Why It Matters: {endpointById.get(f.entity_id)?.relevance_reason}
                                </div>
                              )}
                              {f.compliance_control && <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", marginBottom: 4 }}>Compliance: {f.compliance_control}</div>}
                              {f.evidence && (
                                <div style={{ padding: 8, background: "var(--black)", border: "1px solid var(--border)", marginTop: 4 }}>
                                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.2em" }}>Evidence</div>
                                  <pre style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{f.evidence}</pre>
                                </div>
                              )}
                              {f.timestamp_ms > 0 && <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", marginTop: 4 }}>{formatTimestamp(f.timestamp_ms)}</div>}
                            </div>
                          ) : (
                            <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)" }}>[expand for details]</span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {dashData && (
        <div className="g-scroll-page__footer">
          <ProvenanceBar cycleId={dashData.cycle_id} timestamp={dashData.timestamp_ms} />
        </div>
      )}
    </div>
  );
}
