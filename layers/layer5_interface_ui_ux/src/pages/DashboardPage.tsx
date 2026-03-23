import { useEffect, useState, useMemo, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useSessionStore } from "../stores/useSessionStore";
import { useDashboardStore } from "../stores/useDashboardStore";
import { MetricCard } from "../components/display/MetricCard";
import { SeverityBadge } from "../components/display/SeverityBadge";
import { EmptyState } from "../components/feedback/EmptyState";
import { SkeletonLoader } from "../components/feedback/SkeletonLoader";
import { ErrorBanner } from "../components/feedback/ErrorBanner";
import { ProvenanceBar } from "../components/display/ProvenanceBar";
import { severityBand, severityColor, formatRelativeTime, formatScore } from "../lib/formatters";
import { formatOwnershipLabel } from "../lib/endpointContext";
import { endpointDetailPath } from "../lib/routes";
import {
  extractFindings,
  analyzeQuantumReadiness,
  RECOMMENDED_PQC_SUITES,
  QUANTUM_COMPLIANCE_FRAMEWORKS,
  type ExtractedFinding,
  type QuantumSummary,
} from "../lib/extractors";
import { dataSource, type ScanStatus } from "../lib/api";

export function DashboardPage() {
  const navigate = useNavigate();
  const tenantId = useSessionStore((s) => s.activeTenantId);
  const { data, loading, error, fetchDashboard } = useDashboardStore();
  const [allFindings, setAllFindings] = useState<ExtractedFinding[]>([]);
  const [findingsLoaded, setFindingsLoaded] = useState(false);
  const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
  const scanPollRef = useRef<number | undefined>(undefined);

  useEffect(() => {
    if (tenantId) {
      fetchDashboard(tenantId);
    }
  }, [tenantId, fetchDashboard]);

  // Poll scan status while running so dashboard shows live discovery progress.
  useEffect(() => {
    if (!tenantId) return;
    let cancelled = false;

    const poll = async () => {
      try {
        const s = await dataSource.getScanStatus(tenantId);
        if (cancelled) return;
        setScanStatus(s);
        if (s?.status === "running") {
          fetchDashboard(tenantId); // refresh metrics while scanning
          scanPollRef.current = window.setTimeout(poll, 5000);
        } else if (s?.status === "completed") {
          fetchDashboard(tenantId);
          setScanStatus(s);
        }
      } catch {
        if (!cancelled) scanPollRef.current = window.setTimeout(poll, 8000);
      }
    };

    void poll();
    return () => {
      cancelled = true;
      if (scanPollRef.current !== undefined) window.clearTimeout(scanPollRef.current);
    };
  }, [tenantId, fetchDashboard]);

  // Load posture findings for quantum analysis
  useEffect(() => {
    if (!tenantId || !data?.cycle_id) return;
    dataSource
      .getAllCycleTelemetry(tenantId, data.cycle_id, { recordType: "posture_findings", pageSize: 1000, maxPages: 20 })
      .then((res) => { setAllFindings(extractFindings(res)); setFindingsLoaded(true); })
      .catch(() => setFindingsLoaded(true));
  }, [tenantId, data?.cycle_id]);

  const quantumSummary: QuantumSummary | null = useMemo(() => {
    if (!data || !findingsLoaded) return null;
    return analyzeQuantumReadiness(data.endpoints, allFindings);
  }, [data, allFindings, findingsLoaded]);

  if (loading && !data) {
    return (
      <div className="g-dashboard-panel">
        <SkeletonLoader variant="metric" count={5} />
        <div style={{ marginTop: 12 }}>
          <SkeletonLoader variant="table" count={5} />
        </div>
      </div>
    );
  }

  if (error) {
    return <ErrorBanner message={error} onRetry={() => tenantId && fetchDashboard(tenantId)} />;
  }

  const isScanning = scanStatus?.status === "running";

  if (!data || data.health_summary.total_endpoints === 0) {
    if (isScanning) {
      // Show the real dashboard shell with zeros — numbers update when scan completes.
      // Fall through to render below with empty data substituted.
    } else {
      return (
        <EmptyState
          message="No scan data yet. Run your first scan to see your risk posture."
          action="Start Onboarding"
          onAction={() => navigate("/onboarding")}
        />
      );
    }
  }

  const EMPTY_DATA = {
    health_summary: { total_endpoints: 0, healthy: 0, at_risk: 0, critical: 0, unobserved: 0 },
    observation_summary: { discovered_related: 0, observation_attempts: 0, observation_successes: 0, observation_failures: 0, recorded_endpoints: 0, unverified_historical: 0, tls_findings_count: 0, waf_findings_count: 0 },
    risk_distribution: { critical: 0, high: 0, medium: 0, low: 0 },
    drift_report: { new_endpoints: 0, removed_endpoints: 0, risk_increased: false },
    endpoints: [] as EndpointDTO[],
  };
  const { health_summary: hs, observation_summary: os, risk_distribution: rd, drift_report: dr, endpoints } = data ?? EMPTY_DATA;
  const ownershipSummary = {
    first_party: endpoints.filter((ep) => ep.ownership_category === "first_party").length,
    adjacent_dependency: endpoints.filter((ep) => ep.ownership_category === "adjacent_dependency").length,
    third_party_dependency: endpoints.filter((ep) => ep.ownership_category === "third_party_dependency").length,
    unknown: endpoints.filter((ep) => !ep.ownership_category || ep.ownership_category === "unknown").length,
  };
  const top10 = [...endpoints]
    .sort((a, b) => (b.relevance_score - a.relevance_score) || (b.guardian_risk - a.guardian_risk))
    .slice(0, 10);

  return (
    <div className="g-dashboard-panel">
      {isScanning && (
        <div style={{
          display: "flex", alignItems: "center", gap: 8, marginBottom: 12,
          padding: "6px 10px",
          background: "rgba(34,197,94,0.06)", border: "1px solid rgba(34,197,94,0.18)",
        }}>
          <span style={{ width: 6, height: 6, borderRadius: "50%", flexShrink: 0,
            background: "var(--color-severity-low)", animation: "pulse 1.4s infinite" }} />
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, letterSpacing: "0.18em",
            textTransform: "uppercase", color: "var(--color-severity-low)" }}>
            Scan running
            {(scanStatus?.expanded_candidate_count ?? 0) > 0 && ` — ${scanStatus!.expanded_candidate_count} endpoints discovered`}
            {(scanStatus?.expansion_current_module) && ` — ${String(scanStatus.expansion_current_module).replace(/Module$/, "")}`}
          </span>
        </div>
      )}
      {/* Discovery Summary */}
      <div className="g-section-label">Discovery Summary</div>

      <div className="g-metric-grid" style={{ gridTemplateColumns: "repeat(6, minmax(120px, 1fr))" }}>
        <MetricCard label="Discovered Related" value={os.discovered_related} />
        <MetricCard label="Observation Attempts" value={os.observation_attempts} />
        <MetricCard
          label="Observation Success"
          value={os.observation_successes}
          color="var(--color-severity-low)"
        />
        <MetricCard
          label="Observation Failed"
          value={os.observation_failures}
          color={os.observation_failures > 0 ? "var(--color-severity-high)" : undefined}
        />
        <MetricCard label="Recorded In Snapshot" value={os.recorded_endpoints} />
        <MetricCard label="Unverified / Historical" value={os.unverified_historical} />
      </div>

      <div className="g-metric-grid" style={{ gridTemplateColumns: "repeat(2, minmax(120px, 1fr))", marginTop: 8 }}>
        <MetricCard
          label="TLS Findings"
          value={os.tls_findings_count}
          color={os.tls_findings_count > 0 ? "var(--color-severity-medium)" : undefined}
          onClick={os.tls_findings_count > 0 ? () => navigate("/findings") : undefined}
        />
        <MetricCard
          label="WAF Findings"
          value={os.waf_findings_count}
          color={os.waf_findings_count > 0 ? "var(--color-severity-medium)" : undefined}
          onClick={os.waf_findings_count > 0 ? () => navigate("/findings") : undefined}
        />
      </div>

      <div
        style={{
          fontFamily: "var(--font-mono)",
          fontSize: "var(--font-size-label)",
          color: "var(--muted)",
          marginTop: 8,
          marginBottom: 16,
        }}
      >
        Guardian now separates the full related discovery surface from the subset that was probed and the smaller subset
        that completed successfully. Third-party, CT-only, and unobserved bank-linked assets remain visible as related
        surface instead of disappearing from the UI.
      </div>

      <div className="g-metric-grid" style={{ gridTemplateColumns: "repeat(4, minmax(120px, 1fr))" }}>
        <MetricCard
          label="Critical"
          value={rd.critical}
          color="var(--color-severity-critical)"
          onClick={() => navigate("/alerts?severity=critical")}
        />
        <MetricCard
          label="High"
          value={rd.high}
          color="var(--color-severity-high)"
          onClick={() => navigate("/alerts?severity=high")}
        />
        <MetricCard
          label="Medium"
          value={rd.medium}
          color="var(--color-severity-medium)"
          onClick={() => navigate("/alerts?severity=medium")}
        />
        <MetricCard
          label="Low"
          value={rd.low}
          color="var(--color-severity-low)"
          onClick={() => navigate("/alerts?severity=low")}
        />
      </div>

      <div className="g-section-label">Asset Relevance</div>

      <div className="g-metric-grid" style={{ gridTemplateColumns: "repeat(4, minmax(120px, 1fr))" }}>
        <MetricCard label="First-Party" value={ownershipSummary.first_party} color="var(--color-severity-low)" />
        <MetricCard label="Adjacent" value={ownershipSummary.adjacent_dependency} color="var(--color-severity-medium)" />
        <MetricCard label="Third-Party" value={ownershipSummary.third_party_dependency} color="var(--color-severity-high)" />
        <MetricCard label="Unknown" value={ownershipSummary.unknown} color="var(--color-severity-unknown)" />
      </div>

      {/* ── Drift Report ── */}
      <div className="g-section-label">Drift Report</div>

      <div className="g-metric-grid" style={{ gridTemplateColumns: "repeat(3, minmax(120px, 1fr))" }}>
        <MetricCard
          label="New Endpoints"
          value={dr.new_endpoints}
          onClick={dr.new_endpoints > 0 ? () => navigate("/endpoints?filter=new") : undefined}
        />
        <MetricCard
          label="Removed"
          value={dr.removed_endpoints}
        />
        <MetricCard
          label="Risk Increased"
          value={dr.risk_increased ? "YES" : "NO"}
          color={dr.risk_increased ? "var(--color-severity-critical)" : "var(--color-severity-low)"}
        />
      </div>

      {/* ── Top Risk Endpoints (compact preview) ── */}
      <div className="g-section-label">Top Risk Endpoints</div>

      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        {top10.slice(0, 5).map((ep) => {
          const band = severityBand(ep.guardian_risk);
          return (
            <div
              key={ep.entity_id}
              onClick={() => navigate(endpointDetailPath(ep.entity_id))}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                padding: "10px 14px",
                background: "var(--panel)",
                border: "1px solid var(--border)",
                borderLeft: `3px solid ${severityColor(band)}`,
                cursor: "pointer",
                transition: "background 0.15s",
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "var(--panel)")}
            >
              <SeverityBadge band={band} label={formatScore(ep.guardian_risk)} />
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)", fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {ep.hostname || ep.entity_id}
              </span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                {formatOwnershipLabel(ep.ownership_category)}
              </span>
              <span style={{ flex: 1 }} />
              {ep.alert_count > 0 && (
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--color-severity-high)", padding: "2px 6px", background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)", borderRadius: 2 }}>
                  {ep.alert_count} alert{ep.alert_count !== 1 ? "s" : ""}
                </span>
              )}
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)" }}>
                {formatRelativeTime(ep.last_seen_ms)}
              </span>
            </div>
          );
        })}

        {top10.length === 0 && (
          <div className="g-empty">No endpoints</div>
        )}
      </div>

      <div style={{ textAlign: "right", padding: "8px 0" }}>
        <button
          className="btn btn-small btn-neutral"
          onClick={() => navigate("/endpoints")}
        >
          View All {endpoints.length} Endpoints →
        </button>
      </div>

      {/* ── Quantum Readiness ── */}
      {quantumSummary != null && (
        <QuantumReadinessSection quantum={quantumSummary} navigate={navigate} />
      )}

      {/* Provenance */}
      <ProvenanceBar
        cycleId={data.cycle_id}
        timestamp={data.timestamp_ms}
      />
    </div>
  );
}

/* ─── Quantum Readiness Section ─── */

const QKV_STYLE = {
  label: { fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", textTransform: "uppercase" as const, letterSpacing: "0.15em", marginBottom: 4 },
  value: { fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)" },
};

function QuantumReadinessSection({
  quantum,
  navigate,
}: {
  quantum: QuantumSummary;
  navigate: ReturnType<typeof import("react-router-dom").useNavigate>;
}) {
  const [expanded, setExpanded] = useState(false);

  const readyPct = quantum.total_endpoints > 0 ? Math.round((quantum.quantum_ready / quantum.total_endpoints) * 100) : 0;
  const statusColor = readyPct >= 80 ? "var(--color-quantum-ready)" : readyPct >= 30 ? "var(--color-quantum-not-ready)" : "var(--color-severity-critical)";

  return (
    <div style={{ marginTop: 8 }}>
      <div className="g-section-label" style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <span>Quantum Readiness</span>
        <span style={{
          fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)",
          padding: "2px 8px", borderRadius: 2,
          background: `${statusColor}18`, color: statusColor, border: `1px solid ${statusColor}44`,
          textTransform: "uppercase", letterSpacing: "0.1em",
        }}>
          {readyPct}% Ready
        </span>
      </div>

      {/* Quantum metrics */}
      <div className="g-metric-grid" style={{ gridTemplateColumns: "repeat(5, minmax(100px, 1fr))" }}>
        <MetricCard
          label="Quantum Ready"
          value={quantum.quantum_ready}
          color="var(--color-quantum-ready)"
        />
        <MetricCard
          label="Not Ready"
          value={quantum.quantum_not_ready}
          color="var(--color-quantum-not-ready)"
          onClick={quantum.quantum_not_ready > 0 ? () => navigate("/findings") : undefined}
        />
        <MetricCard
          label="Unknown"
          value={quantum.quantum_unknown}
          color="var(--color-quantum-unknown)"
        />
        <MetricCard
          label="HNDL Risk"
          value={quantum.hndl_risk_count}
          color={quantum.hndl_risk_count > 0 ? "var(--color-severity-critical)" : "var(--color-severity-low)"}
        />
        <MetricCard
          label="Non-Compliant"
          value={quantum.non_compliant_count}
          color={quantum.non_compliant_count > 0 ? "var(--color-severity-high)" : "var(--color-severity-low)"}
        />
      </div>

      {/* Readiness progress bar */}
      <div style={{ margin: "12px 0", padding: "10px 14px", background: "var(--panel)", border: "1px solid var(--border)" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
          <span style={QKV_STYLE.label}>PQC Migration Progress</span>
          <span style={{ ...QKV_STYLE.value, color: statusColor, fontWeight: 600 }}>{readyPct}%</span>
        </div>
        <div style={{ height: 6, background: "var(--border)", borderRadius: 3, overflow: "hidden" }}>
          <div style={{ width: `${readyPct}%`, height: "100%", borderRadius: 3, background: `linear-gradient(90deg, ${statusColor}, ${statusColor}aa)`, transition: "width 0.5s ease" }} />
        </div>
        <div style={{ display: "flex", justifyContent: "space-between", marginTop: 6 }}>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--ghost)" }}>
            {quantum.quantum_ready} of {quantum.total_endpoints} endpoints migrated
          </span>
          {quantum.hndl_risk_count > 0 && (
            <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--color-severity-critical)" }}>
              {quantum.hndl_risk_count} harvest-now-decrypt-later risk
            </span>
          )}
        </div>
      </div>

      {/* Expand/collapse for details */}
      <button
        className="btn btn-small btn-neutral"
        onClick={() => setExpanded(!expanded)}
        style={{ marginBottom: 8 }}
      >
        {expanded ? "Hide Details" : "View Quantum Details"}
      </button>

      {expanded && (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>

          {/* Vulnerable Endpoints */}
          {quantum.vulnerable_endpoints.length > 0 && (
            <div style={{ background: "var(--panel)", border: "1px solid var(--border)", padding: 14 }}>
              <div style={{ ...QKV_STYLE.label, marginBottom: 10 }}>Vulnerable Endpoints</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {quantum.vulnerable_endpoints.slice(0, 10).map((ep) => (
                  <div
                    key={ep.entity_id}
                    onClick={() => navigate(endpointDetailPath(ep.entity_id))}
                    style={{
                      display: "flex", alignItems: "center", gap: 10,
                      padding: "8px 12px", background: "var(--surface)", border: "1px solid var(--border)",
                      borderLeft: `3px solid ${ep.quantum_status === "not_ready" ? "var(--color-quantum-not-ready)" : "var(--color-quantum-unknown)"}`,
                      cursor: "pointer",
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.background = "var(--dim)")}
                    onMouseLeave={(e) => (e.currentTarget.style.background = "var(--surface)")}
                  >
                    <span style={{
                      fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", padding: "2px 6px",
                      borderRadius: 2, textTransform: "uppercase",
                      background: ep.quantum_status === "not_ready" ? "rgba(255,109,0,0.1)" : "rgba(84,110,122,0.2)",
                      color: ep.quantum_status === "not_ready" ? "var(--color-quantum-not-ready)" : "var(--color-quantum-unknown)",
                      border: `1px solid ${ep.quantum_status === "not_ready" ? "rgba(255,109,0,0.3)" : "rgba(84,110,122,0.3)"}`,
                    }}>
                      {ep.quantum_status === "not_ready" ? "NOT READY" : "UNKNOWN"}
                    </span>
                    <span style={{ ...QKV_STYLE.value, fontWeight: 600, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {ep.hostname || ep.entity_id}
                    </span>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--ghost)" }}>
                      {ep.cipher || "No cipher detected"}
                    </span>
                    {ep.hndl_risk && (
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--color-severity-critical)", padding: "1px 5px", border: "1px solid rgba(238,85,85,0.3)", borderRadius: 2, background: "rgba(238,85,85,0.08)" }}>
                        HNDL
                      </span>
                    )}
                    <SeverityBadge band={severityBand(ep.guardian_risk)} label={formatScore(ep.guardian_risk)} />
                  </div>
                ))}
                {quantum.vulnerable_endpoints.length > 10 && (
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--muted)", padding: "6px 0" }}>
                    +{quantum.vulnerable_endpoints.length - 10} more endpoints
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Recommended Cipher Suites */}
          <div style={{ background: "var(--panel)", border: "1px solid var(--border)", padding: 14 }}>
            <div style={{ ...QKV_STYLE.label, marginBottom: 10 }}>Recommended Post-Quantum Cipher Suites</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {RECOMMENDED_PQC_SUITES.map((suite) => (
                <div key={suite.name} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 12px", background: "var(--surface)", border: "1px solid var(--border)" }}>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--color-quantum-ready)", flex: 1 }}>
                    {suite.name}
                  </span>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--ghost)", padding: "2px 6px", background: "var(--dim)", borderRadius: 2 }}>
                    {suite.standard}
                  </span>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--color-quantum-ready)" }}>
                    {suite.status}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Compliance Frameworks */}
          <div style={{ background: "var(--panel)", border: "1px solid var(--border)", padding: 14 }}>
            <div style={{ ...QKV_STYLE.label, marginBottom: 10 }}>Applicable Quantum Compliance Frameworks</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 4 }}>
              {QUANTUM_COMPLIANCE_FRAMEWORKS.map((fw) => (
                <div key={fw.code} style={{ padding: "8px 12px", background: "var(--surface)", border: "1px solid var(--border)" }}>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)", fontWeight: 600 }}>{fw.code}</div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--ghost)", marginTop: 2 }}>{fw.title}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Migration Actions */}
          {quantum.migration_actions.length > 0 && (
            <div style={{ background: "var(--panel)", border: "1px solid var(--border)", borderLeft: "3px solid var(--color-quantum-not-ready)", padding: 14 }}>
              <div style={{ ...QKV_STYLE.label, marginBottom: 10 }}>Migration Roadmap</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {quantum.migration_actions.map((action, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "start", gap: 8, fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)" }}>
                    <span style={{ color: "var(--color-quantum-not-ready)", fontWeight: 700, flexShrink: 0 }}>{i + 1}.</span>
                    {action}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* What Guardian Can Do */}
          <div style={{ background: "var(--panel)", border: "1px solid var(--border)", borderLeft: "3px solid var(--color-quantum-ready)", padding: 14 }}>
            <div style={{ ...QKV_STYLE.label, marginBottom: 10 }}>How Guardian Helps Your Quantum Transition</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 6, fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)" }}>
              {[
                "Continuous monitoring of all endpoint cipher suites and key exchange algorithms for PQC readiness",
                "Automated detection of HNDL (harvest-now-decrypt-later) risk across your attack surface",
                "Compliance mapping against NIST, CNSA 2.0, G7, and RBI quantum readiness frameworks",
                "Real-time alerts when endpoints fall below quantum readiness thresholds",
                "Cryptographic health scoring with 25-point quantum readiness weight factor",
                "Certificate authority and issuer tracking for PQC migration planning",
                "Trust graph analysis showing quantum risk propagation across connected systems",
              ].map((item, i) => (
                <div key={i} style={{ display: "flex", alignItems: "start", gap: 8 }}>
                  <span style={{ color: "var(--color-quantum-ready)", flexShrink: 0 }}>•</span>
                  {item}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
