import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useSessionStore } from "../stores/useSessionStore";
import { ErrorBanner } from "../components/feedback/ErrorBanner";
import { SkeletonLoader } from "../components/feedback/SkeletonLoader";
import { EmptyState } from "../components/feedback/EmptyState";
import { SeverityBadge } from "../components/display/SeverityBadge";
import { GraphViewer } from "../components/GraphViewer";
import { dataSource } from "../lib/api";
import {
  asObject, asArray, asString, asNumber,
  formatTimestamp, formatScore,
  severityBand, downloadJson,
} from "../lib/formatters";
import {
  extractEndpointSnapshot, extractGuardianRecords,
  extractTrustGraph,
} from "../lib/extractors";
import { endpointDetailPath } from "../lib/routes";

type Tab = "overview" | "snapshot" | "guardian" | "graph" | "raw";

const TABS: { key: Tab; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "snapshot", label: "Snapshot" },
  { key: "guardian", label: "Guardian" },
  { key: "graph", label: "Trust Graph" },
  { key: "raw", label: "Raw" },
];

export function SimulationDetailPage() {
  const { simulationId: rawId } = useParams<{ simulationId: string }>();
  const simulationId = rawId ? decodeURIComponent(rawId) : "";
  const navigate = useNavigate();
  const tenantId = useSessionStore((s) => s.activeTenantId);

  const [payload, setPayload] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("overview");
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  useEffect(() => {
    if (!tenantId || !simulationId) return;
    setLoading(true);
    setError(null);
    dataSource
      .getSimulationDetail(tenantId, simulationId)
      .then((res) => setPayload(asObject(res)))
      .catch((err) => setError(String(err)))
      .finally(() => setLoading(false));
  }, [tenantId, simulationId]);

  function toggleExpand(idx: number) {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(idx) ? next.delete(idx) : next.add(idx);
      return next;
    });
  }

  if (loading) {
    return (
      <div>
        <div className="g-section-label">Simulation: {simulationId}</div>
        <SkeletonLoader variant="card" count={3} />
      </div>
    );
  }

  if (error) {
    return <ErrorBanner message={error} onRetry={() => window.location.reload()} />;
  }

  if (!payload) {
    return (
      <EmptyState
        message="Simulation not found or not loaded."
        action="Back to Simulator"
        onAction={() => navigate("/simulator")}
      />
    );
  }

  const meta = asObject(payload.metadata ?? payload);
  const scenarioId = asString(meta.scenario_id || payload.scenario_id);
  const baselineCycleId = asString(meta.baseline_cycle_id || payload.baseline_cycle_id);
  const status = asString(meta.status || payload.status);
  const createdMs = asNumber(meta.created_at_ms || meta.created_at_unix_ms || payload.created_at_ms);
  const description = asString(meta.description || payload.description);

  const snapshotData = extractEndpointSnapshot(payload);
  const guardianRecords = extractGuardianRecords(payload);
  const trustGraph = extractTrustGraph(payload);

  return (
    <div>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
        <button className="btn btn-small btn-neutral" onClick={() => navigate("/simulator")}>Back to Simulator</button>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-h3)", fontWeight: 600, color: "var(--pure)" }}>
          Simulation
        </span>
      </div>

      {/* Metadata bar */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 16, padding: "8px 12px", background: "var(--panel)", border: "1px solid var(--border)", marginBottom: 12 }}>
        <KV label="ID" value={simulationId} />
        <KV label="Scenario" value={scenarioId || "-"} />
        <KV label="Baseline Cycle" value={baselineCycleId || "-"} />
        <KV label="Status" value={status || "-"} />
        <KV label="Created" value={createdMs ? formatTimestamp(createdMs) : "-"} />
        <KV label="Endpoints" value={String(snapshotData.length)} />
        <KV label="Guardian Records" value={String(guardianRecords.length)} />
        <button
          className="btn btn-small btn-neutral"
          style={{ marginLeft: "auto" }}
          onClick={() => downloadJson(`simulation-${simulationId}.json`, payload)}
        >
          Download
        </button>
      </div>

      {description && (
        <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", padding: "8px 12px", background: "var(--black)", border: "1px solid var(--border)", marginBottom: 12 }}>
          {description}
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: "flex", borderBottom: "1px solid var(--border)", marginBottom: 12 }}>
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => { setTab(t.key); setExpanded(new Set()); }}
            style={{
              background: "none", border: "none",
              borderBottom: tab === t.key ? "2px solid var(--pure)" : "2px solid transparent",
              padding: "10px 16px",
              fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)",
              letterSpacing: "0.08em", textTransform: "uppercase",
              color: tab === t.key ? "var(--pure)" : "var(--muted)",
              cursor: "pointer",
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === "overview" && <OverviewTab payload={payload} snapshotCount={snapshotData.length} guardianCount={guardianRecords.length} />}
      {tab === "snapshot" && <SnapshotTab endpoints={snapshotData} navigate={navigate} />}
      {tab === "guardian" && <GuardianTab records={guardianRecords} expanded={expanded} toggleExpand={toggleExpand} navigate={navigate} />}
      {tab === "graph" && <GraphTab snapshot={trustGraph} />}
      {tab === "raw" && <RawTab payload={payload} />}
    </div>
  );
}

function OverviewTab({ payload, snapshotCount, guardianCount }: { payload: Record<string, unknown>; snapshotCount: number; guardianCount: number }) {
  const keys = Object.keys(payload);
  return (
    <div>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.2em", marginBottom: 8 }}>
        Simulation Contents
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        {keys.map((key) => {
          const val = payload[key];
          const count = Array.isArray(val) ? val.length : val && typeof val === "object" ? Object.keys(val as object).length : 1;
          return (
            <div key={key} style={{ display: "flex", gap: 12, padding: "4px 12px", background: "var(--panel)", border: "1px solid var(--border)" }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)", flex: 1 }}>{key}</span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--muted)" }}>
                {Array.isArray(val) ? `${count} items` : typeof val === "object" && val ? `${count} keys` : typeof val}
              </span>
            </div>
          );
        })}
      </div>
      <div style={{ marginTop: 12, display: "flex", gap: 16 }}>
        <KV label="Endpoint Snapshot" value={String(snapshotCount)} />
        <KV label="Guardian Records" value={String(guardianCount)} />
      </div>
    </div>
  );
}

function SnapshotTab({ endpoints, navigate }: { endpoints: Record<string, unknown>[]; navigate: ReturnType<typeof useNavigate> }) {
  if (endpoints.length === 0) {
    return <EmptyState message="No endpoint snapshot data in this simulation." />;
  }
  return (
    <div style={{ border: "1px solid var(--border)" }}>
      <div style={{
        display: "grid", gridTemplateColumns: "2fr 1fr 60px 80px 80px 70px",
        gap: 8, padding: "8px 12px", background: "var(--panel)",
        borderBottom: "1px solid var(--border)",
        fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)",
        letterSpacing: "0.2em", textTransform: "uppercase", color: "var(--muted)",
      }}>
        <span>Entity</span><span>Hostname</span><span>Port</span><span>Risk</span><span>Confidence</span><span>Alerts</span>
      </div>
      {endpoints.slice(0, 200).map((ep, idx) => {
        const entityId = asString(ep.entity_id);
        const risk = asNumber(ep.guardian_risk);
        const band = severityBand(risk);
        return (
          <div
            key={idx}
            onClick={() => entityId && navigate(endpointDetailPath(entityId))}
            style={{
              display: "grid", gridTemplateColumns: "2fr 1fr 60px 80px 80px 70px",
              gap: 8, padding: "8px 12px", borderBottom: "1px solid var(--border)",
              cursor: entityId ? "pointer" : "default", transition: "background 0.1s",
              fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)",
            }}
            onMouseEnter={(e) => entityId && (e.currentTarget.style.background = "var(--surface)")}
            onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
          >
            <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{entityId || "-"}</span>
            <span style={{ color: "var(--ghost)" }}>{asString(ep.hostname) || "-"}</span>
            <span style={{ color: "var(--ghost)" }}>{asNumber(ep.port) || "-"}</span>
            <span><SeverityBadge band={band} label={formatScore(risk)} /></span>
            <span style={{ color: "var(--ghost)" }}>{formatScore(asNumber(ep.confidence))}</span>
            <span>{asNumber(ep.alert_count) || "0"}</span>
          </div>
        );
      })}
      {endpoints.length > 200 && (
        <div style={{ padding: "8px 12px", fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--muted)" }}>
          Showing 200 of {endpoints.length}
        </div>
      )}
    </div>
  );
}

function GuardianTab({ records, expanded, toggleExpand, navigate }: {
  records: Record<string, unknown>[];
  expanded: Set<number>;
  toggleExpand: (idx: number) => void;
  navigate: ReturnType<typeof useNavigate>;
}) {
  if (records.length === 0) {
    return <EmptyState message="No guardian records in this simulation." />;
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
      {records.map((rec, idx) => {
        const entityId = asString(rec.entity_id);
        const isExp = expanded.has(idx);
        return (
          <div key={idx} style={{ background: "var(--panel)", border: "1px solid var(--border)" }}>
            <div
              style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 12px", cursor: "pointer" }}
              onClick={() => toggleExpand(idx)}
            >
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", width: 30 }}>{idx + 1}</span>
              <span
                onClick={(e) => { e.stopPropagation(); if (entityId) navigate(endpointDetailPath(entityId)); }}
                style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", cursor: entityId ? "pointer" : "default", textDecoration: entityId ? "underline" : "none", textUnderlineOffset: 2, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
              >
                {entityId || "-"}
              </span>
              <SeverityBadge band={severityBand(asNumber(rec.overall_severity_01) * 10)} label={formatScore(asNumber(rec.overall_severity_01) * 10)} />
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--muted)" }}>{isExp ? "[-]" : "[+]"}</span>
            </div>
            {isExp && (
              <div style={{ padding: "0 12px 12px 12px", borderTop: "1px solid var(--border)" }}>
                <pre style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 400, overflow: "auto" }}>
                  {JSON.stringify(rec, null, 2)}
                </pre>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function GraphTab({ snapshot }: { snapshot: unknown }) {
  if (!snapshot) {
    return <EmptyState message="No trust graph data in this simulation." />;
  }
  return <GraphViewer snapshot={snapshot} width={920} height={520} />;
}

function RawTab({ payload }: { payload: Record<string, unknown> }) {
  return (
    <div style={{ background: "var(--black)", border: "1px solid var(--border)", padding: 12 }}>
      <pre style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 600, overflow: "auto" }}>
        {JSON.stringify(payload, null, 2)}
      </pre>
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
