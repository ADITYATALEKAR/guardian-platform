import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useSessionStore } from "../stores/useSessionStore";
import { parseEndpointDTO, useDashboardStore, type EndpointDTO } from "../stores/useDashboardStore";
import { GraphViewer } from "../components/GraphViewer";
import { SeverityBadge } from "../components/display/SeverityBadge";
import { ProvenanceBar } from "../components/display/ProvenanceBar";
import { ErrorBanner } from "../components/feedback/ErrorBanner";
import { SkeletonLoader } from "../components/feedback/SkeletonLoader";
import { EmptyState } from "../components/feedback/EmptyState";
import { extractTrustGraph } from "../lib/extractors";
import { dataSource } from "../lib/api";
import { formatOwnershipLabel, summarizeDiscoverySources } from "../lib/endpointContext";
import { severityBand, formatScore } from "../lib/formatters";
import { endpointDetailPath } from "../lib/routes";

export function GraphPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const focusEntity = searchParams.get("focus") || "";
  const tenantId = useSessionStore((s) => s.activeTenantId);
  const { data: dashData, fetchDashboard } = useDashboardStore();

  const [graphSnapshot, setGraphSnapshot] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedEndpoint, setSelectedEndpoint] = useState<EndpointDTO | null>(null);

  useEffect(() => {
    if (tenantId && !dashData) fetchDashboard(tenantId);
  }, [tenantId, dashData, fetchDashboard]);

  useEffect(() => {
    if (!tenantId || !dashData?.cycle_id) return;
    setLoading(true);
    setError(null);
    dataSource
      .getCycleBundle(tenantId, dashData.cycle_id)
      .then((bundle) => setGraphSnapshot(extractTrustGraph(bundle)))
      .catch((err) => setError(String(err)))
      .finally(() => setLoading(false));
  }, [tenantId, dashData?.cycle_id]);

  // When focus entity changes, look it up in endpoints
  useEffect(() => {
    if (focusEntity && dashData) {
      const ep = dashData.endpoints.find((e) => e.entity_id === focusEntity);
      if (ep) {
        setSelectedEndpoint(ep);
        return;
      }
    }
    if (!tenantId || !focusEntity) return;
    dataSource
      .getEndpointDetail(tenantId, focusEntity)
      .then((payload) => {
        const row = payload && typeof payload === "object" ? (payload as Record<string, unknown>).row : null;
        if (row) setSelectedEndpoint(parseEndpointDTO(row));
      })
      .catch(() => {});
  }, [tenantId, focusEntity, dashData]);

  function resolveEndpointFromNodeId(nodeId: string) {
    if (!dashData) return null;
    const normalizedNodeId = nodeId.startsWith("endpoint:") ? nodeId.slice("endpoint:".length) : nodeId;
    return (
      dashData.endpoints.find((endpoint) => endpoint.entity_id === normalizedNodeId) ??
      dashData.endpoints.find((endpoint) =>
        endpoint.hostname ? normalizedNodeId.toUpperCase().includes(endpoint.hostname.toUpperCase()) : false,
      ) ??
      null
    );
  }

  if (loading) {
    return (
      <div>
        <div className="g-section-label">Trust Graph</div>
        <SkeletonLoader variant="card" count={1} />
      </div>
    );
  }

  if (error) {
    return <ErrorBanner message={error} onRetry={() => window.location.reload()} />;
  }

  if (!graphSnapshot) {
    return (
      <EmptyState
        message="No trust graph data. Run a scan to build the graph."
        action="Go to Onboarding"
        onAction={() => navigate("/onboarding")}
      />
    );
  }

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
        <div className="g-section-label" style={{ margin: 0 }}>Trust Graph</div>
        {focusEntity && (
          <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)" }}>
            Focused: {focusEntity}
          </span>
        )}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: selectedEndpoint ? "1fr 280px" : "1fr", gap: 12 }}>
        {/* Graph canvas */}
        <GraphViewer
          snapshot={graphSnapshot}
          width={selectedEndpoint ? 640 : 920}
          height={520}
          focusNodeId={focusEntity ? `endpoint:${focusEntity}` : undefined}
          onNodeSelect={(nodeId) => {
            const ep = resolveEndpointFromNodeId(nodeId);
            if (ep) {
              setSelectedEndpoint(ep);
              return;
            }
            const normalizedNodeId = nodeId.startsWith("endpoint:") ? nodeId.slice("endpoint:".length) : nodeId;
            if (!tenantId || !normalizedNodeId.includes(":")) return;
            dataSource
              .getEndpointDetail(tenantId, normalizedNodeId)
              .then((payload) => {
                const row = payload && typeof payload === "object" ? (payload as Record<string, unknown>).row : null;
                if (row) setSelectedEndpoint(parseEndpointDTO(row));
              })
              .catch(() => {});
          }}
        />

        {/* Side panel - endpoint detail */}
        {selectedEndpoint && (
          <div style={{ border: "1px solid var(--border)", background: "var(--panel)", padding: 12, overflowY: "auto", maxHeight: 520 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.15em" }}>
                Endpoint
              </span>
              <button
                onClick={() => setSelectedEndpoint(null)}
                style={{ background: "none", border: "none", color: "var(--muted)", cursor: "pointer", fontSize: 14 }}
              >
                x
              </button>
            </div>

            <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--pure)", marginBottom: 8, wordBreak: "break-all" }}>
              {selectedEndpoint.entity_id}
            </div>

            <SeverityBadge band={severityBand(selectedEndpoint.guardian_risk)} label={`Risk ${formatScore(selectedEndpoint.guardian_risk)}`} />

            <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 6 }}>
              <SideKV label="Hostname" value={selectedEndpoint.hostname} />
              <SideKV label="Port" value={String(selectedEndpoint.port)} />
              <SideKV label="IP" value={selectedEndpoint.ip || "-"} />
              <SideKV label="Confidence" value={formatScore(selectedEndpoint.confidence)} />
              <SideKV label="Ownership" value={formatOwnershipLabel(selectedEndpoint.ownership_category)} />
              <SideKV label="Relevance" value={formatScore(selectedEndpoint.relevance_score)} />
              <SideKV label="Alerts" value={String(selectedEndpoint.alert_count)} />
              <SideKV label="TLS" value={selectedEndpoint.tls_version || "-"} />
              <SideKV label="Shared Cert Cluster" value={selectedEndpoint.shared_cert_cluster_id || "-"} />
              <SideKV label="LB Cluster" value={selectedEndpoint.lb_cluster_id || "-"} />
              <SideKV label="Identity Cluster" value={selectedEndpoint.identity_cluster_id || "-"} />
              <SideKV label="Discovery" value={summarizeDiscoverySources(selectedEndpoint.discovery_sources, selectedEndpoint.discovery_source)} />
            </div>

            <button
              className="btn btn-small btn-primary"
              style={{ marginTop: 12, width: "100%" }}
              onClick={() => navigate(endpointDetailPath(selectedEndpoint.entity_id))}
            >
              Open Detail
            </button>
          </div>
        )}
      </div>

      {/* Endpoint quick-select: clickable endpoint list below graph */}
      {dashData && dashData.endpoints.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.15em" }}>
            Endpoints ({dashData.endpoints.length})
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
            {dashData.endpoints.slice(0, 50).map((ep) => {
              const band = severityBand(ep.guardian_risk);
              const isSelected = selectedEndpoint?.entity_id === ep.entity_id;
              return (
                <button
                  key={ep.entity_id}
                  onClick={() => setSelectedEndpoint(ep)}
                  className="btn btn-small"
                  style={{
                    borderColor: isSelected ? "var(--pure)" : "var(--border)",
                    background: isSelected ? "var(--surface)" : "transparent",
                    color: `var(--color-severity-${band})`,
                    fontFamily: "var(--font-mono)",
                    fontSize: "var(--font-size-label)",
                    maxWidth: 200,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {ep.entity_id}
                </button>
              );
            })}
            {dashData.endpoints.length > 50 && (
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--muted)", padding: "4px 8px" }}>
                +{dashData.endpoints.length - 50} more
              </span>
            )}
          </div>
        </div>
      )}

      {dashData && <ProvenanceBar cycleId={dashData.cycle_id} timestamp={dashData.timestamp_ms} />}
    </div>
  );
}

function SideKV({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.1em" }}>
        {label}
      </span>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", wordBreak: "break-all" }}>
        {value}
      </div>
    </div>
  );
}
