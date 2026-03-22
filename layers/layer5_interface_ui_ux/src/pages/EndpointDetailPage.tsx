import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useSessionStore } from "../stores/useSessionStore";
import { parseEndpointDTO, type EndpointDTO } from "../stores/useDashboardStore";
import { SeverityBadge } from "../components/display/SeverityBadge";
import { AlertCard, type AlertCardAlert, type AlertCardFinding } from "../components/display/AlertCard";
import { ProvenanceBar } from "../components/display/ProvenanceBar";
import { ErrorBanner } from "../components/feedback/ErrorBanner";
import { SkeletonLoader } from "../components/feedback/SkeletonLoader";
import { GraphViewer } from "../components/GraphViewer";
import { NotesSection } from "../components/NotesSection";
import { TasksSection } from "../components/TasksSection";
import { extractFindings, extractAlerts, extractTrustGraph, type ExtractedFinding, type ExtractedAlert } from "../lib/extractors";
import { formatOwnershipLabel, summarizeDiscoverySources } from "../lib/endpointContext";
import { severityBand, formatScore, formatTimestamp } from "../lib/formatters";
import { dataSource } from "../lib/api";


export function EndpointDetailPage() {
  const { entityId: rawEntityId } = useParams<{ entityId: string }>();
  const entityId = rawEntityId ? decodeURIComponent(rawEntityId) : "";
  const navigate = useNavigate();
  const tenantId = useSessionStore((s) => s.activeTenantId);

  const [extractedAlerts, setExtractedAlerts] = useState<ExtractedAlert[]>([]);
  const [endpoint, setEndpoint] = useState<EndpointDTO | null>(null);
  const [cycleId, setCycleId] = useState("");
  const [endpointLoading, setEndpointLoading] = useState(false);
  const [endpointError, setEndpointError] = useState<string | null>(null);
  const [bundleLoading, setBundleLoading] = useState(false);
  const [bundleError, setBundleError] = useState<string | null>(null);
  const [findings, setFindings] = useState<ExtractedFinding[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [graphSnapshot, setGraphSnapshot] = useState<unknown>(null);

  useEffect(() => {
    if (!tenantId || !entityId) return;
    let cancelled = false;
    setEndpointLoading(true);
    setEndpointError(null);
    dataSource
      .getEndpointDetail(tenantId, entityId)
      .then((payload) => {
        if (cancelled) return;
        const raw = payload && typeof payload === "object" ? (payload as Record<string, unknown>).row : null;
        setEndpoint(raw ? parseEndpointDTO(raw) : null);
        setCycleId(String((payload as Record<string, unknown>)?.cycle_id || "").trim());
      })
      .catch((err) => {
        if (cancelled) return;
        setEndpoint(null);
        setCycleId("");
        setEndpointError(String(err));
      })
      .finally(() => {
        if (!cancelled) setEndpointLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [tenantId, entityId]);

  // Load guardian records from latest cycle bundle
  useEffect(() => {
    if (!tenantId || !cycleId) return;
    setBundleLoading(true);
    setBundleError(null);
    dataSource
      .getCycleBundle(tenantId, cycleId)
      .then((bundle) => {
        setExtractedAlerts(extractAlerts(bundle));
        setGraphSnapshot(extractTrustGraph(bundle));
      })
      .catch((err) => setBundleError(String(err)))
      .finally(() => setBundleLoading(false));
  }, [tenantId, cycleId]);

  // Load posture findings for this endpoint
  useEffect(() => {
    if (!tenantId || !cycleId || !entityId) return;
    setFindingsLoading(true);
    dataSource
      .getAllCycleTelemetry(tenantId, cycleId, { recordType: "posture_findings", pageSize: 1000, maxPages: 20 })
      .then((res) => {
        const all = extractFindings(res);
        setFindings(all.filter((f) => f.entity_id === entityId));
      })
      .catch(() => {})
      .finally(() => setFindingsLoading(false));
  }, [tenantId, cycleId, entityId]);

  if (endpointLoading && !endpoint) return <SkeletonLoader variant="card" count={3} />;
  if (endpointError != null) return <ErrorBanner message={endpointError} />;
  if (!endpoint) {
    return (
      <div className="g-empty">
        Endpoint "{entityId}" not found in current scan data.{" "}
        <button className="btn btn-small btn-neutral" onClick={() => navigate("/endpoints")}>
          Back to Endpoints
        </button>
      </div>
    );
  }

  const band = severityBand(endpoint.guardian_risk);
  const entityAlertRecords = extractedAlerts.filter((r) => r.entity_id === entityId);

  // Build the super card props from endpoint data
  const primaryRecord = entityAlertRecords[0] ?? null;
  const allAlerts: AlertCardAlert[] = entityAlertRecords.flatMap((r) => r.alerts);
  const alertCardFindings = findings.map((f) => ({
    finding_type: f.finding_type,
    description: f.description,
    severity: f.severity,
    severity_score: f.severity_score,
    category: f.category,
    compliance_control: f.compliance_control,
    evidence: f.evidence,
  }));

  function renderSuperCard() {
    if (bundleLoading || primaryRecord == null || endpoint == null) return null;
    return (
      <SuperCard
        primaryRecord={primaryRecord}
        entityId={entityId}
        allAlerts={allAlerts}
        endpoint={endpoint}
        findings={alertCardFindings}
      />
    );
  }

  return (
    <div className="g-scroll-page">
      <div className="g-scroll-page__body g-scroll-page__body--stack">
      {/* ── Identity Header ── */}
      <div style={{ marginBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
          <button className="btn btn-small btn-neutral" onClick={() => navigate("/endpoints")}>Back</button>
          <span
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "var(--font-size-h2)",
              fontWeight: 600,
              color: "var(--pure)",
            }}
          >
            {endpoint.hostname || endpoint.entity_id}
          </span>
          <SeverityBadge band={band} label={`Risk ${formatScore(endpoint.guardian_risk)}`} />
        </div>

        <ProvenanceBar
          cycleId={cycleId}
          firstSeenMs={endpoint.first_seen_ms}
          lastSeenMs={endpoint.last_seen_ms}
        />
      </div>

      {/* ── ALERT SUPER CARD (AVYAKTA-style investigation card) ── */}
      {bundleLoading && <SkeletonLoader variant="card" count={2} />}
      {bundleError != null && <ErrorBanner message={bundleError} />}

      {renderSuperCard()}
      <EndpointContextSection endpoint={endpoint} />

      {/* ── No alerts: show basic endpoint info cards ── */}
      {!primaryRecord && !bundleLoading && (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 1, background: "var(--border)", border: "1px solid var(--border)", marginBottom: 16 }}>
            {[
              { label: "Port", value: String(endpoint.port) },
              { label: "IP Address", value: endpoint.ip || "-" },
              { label: "ASN", value: endpoint.asn || "-" },
              { label: "Confidence", value: formatScore(endpoint.confidence) },
            ].map((item) => (
              <div key={item.label} style={{ background: "var(--panel)", padding: "10px 14px" }}>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.15em", marginBottom: 4 }}>{item.label}</div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)" }}>{item.value}</div>
              </div>
            ))}
          </div>
          <TlsTab endpoint={endpoint} />
          <div style={{ marginTop: 12 }}>
            <TemporalTab endpoint={endpoint} />
          </div>
          {findings.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <FindingsTab findings={findings} loading={findingsLoading} navigate={navigate} />
            </div>
          )}
        </>
      )}

      {/* ── Graph Context (always available below) ── */}
      {graphSnapshot != null && (
        <div style={{ marginTop: 16 }}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.2em", marginBottom: 8 }}>Trust Graph Context</div>
          <GraphContextTab
            graphSnapshot={graphSnapshot}
            loading={bundleLoading}
            entityId={entityId}
          />
        </div>
      )}

      {/* Notes & Tasks */}
      <NotesSection objectType="endpoint" objectId={entityId} />
      <TasksSection objectType="endpoint" objectId={entityId} />
      </div>
    </div>
  );
}


function TlsTab({ endpoint }: { endpoint: EndpointDTO }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 1, background: "var(--border)", border: "1px solid var(--border)" }}>
      {[
        { label: "TLS Version", value: endpoint.tls_version || "-" },
        { label: "Cipher Suite", value: endpoint.cipher || "-" },
        { label: "Cert Issuer", value: endpoint.cert_issuer || "-" },
        { label: "Cert SHA256", value: endpoint.certificate_sha256 || "-" },
        { label: "Cert Expiry", value: endpoint.certificate_expiry_unix_ms ? formatTimestamp(endpoint.certificate_expiry_unix_ms) : "-" },
        { label: "Entropy Score", value: endpoint.entropy_score ? formatScore(endpoint.entropy_score) : "-" },
      ].map((item) => (
        <div key={item.label} style={{ background: "var(--panel)", padding: 12 }}>
          <div className="g-kv-key">{item.label}</div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)", marginTop: 4, wordBreak: "break-all" }}>
            {item.value}
          </div>
        </div>
      ))}
    </div>
  );
}

function TemporalTab({ endpoint }: { endpoint: EndpointDTO }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 1, background: "var(--border)", border: "1px solid var(--border)" }}>
      {[
        { label: "Volatility", value: formatScore(endpoint.volatility_score) },
        { label: "Visibility", value: formatScore(endpoint.visibility_score) },
        { label: "Consecutive Absence", value: String(endpoint.consecutive_absence) },
        { label: "First Seen", value: formatTimestamp(endpoint.first_seen_ms) },
        { label: "Last Seen", value: formatTimestamp(endpoint.last_seen_ms) },
      ].map((item) => (
        <div key={item.label} style={{ background: "var(--panel)", padding: 12 }}>
          <div className="g-kv-key">{item.label}</div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)", marginTop: 4 }}>
            {item.value}
          </div>
        </div>
      ))}
    </div>
  );
}

function FindingsTab({
  findings,
  loading,
  navigate,
}: {
  findings: ExtractedFinding[];
  loading: boolean;
  navigate: ReturnType<typeof useNavigate>;
}) {
  const [expandedIdx, setExpandedIdx] = useState<Set<number>>(new Set());

  if (loading) return <SkeletonLoader variant="card" count={3} />;

  if (findings.length === 0) {
    return <div className="g-empty">No posture findings for this endpoint in the latest cycle.</div>;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
      {findings.map((f, idx) => (
        <div
          key={f.record_id || idx}
          style={{ background: "var(--panel)", border: "1px solid var(--border)", padding: 12 }}
        >
          <div
            style={{ display: "flex", alignItems: "center", gap: 10, cursor: "pointer" }}
            onClick={() => {
              const next = new Set(expandedIdx);
              next.has(idx) ? next.delete(idx) : next.add(idx);
              setExpandedIdx(next);
            }}
          >
            <SeverityBadge band={f.severity} />
            <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)", flex: 1 }}>
              {f.description || f.finding_type || "Finding"}
            </span>
            {f.category && (
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)" }}>
                {f.category}
              </span>
            )}
            <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--muted)" }}>
              {expandedIdx.has(idx) ? "[-]" : "[+]"}
            </span>
          </div>

          {expandedIdx.has(idx) && (
            <div style={{ marginTop: 8 }}>
              {f.compliance_control && (
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", marginBottom: 4 }}>
                  Compliance: {f.compliance_control}
                </div>
              )}
              <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", marginBottom: 4 }}>
                Score: {formatScore(f.severity_score)}
              </div>
              {f.evidence && (
                <div style={{ padding: 8, background: "var(--black)", border: "1px solid var(--border)", marginTop: 4 }}>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.2em" }}>Evidence</div>
                  <pre style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                    {f.evidence}
                  </pre>
                </div>
              )}
              {f.timestamp_ms > 0 && (
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", marginTop: 4 }}>
                  {formatTimestamp(f.timestamp_ms)}
                </div>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function GraphContextTab({
  graphSnapshot,
  loading,
  entityId,
}: {
  graphSnapshot: unknown;
  loading: boolean;
  entityId: string;
}) {
  const navigate = useNavigate();

  if (loading) return <SkeletonLoader variant="card" count={1} />;

  if (!graphSnapshot) {
    return <div className="g-empty">No trust graph data available for this cycle.</div>;
  }

  return (
    <div>
      <div style={{ marginBottom: 8, display: "flex", alignItems: "center", gap: 12 }}>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--muted)" }}>
          Trust graph centered on {entityId}
        </span>
        <button
          className="btn btn-small btn-neutral"
          onClick={() => navigate(`/graph?focus=${encodeURIComponent(entityId)}`)}
        >
          Open Full Graph
        </button>
      </div>
      <GraphViewer
        snapshot={graphSnapshot}
        width={720}
        height={400}
        focusNodeId={`endpoint:${entityId}`}
        compact
      />
    </div>
  );
}

function SuperCard({
  primaryRecord,
  entityId,
  allAlerts,
  endpoint,
  findings,
}: {
  primaryRecord: ExtractedAlert;
  entityId: string;
  allAlerts: AlertCardAlert[];
  endpoint: EndpointDTO;
  findings: AlertCardFinding[];
}) {
  return (
    <AlertCard
      entityId={entityId}
      overallSeverity01={primaryRecord.overall_severity_01}
      overallConfidence01={primaryRecord.overall_confidence_01}
      campaignPhase={primaryRecord.campaign_phase}
      narrative={primaryRecord.narrative}
      advisory={primaryRecord.advisory}
      syncIndex={primaryRecord.sync_index}
      alerts={allAlerts}
      trend={primaryRecord.overall_severity_01 >= 0.7 ? "escalating" : primaryRecord.overall_severity_01 >= 0.4 ? "stable" : "declining"}
      endpoint={{
        hostname: endpoint.hostname,
        port: endpoint.port,
        ip: endpoint.ip,
        asn: endpoint.asn,
        tls_version: endpoint.tls_version,
        cipher: endpoint.cipher,
        cert_issuer: endpoint.cert_issuer,
        certificate_expiry_unix_ms: endpoint.certificate_expiry_unix_ms,
        entropy_score: endpoint.entropy_score,
        volatility_score: endpoint.volatility_score,
        visibility_score: endpoint.visibility_score,
        consecutive_absence: endpoint.consecutive_absence,
        guardian_risk: endpoint.guardian_risk,
        confidence: endpoint.confidence,
        first_seen_ms: endpoint.first_seen_ms,
        last_seen_ms: endpoint.last_seen_ms,
      }}
      findings={findings}
    />
  );
}

function EndpointContextSection({ endpoint }: { endpoint: EndpointDTO }) {
  const discoveryLabel = endpoint.discovery_sources.length > 0
    ? summarizeDiscoverySources(endpoint.discovery_sources, endpoint.discovery_source)
    : endpoint.discovery_source || "-";

  return (
    <div style={{ marginTop: 12, marginBottom: 12 }}>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.2em", marginBottom: 8 }}>
        Endpoint Context
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 1, background: "var(--border)", border: "1px solid var(--border)", marginBottom: 1 }}>
        {[
          { label: "Ownership", value: formatOwnershipLabel(endpoint.ownership_category) },
          { label: "Ownership Confidence", value: formatScore(endpoint.ownership_confidence) },
          { label: "Relevance", value: formatScore(endpoint.relevance_score) },
          { label: "Discovery Paths", value: String(endpoint.discovery_sources.length || (endpoint.discovery_source ? 1 : 0)) },
        ].map((item) => (
          <div key={item.label} style={{ background: "var(--panel)", padding: "10px 14px" }}>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.15em", marginBottom: 4 }}>{item.label}</div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)" }}>{item.value}</div>
          </div>
        ))}
      </div>
      <div style={{ background: "var(--panel)", border: "1px solid var(--border)", padding: 12, display: "flex", flexDirection: "column", gap: 8 }}>
        <div>
          <div className="g-kv-key">Why It Matters</div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", marginTop: 4, lineHeight: 1.6 }}>
            {endpoint.relevance_reason || "No relevance narrative available yet."}
          </div>
        </div>
        <div>
          <div className="g-kv-key">Discovery Provenance</div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)", marginTop: 4 }}>
            {discoveryLabel}
          </div>
        </div>
      </div>
    </div>
  );
}
