import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useSessionStore } from "../stores/useSessionStore";
import { ErrorBanner } from "../components/feedback/ErrorBanner";
import { SkeletonLoader } from "../components/feedback/SkeletonLoader";
import { EmptyState } from "../components/feedback/EmptyState";
import { ProvenanceBar } from "../components/display/ProvenanceBar";
import { dataSource } from "../lib/api";
import { asObject, asArray, asString, asNumber, formatTimestamp } from "../lib/formatters";
import { cycleDetailPath } from "../lib/routes";

type RecordType = "all" | "fingerprints" | "posture_signals" | "posture_findings";

const RECORD_TYPES: { key: RecordType; label: string }[] = [
  { key: "all", label: "All" },
  { key: "fingerprints", label: "Fingerprints" },
  { key: "posture_signals", label: "Posture Signals" },
  { key: "posture_findings", label: "Posture Findings" },
];

export function TelemetryPage() {
  const { cycleId: rawCycleId } = useParams<{ cycleId: string }>();
  const cycleId = rawCycleId ? decodeURIComponent(rawCycleId) : "";
  const navigate = useNavigate();
  const tenantId = useSessionStore((s) => s.activeTenantId);

  const [records, setRecords] = useState<unknown[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recordType, setRecordType] = useState<RecordType>("all");
  const [page, setPage] = useState(1);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  const pageSize = 100;

  useEffect(() => {
    if (!tenantId || !cycleId) return;
    setLoading(true);
    setError(null);
    setExpanded(new Set());
    dataSource
      .getCycleTelemetry(tenantId, cycleId, { recordType, page, pageSize })
      .then((res) => {
        const obj = asObject(res);
        setRecords(asArray(obj.records ?? res));
        setTotalCount(asNumber(obj.total_count ?? obj.total ?? asArray(obj.records ?? res).length));
      })
      .catch((err) => setError(String(err)))
      .finally(() => setLoading(false));
  }, [tenantId, cycleId, recordType, page]);

  function toggleExpand(idx: number) {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(idx) ? next.delete(idx) : next.add(idx);
      return next;
    });
  }

  const totalPages = Math.max(1, Math.ceil(totalCount / pageSize));

  if (loading && records.length === 0) {
    return (
      <div>
        <div className="g-section-label">Telemetry: {cycleId}</div>
        <SkeletonLoader variant="table" count={10} />
      </div>
    );
  }

  if (error) {
    return <ErrorBanner message={error} onRetry={() => window.location.reload()} />;
  }

  return (
    <div className="g-scroll-page">
      <div className="g-scroll-page__header">
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
        <button className="btn btn-small btn-neutral" onClick={() => navigate(cycleDetailPath(cycleId))}>Back to Cycle</button>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-h3)", fontWeight: 600, color: "var(--pure)" }}>
          Telemetry Records
        </span>
      </div>

        <div style={{ display: "flex", borderBottom: "1px solid var(--border)", marginBottom: 12 }}>
        {RECORD_TYPES.map((rt) => (
          <button
            key={rt.key}
            onClick={() => { setRecordType(rt.key); setPage(1); }}
            style={{
              background: "none", border: "none",
              borderBottom: recordType === rt.key ? "2px solid var(--pure)" : "2px solid transparent",
              padding: "10px 16px",
              fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)",
              letterSpacing: "0.08em", textTransform: "uppercase",
              color: recordType === rt.key ? "var(--pure)" : "var(--muted)",
              cursor: "pointer",
            }}
          >
            {rt.label}
          </button>
        ))}
        <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--muted)", padding: "10px 0" }}>
          {totalCount} record{totalCount !== 1 ? "s" : ""}
        </span>
      </div>
      </div>

      {records.length === 0 && !loading ? (
        <EmptyState message="No telemetry records for this cycle and record type." />
      ) : (
        <>
          <div className="g-scroll-page__body g-scroll-page__body--stack">
            {records.map((raw, idx) => {
              const obj = asObject(raw);
              const isExp = expanded.has(idx);
              const recType = asString(obj.record_type || obj.type) || "-";
              const entityId = asString(obj.entity_id || asObject(obj.payload).entity_id) || "";
              const ts = formatTimestamp(obj.timestamp_ms || obj.created_at_ms);

              // Format record type for display
              const typeLabel = recType.replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase());
              const typeColor = recType.includes("finding") ? "var(--color-severity-high)"
                : recType.includes("signal") ? "var(--color-severity-medium)"
                : "var(--ghost)";

              return (
                <div key={idx} style={{ background: "var(--panel)", border: "1px solid var(--border)", borderRadius: 2 }}>
                  <div
                    style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", cursor: "pointer" }}
                    onClick={() => toggleExpand(idx)}
                  >
                    <span style={{
                      fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)",
                      padding: "2px 8px", background: "var(--surface)", border: "1px solid var(--border)",
                      color: typeColor, borderRadius: 2, textTransform: "uppercase", letterSpacing: "0.05em",
                    }}>
                      {typeLabel}
                    </span>
                    {entityId && (
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--white)", fontWeight: 600 }}>
                        {entityId}
                      </span>
                    )}
                    <span style={{ flex: 1 }} />
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)" }}>
                      {ts}
                    </span>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--muted)" }}>
                      {isExp ? "▾" : "▸"}
                    </span>
                  </div>
                  {isExp && (
                    <div style={{ padding: "0 14px 14px 14px", borderTop: "1px solid var(--border)" }}>
                      {/* Render key fields as structured KV pairs instead of raw JSON */}
                      {(() => {
                        const payload = asObject(obj.payload || obj);
                        // Filter out internal/ID fields
                        const displayKeys = Object.keys(payload).filter((k) =>
                          !["record_id", "id", "record_type", "type", "tenant_id", "cycle_id", "hash", "snapshot_hash"].includes(k)
                        );
                        const simpleKeys = displayKeys.filter((k) => typeof payload[k] !== "object" || payload[k] === null);
                        const complexKeys = displayKeys.filter((k) => typeof payload[k] === "object" && payload[k] !== null);

                        return (
                          <div style={{ marginTop: 8 }}>
                            {simpleKeys.length > 0 && (
                              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 1, background: "var(--border)", border: "1px solid var(--border)", marginBottom: 8, borderRadius: 2 }}>
                                {simpleKeys.slice(0, 12).map((k) => (
                                  <div key={k} style={{ background: "var(--black)", padding: "8px 10px" }}>
                                    <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 2 }}>
                                      {k.replace(/_/g, " ")}
                                    </div>
                                    <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", wordBreak: "break-all" }}>
                                      {String(payload[k] ?? "-")}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            )}
                            {complexKeys.map((k) => (
                              <div key={k} style={{ marginBottom: 6 }}>
                                <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.15em", marginBottom: 4 }}>
                                  {k.replace(/_/g, " ")}
                                </div>
                                <pre style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)", margin: 0, padding: 10, background: "var(--black)", border: "1px solid var(--border)", borderRadius: 2, whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 250, overflow: "auto", lineHeight: 1.5 }}>
                                  {JSON.stringify(payload[k], null, 2)}
                                </pre>
                              </div>
                            ))}
                          </div>
                        );
                      })()}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          <div className="g-scroll-page__footer">
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 12, padding: "12px 0" }}>
              <button className="btn btn-small btn-neutral" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                Prev
              </button>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--muted)" }}>
                Page {page} of {totalPages}
              </span>
              <button className="btn btn-small btn-neutral" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
                Next
              </button>
            </div>
            <ProvenanceBar cycleId={cycleId} />
          </div>
        </>
      )}
    </div>
  );
}
