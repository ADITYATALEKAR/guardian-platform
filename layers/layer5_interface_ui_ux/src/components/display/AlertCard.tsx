import { useState, type ReactElement, type ReactNode } from "react";
import { severityBand, formatScore, formatTimestamp } from "../../lib/formatters";

/* ─── Types ─── */

export interface AlertCardAlert {
  alert_kind: string;
  title: string;
  body: string;
  severity_01: number;
  confidence_01: number;
  pattern_labels: string[];
  evidence_refs: string[];
}

export interface AlertCardFinding {
  finding_type: string;
  description: string;
  severity: string;
  severity_score: number;
  category: string;
  compliance_control: string;
  evidence: string;
}

export interface AlertCardEndpoint {
  hostname: string;
  port: number;
  ip: string;
  asn: string;
  tls_version: string;
  cipher: string;
  cert_issuer: string;
  certificate_expiry_unix_ms: number;
  entropy_score: number;
  volatility_score: number;
  visibility_score: number;
  consecutive_absence: number;
  guardian_risk: number;
  confidence: number;
  first_seen_ms: number;
  last_seen_ms: number;
}

export interface AlertCardProps {
  entityId: string;
  overallSeverity01: number;
  overallConfidence01: number;
  campaignPhase: string;
  narrative: string;
  advisory: string;
  syncIndex: number;
  alerts: AlertCardAlert[];
  trend?: "escalating" | "stable" | "declining";
  onEntityClick?: () => void;
  /** When provided, renders full investigation "super card" mode */
  endpoint?: AlertCardEndpoint;
  findings?: AlertCardFinding[];
  /** Total systems at risk (from dashboard) */
  impactedAssets?: number;
}

/* ─── Severity accent colors (hex for gradients) ─── */
const ACCENT_HEX: Record<string, string> = {
  critical: "#ee5555",
  high: "#ee9933",
  medium: "#eeaa33",
  low: "#66aa66",
};

function accentHex(band: string): string {
  return ACCENT_HEX[band] || "#888888";
}

/* ─── Component ─── */

export function AlertCard({
  entityId,
  overallSeverity01,
  overallConfidence01,
  campaignPhase,
  narrative,
  advisory,
  syncIndex,
  alerts,
  trend = "stable",
  onEntityClick,
  endpoint,
  findings,
  impactedAssets,
}: AlertCardProps): ReactElement {
  const [showDetail, setShowDetail] = useState(false);

  const severity10 = overallSeverity01 * 10;
  const band = severityBand(severity10);
  const accent = accentHex(band);
  const alertCount = alerts.length;
  const criticalAlerts = alerts.filter((a) => severityBand(a.severity_01 * 10) === "critical").length;
  const highAlerts = alerts.filter((a) => severityBand(a.severity_01 * 10) === "high").length;

  const bandLabel = band.toUpperCase();
  const trendLabel = trend.toUpperCase();
  const trendColor = trend === "escalating" ? "#ee5555" : trend === "declining" ? "#66aa66" : "#94a3b8";
  const confPercent = Math.round(overallConfidence01 * 100);

  return (
    <div style={{ fontFamily: "var(--font-mono)" }}>
      {/* ── SUMMARY BAR ── */}
      <div
        style={{
          background: `linear-gradient(135deg, ${accent}18 0%, ${accent}05 50%, #0a0a0acc 100%)`,
          border: `1px solid ${accent}`,
          borderRadius: 4,
          padding: "20px 24px",
          minHeight: 110,
          cursor: "pointer",
        }}
        onClick={() => setShowDetail(!showDetail)}
      >
        {/* 5-column summary grid — matches AVYAKTA layout */}
        <div style={{ display: "grid", gridTemplateColumns: "80px 1fr 120px 130px 120px", gap: 24, alignItems: "start" }}>

          {/* Risk Status */}
          <div style={{ display: "flex", flexDirection: "column", gap: 10, alignItems: "center", textAlign: "center" }}>
            <div style={{ fontSize: 8, fontWeight: 600, color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.15em" }}>Risk Status</div>
            <div style={{ display: "flex", alignItems: "center", gap: 7, padding: "6px 8px", borderRadius: 3, background: `${accent}18` }}>
              <div style={{
                width: 8, height: 8, borderRadius: "50%", backgroundColor: accent,
                boxShadow: `0 0 6px ${accent}, 0 0 12px ${accent}66`,
                animation: "avyakta-pulse 2s infinite",
              }} />
              <div style={{ fontSize: 13, fontWeight: 700, color: accent, textTransform: "uppercase" }}>{bandLabel}</div>
            </div>
          </div>

          {/* Affected System */}
          <div style={{ display: "flex", flexDirection: "column", gap: 10, alignItems: "center", textAlign: "center" }}>
            <div style={{ fontSize: 8, fontWeight: 600, color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.15em" }}>Affected System</div>
            <div
              onClick={(e) => { e.stopPropagation(); onEntityClick?.(); }}
              style={{
                fontSize: 13, fontWeight: 700, color: "#f1f5f9", textTransform: "uppercase",
                cursor: onEntityClick ? "pointer" : "default",
              }}
            >
              {endpoint?.hostname || entityId}
            </div>
            {campaignPhase && (
              <div style={{ fontSize: 9, color: "#64748b", textTransform: "uppercase" }}>{campaignPhase}</div>
            )}
          </div>

          {/* Detection Confidence */}
          <div style={{ display: "flex", flexDirection: "column", gap: 10, alignItems: "center", textAlign: "center" }}>
            <div style={{ fontSize: 8, fontWeight: 600, color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.15em" }}>Detection Confidence</div>
            <div style={{ fontSize: 18, fontWeight: 700, color: "#f1f5f9" }}>{confPercent}%</div>
          </div>

          {/* Risk Trajectory */}
          <div style={{ display: "flex", flexDirection: "column", gap: 10, alignItems: "center", textAlign: "center" }}>
            <div style={{ fontSize: 8, fontWeight: 600, color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.15em" }}>Risk Trajectory</div>
            <div style={{
              fontSize: 13, fontWeight: 700, color: "#f1f5f9", padding: "8px 10px", borderRadius: 3,
              background: `${trendColor}18`, border: `1px solid ${trendColor}`,
              textTransform: "uppercase", display: "flex", alignItems: "center", gap: 6,
            }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={trendColor} strokeWidth="2.5">
                {trend === "escalating" ? (
                  <>
                    <polyline points="23 6 13.5 15.5 8.5 10.5 1 18" />
                    <polyline points="17 6 23 6 23 12" />
                  </>
                ) : trend === "declining" ? (
                  <>
                    <polyline points="23 18 13.5 8.5 8.5 13.5 1 6" />
                    <polyline points="17 18 23 18 23 12" />
                  </>
                ) : (
                  <line x1="1" y1="12" x2="23" y2="12" />
                )}
              </svg>
              {trendLabel}
            </div>
          </div>

          {/* Alerts / Systems at Risk */}
          <div style={{ display: "flex", flexDirection: "column", gap: 10, alignItems: "center", textAlign: "center" }}>
            <div style={{ fontSize: 8, fontWeight: 600, color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.15em" }}>
              {impactedAssets != null ? "Systems at Risk" : "Alerts"}
            </div>
            <div style={{ fontSize: 20, fontWeight: 700, color: "#f1f5f9" }}>
              {impactedAssets ?? alertCount}
            </div>
          </div>
        </div>

        {/* Investigate button bar */}
        <div style={{ marginTop: 16, paddingTop: 16, borderTop: `1px solid ${accent}33`, display: "flex", alignItems: "center", gap: 16 }}>
          <button
            onClick={(e) => { e.stopPropagation(); setShowDetail(!showDetail); }}
            style={{
              padding: "8px 16px", backgroundColor: "transparent", border: `1px solid ${accent}`,
              color: accent, borderRadius: 3, fontSize: 11, fontWeight: 600, cursor: "pointer",
              textTransform: "uppercase", letterSpacing: "0.5px", fontFamily: "var(--font-mono)",
              transition: "background 0.15s",
            }}
            onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = `${accent}33`)}
            onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = "transparent")}
          >
            {showDetail ? "Collapse" : "Investigate"}
          </button>
          {(criticalAlerts > 0 || highAlerts > 0) && (
            <span style={{ fontSize: 10, color: "#94a3b8" }}>
              {criticalAlerts > 0 && <span style={{ color: "#ee5555", fontWeight: 600 }}>{criticalAlerts} critical</span>}
              {criticalAlerts > 0 && highAlerts > 0 && <span> · </span>}
              {highAlerts > 0 && <span style={{ color: "#ee9933", fontWeight: 600 }}>{highAlerts} high</span>}
            </span>
          )}
        </div>
      </div>

      {/* ── DETAIL VIEW ── */}
      {showDetail && (
        <div style={{ marginTop: 6 }}>

          {/* Decision Window */}
          <div style={{
            background: `${accent}15`, border: `1px solid ${accent}66`, borderRadius: 4,
            padding: "16px 20px", marginBottom: 6,
          }}>
            <div style={{ fontSize: 8, textTransform: "uppercase", letterSpacing: "0.2em", fontWeight: 700, color: `${accent}dd`, marginBottom: 10 }}>Decision Window</div>
            <div style={{ fontSize: 11, color: `${accent}cc`, lineHeight: 1.7 }}>
              <div><strong style={{ color: "#f1f5f9" }}>Trend:</strong> {trendLabel} {syncIndex > 0 ? `+${formatScore(syncIndex)}/cycle` : ""}</div>
              {band === "high" || band === "critical" ? (
                <div><strong style={{ color: "#f1f5f9" }}>Escalation:</strong> {band === "high" ? "HIGH → CRITICAL if unaddressed" : "CRITICAL — immediate action required"}</div>
              ) : null}
              {campaignPhase && <div style={{ fontWeight: 700, paddingTop: 8, borderTop: `1px solid ${accent}33`, marginTop: 8, color: accent }}>{campaignPhase}</div>}
            </div>
          </div>

          {/* Observed Signals */}
          {alerts.length > 0 && (
            <DetailSection title="Observed Signals" accent={accent}>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {alerts.map((alert, i) => {
                  const aBand = severityBand(alert.severity_01 * 10);
                  const aAccent = accentHex(aBand);
                  const aConf = Math.round(alert.confidence_01 * 100);
                  return (
                    <div key={i} style={{
                      background: "#00000050", borderRadius: 4, padding: 16,
                      borderLeft: `4px solid ${aAccent}`,
                    }}>
                      <div style={{ display: "flex", alignItems: "start", justifyContent: "space-between", marginBottom: 12 }}>
                        <div>
                          <div style={{ fontSize: 11, fontWeight: 700, color: "#e2e8f0" }}>
                            {i + 1}. {(alert.title || alert.alert_kind || "Signal").toUpperCase()}
                          </div>
                          {alert.body && (
                            <div style={{ fontSize: 11, color: "#94a3b8", marginTop: 4, lineHeight: 1.5 }}>
                              {alert.body}
                            </div>
                          )}
                        </div>
                        <span style={{ color: aBand === "critical" ? "#ef4444" : aBand === "high" ? "#f59e0b" : "#94a3b8", fontSize: 11, fontWeight: 700, textTransform: "uppercase", flexShrink: 0, marginLeft: 12 }}>
                          {aBand.toUpperCase()}
                        </span>
                      </div>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
                        <div style={{ background: "#00000060", borderRadius: 4, padding: 8 }}>
                          <div style={{ fontSize: 9, color: "#94a3b8" }}>Confidence</div>
                          <div style={{ fontSize: 13, fontWeight: 700, color: "#e2e8f0" }}>{aConf}%</div>
                          <div style={{ height: 3, background: "#374151", borderRadius: 2, marginTop: 6, overflow: "hidden" }}>
                            <div style={{ width: `${aConf}%`, backgroundColor: aAccent, height: "100%", borderRadius: 2 }} />
                          </div>
                        </div>
                        <div style={{ background: "#00000060", borderRadius: 4, padding: 8 }}>
                          <div style={{ fontSize: 9, color: "#94a3b8" }}>Severity</div>
                          <div style={{ fontSize: 13, fontWeight: 700, color: "#e2e8f0" }}>{formatScore(alert.severity_01 * 10)}</div>
                        </div>
                        <div style={{ background: "#00000060", borderRadius: 4, padding: 8 }}>
                          <div style={{ fontSize: 9, color: "#94a3b8" }}>Status</div>
                          <div style={{ fontSize: 13, fontWeight: 700, color: aAccent }}>ACTIVE</div>
                        </div>
                      </div>
                      {alert.pattern_labels.length > 0 && (
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 10 }}>
                          {alert.pattern_labels.map((label) => (
                            <span key={label} style={{
                              background: `${aAccent}20`, color: `${aAccent}cc`, fontSize: 9,
                              padding: "2px 8px", borderRadius: 3, border: `1px solid ${aAccent}44`,
                            }}>
                              {label}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </DetailSection>
          )}

          {/* Narrative */}
          {narrative && (
            <DetailSection title="Narrative Assessment" accent={accent}>
              <div style={{
                background: "#00000040", borderRadius: 4, padding: 16,
                borderLeft: `4px solid ${accent}88`,
              }}>
                <div style={{ fontSize: 11, color: "#cbd5e1", whiteSpace: "pre-wrap", lineHeight: 1.7 }}>{narrative}</div>
              </div>
            </DetailSection>
          )}

          {/* Advisory */}
          {advisory && (
            <DetailSection title="Advisory" accent={accent}>
              <div style={{
                background: `${accent}08`, borderRadius: 4, padding: 16,
                borderLeft: `4px solid ${accent}`,
              }}>
                <div style={{ fontSize: 11, color: "#cbd5e1", whiteSpace: "pre-wrap", lineHeight: 1.7 }}>{advisory}</div>
              </div>
            </DetailSection>
          )}

          {/* ── SUPER CARD SECTIONS (when endpoint data provided) ── */}

          {/* Endpoint Identity */}
          {endpoint && (
            <DetailSection title="Endpoint Identity" accent={accent}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 12 }}>
                <InfoBox title="Hostname">
                  <div style={{ fontSize: 12, fontWeight: 700, color: "#e2e8f0", wordBreak: "break-all" }}>{endpoint.hostname || "-"}</div>
                </InfoBox>
                <InfoBox title="IP Address">
                  <div style={{ fontSize: 12, fontWeight: 700, color: "#e2e8f0" }}>{endpoint.ip || "-"}</div>
                </InfoBox>
                <InfoBox title="Port">
                  <div style={{ fontSize: 15, fontWeight: 700, color: "#e2e8f0" }}>{endpoint.port || "-"}</div>
                </InfoBox>
                <InfoBox title="ASN">
                  <div style={{ fontSize: 12, color: "#e2e8f0" }}>{endpoint.asn || "-"}</div>
                </InfoBox>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 12, marginTop: 12 }}>
                <InfoBox title="First Seen">
                  <div style={{ fontSize: 11, color: "#e2e8f0" }}>{endpoint.first_seen_ms ? formatTimestamp(endpoint.first_seen_ms) : "-"}</div>
                </InfoBox>
                <InfoBox title="Last Seen">
                  <div style={{ fontSize: 11, color: "#e2e8f0" }}>{endpoint.last_seen_ms ? formatTimestamp(endpoint.last_seen_ms) : "-"}</div>
                </InfoBox>
                <InfoBox title="Consecutive Absence">
                  <div style={{ fontSize: 15, fontWeight: 700, color: endpoint.consecutive_absence > 0 ? "#f59e0b" : "#e2e8f0" }}>
                    {endpoint.consecutive_absence}
                  </div>
                </InfoBox>
                <InfoBox title="Confidence">
                  <div style={{ fontSize: 15, fontWeight: 700, color: "#e2e8f0" }}>{Math.round(endpoint.confidence * 100)}%</div>
                  <div style={{ height: 3, background: "#374151", borderRadius: 2, marginTop: 6, overflow: "hidden" }}>
                    <div style={{ width: `${endpoint.confidence * 100}%`, backgroundColor: accent, height: "100%", borderRadius: 2 }} />
                  </div>
                </InfoBox>
              </div>
            </DetailSection>
          )}

          {/* Attack Surface Summary */}
          {endpoint && (
            <DetailSection title="Attack Surface Summary" accent={accent}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
                <InfoBox title="TLS Configuration">
                  <KVLine label="Version" value={endpoint.tls_version || "-"} />
                  <KVLine label="Cipher" value={endpoint.cipher || "-"} />
                  <KVLine label="Risk" value={formatScore(endpoint.guardian_risk)} color={accentHex(severityBand(endpoint.guardian_risk))} />
                </InfoBox>
                <InfoBox title="Certificates">
                  <KVLine label="Issuer" value={endpoint.cert_issuer || "-"} />
                  <KVLine label="Expires" value={endpoint.certificate_expiry_unix_ms ? formatTimestamp(endpoint.certificate_expiry_unix_ms) : "-"} />
                </InfoBox>
                <InfoBox title="Entropy & Stability">
                  <KVLine label="Entropy" value={endpoint.entropy_score ? formatScore(endpoint.entropy_score) : "-"} color={endpoint.entropy_score && endpoint.entropy_score < 0.5 ? "#f59e0b" : undefined} />
                  <KVLine label="Volatility" value={formatScore(endpoint.volatility_score)} />
                  <KVLine label="Visibility" value={formatScore(endpoint.visibility_score)} />
                </InfoBox>
              </div>
            </DetailSection>
          )}

          {/* Posture Findings */}
          {findings && findings.length > 0 && (
            <DetailSection title="Posture Findings" accent={accent}>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {findings.map((f, idx) => {
                  const fBand = f.severity || severityBand(f.severity_score);
                  const fAccent = accentHex(fBand);
                  return (
                    <div key={idx} style={{
                      background: "#00000040", borderRadius: 4, padding: 12,
                      borderLeft: `4px solid ${fAccent}`,
                    }}>
                      <div style={{ display: "flex", alignItems: "start", justifyContent: "space-between", marginBottom: 6 }}>
                        <div>
                          <div style={{ fontSize: 11, fontWeight: 700, color: "#e2e8f0" }}>{f.finding_type || f.category}</div>
                          <div style={{ fontSize: 10, color: "#94a3b8", marginTop: 2 }}>{f.description}</div>
                        </div>
                        <span style={{ color: fAccent, fontSize: 10, fontWeight: 700, textTransform: "uppercase", flexShrink: 0, marginLeft: 12 }}>{fBand.toUpperCase()}</span>
                      </div>
                      {f.compliance_control && (
                        <div style={{ fontSize: 9, color: "#64748b", marginTop: 4 }}>Compliance: {f.compliance_control}</div>
                      )}
                      {f.evidence && (
                        <div style={{
                          fontSize: 10, color: "#cbd5e1", background: `${fAccent}10`, borderRadius: 3,
                          padding: "6px 10px", marginTop: 8,
                        }}>
                          {f.evidence}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </DetailSection>
          )}

          {/* Evidence References */}
          {alerts.some((a) => a.evidence_refs.length > 0) && (
            <DetailSection title="Evidence References" accent={accent}>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {alerts.flatMap((a) => a.evidence_refs).filter(Boolean).map((ref, i) => (
                  <div key={i} style={{
                    background: "#00000040", borderRadius: 3, padding: "8px 12px",
                    borderLeft: `2px solid ${accent}66`, fontSize: 11, color: "#cbd5e1",
                  }}>
                    • {ref}
                  </div>
                ))}
              </div>
            </DetailSection>
          )}

          {/* Recommended Actions — only for medium severity and above */}
          {(band === "critical" || band === "high" || band === "medium") && (
            <DetailSection title="Recommended Actions" accent={accent}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
                <ActionBox title="INVESTIGATION" color="#3b82f6" items={[
                  "Review logs for anomalous patterns",
                  "Correlate with other endpoint signals",
                  "Validate detection confidence",
                ]} />
                <ActionBox title="CONTAINMENT" color="#f59e0b" items={[
                  ...(endpoint?.tls_version ? ["Verify TLS configuration"] : []),
                  ...(endpoint?.entropy_score && endpoint.entropy_score < 0.5 ? ["Rotate cryptographic material"] : []),
                  "Apply network segmentation if needed",
                  "Update access controls",
                ]} />
                <ActionBox title="ESCALATION" color="#ef4444" items={[
                  ...(band === "critical" ? ["Activate incident response team"] : []),
                  ...(band === "critical" || band === "high" ? ["Brief security leadership"] : []),
                  "Document findings for audit trail",
                ]} />
              </div>
            </DetailSection>
          )}

          {/* Footer metadata */}
          <div style={{
            display: "flex", justifyContent: "space-between", alignItems: "center",
            fontSize: 10, color: "#64748b", borderTop: "1px solid #374151", padding: "10px 0", marginTop: 4,
          }}>
            <div style={{ display: "flex", gap: 16 }}>
              <span style={{ background: "#ffffff08", padding: "4px 8px", borderRadius: 3 }}>
                Severity: {formatScore(severity10)}
              </span>
              <span style={{ background: "#ffffff08", padding: "4px 8px", borderRadius: 3 }}>
                Confidence: {confPercent}%
              </span>
              {syncIndex > 0 && (
                <span style={{ background: "#ffffff08", padding: "4px 8px", borderRadius: 3 }}>
                  Sync: {formatScore(syncIndex)}
                </span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Pulse animation */}
      <style>{`
        @keyframes avyakta-pulse {
          0%, 100% { opacity: 0.4; }
          50% { opacity: 1; }
        }
      `}</style>
    </div>
  );
}

/* ─── Sub-components ─── */

function DetailSection({ title, accent, children }: { title: string; accent: string; children: ReactNode }) {
  return (
    <div style={{
      background: "linear-gradient(135deg, #1e293b 0%, #1a2332 50%, #1e293b 100%)",
      border: "1px solid #334155", borderRadius: 4, padding: "16px 20px", marginBottom: 6,
    }}>
      <div style={{
        fontSize: 8, textTransform: "uppercase", letterSpacing: "0.2em",
        fontWeight: 700, color: "#e2e8f0", marginBottom: 14,
        fontFamily: "var(--font-mono)",
      }}>
        {title}
      </div>
      {children}
    </div>
  );
}

function InfoBox({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div style={{ background: "#00000040", borderRadius: 4, padding: 12 }}>
      <div style={{ fontSize: 10, fontWeight: 700, color: "#e2e8f0", marginBottom: 8, fontFamily: "var(--font-mono)" }}>{title}</div>
      <div style={{ fontSize: 11, color: "#94a3b8", display: "flex", flexDirection: "column", gap: 4, fontFamily: "var(--font-mono)" }}>
        {children}
      </div>
    </div>
  );
}

function KVLine({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div>
      <strong style={{ fontWeight: 500 }}>{label}:</strong>{" "}
      <span style={{ color: color || undefined }}>{value}</span>
    </div>
  );
}

function ActionBox({ title, color, items }: { title: string; color: string; items: string[] }) {
  return (
    <div style={{
      background: "#00000040", borderRadius: 4, padding: 16,
      borderTop: `2px solid ${color}`,
    }}>
      <div style={{ fontSize: 10, fontWeight: 700, color, marginBottom: 12, fontFamily: "var(--font-mono)" }}>{title}</div>
      <ul style={{ margin: 0, padding: 0, listStyle: "none", fontSize: 11, color: "#94a3b8", display: "flex", flexDirection: "column", gap: 8, fontFamily: "var(--font-mono)" }}>
        {items.filter(Boolean).map((item, i) => (
          <li key={i}>• {item}</li>
        ))}
      </ul>
    </div>
  );
}
