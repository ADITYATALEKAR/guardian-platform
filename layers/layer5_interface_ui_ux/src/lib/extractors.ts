import { asObject, asArray, asString, asNumber, severityBand } from "./formatters";

// ─── Alert extraction (from guardian_records in cycle bundle) ───

export interface ExtractedAlert {
  entity_id: string;
  overall_severity_01: number;
  overall_confidence_01: number;
  campaign_phase: string;
  sync_index: number;
  narrative: string;
  advisory: string;
  alerts: AlertItem[];
}

export interface AlertItem {
  alert_kind: string;
  title: string;
  body: string;
  severity_01: number;
  confidence_01: number;
  pattern_labels: string[];
  evidence_refs: string[];
}

function deriveEntityId(raw: Record<string, unknown>): string {
  const explicit = asString(raw.entity_id);
  if (explicit) return explicit;
  const hostname = asString(raw.hostname || raw.host || raw.ip);
  const port = asNumber(raw.port);
  if (!hostname || !port) return "";
  return `${hostname}:${port}`;
}

function normalizeAlert(raw: unknown): AlertItem {
  const ao = asObject(raw);
  return {
    alert_kind: asString(ao.alert_kind),
    title: asString(ao.title),
    body: asString(ao.body),
    severity_01: asNumber(ao.severity_01 ?? ao.severity),
    confidence_01: asNumber(ao.confidence_01 ?? ao.confidence),
    pattern_labels: asArray(ao.pattern_labels).map((l) => asString(l)).filter(Boolean),
    evidence_refs: asArray(ao.evidence_refs)
      .map((r) => {
        if (typeof r === "string") return r;
        const obj = asObject(r);
        const kind = asString(obj.kind);
        const hash = asString(obj.hash);
        return [kind, hash].filter(Boolean).join(":");
      })
      .filter(Boolean),
  };
}

function normalizeGuardianRecord(raw: unknown): Record<string, unknown> {
  const obj = asObject(raw);
  return {
    ...obj,
    entity_id: deriveEntityId(obj),
    overall_severity_01: asNumber(obj.overall_severity_01 ?? obj.severity),
    overall_confidence_01: asNumber(obj.overall_confidence_01 ?? obj.confidence),
    alerts: asArray(obj.alerts).map((a) => normalizeAlert(a)),
    pattern_labels: asArray(obj.pattern_labels).map((l) => asString(l)).filter(Boolean),
  };
}

function temporalEntryTimes(raw: Record<string, unknown>): { first_seen_ms: number; last_seen_ms: number } {
  const explicitFirst = asNumber(raw.first_seen_ms);
  const explicitLast = asNumber(raw.last_seen_ms);
  if (explicitFirst || explicitLast) {
    return { first_seen_ms: explicitFirst, last_seen_ms: explicitLast };
  }

  const history = asArray(raw.presence_history)
    .map(asObject)
    .map((entry) => asNumber(entry.timestamp_unix_ms))
    .filter((value) => value > 0);
  if (history.length === 0) {
    return { first_seen_ms: 0, last_seen_ms: 0 };
  }
  return {
    first_seen_ms: history[0],
    last_seen_ms: history[history.length - 1],
  };
}

export function extractAlerts(bundle: Record<string, unknown>): ExtractedAlert[] {
  const records = asArray(bundle.guardian_records).map((raw) => normalizeGuardianRecord(raw));
  const result: ExtractedAlert[] = [];

  for (const raw of records) {
    const obj = asObject(raw);
    const entityId = asString(obj.entity_id);
    if (!entityId) continue;

    const alertList = asArray(obj.alerts);
    const items: AlertItem[] = alertList.map((a) => normalizeAlert(a));

    result.push({
      entity_id: entityId,
      overall_severity_01: asNumber(obj.overall_severity_01 ?? obj.severity),
      overall_confidence_01: asNumber(obj.overall_confidence_01 ?? obj.confidence),
      campaign_phase: asString(obj.campaign_phase),
      sync_index: asNumber(obj.sync_index),
      narrative: typeof obj.narrative === "string" ? obj.narrative : obj.narrative != null ? JSON.stringify(obj.narrative) : "",
      advisory: typeof obj.advisory === "string" ? obj.advisory : obj.advisory != null ? JSON.stringify(obj.advisory) : "",
      alerts: items,
    });
  }

  return result.filter((record) => record.overall_severity_01 > 0 || record.alerts.length > 0);
}

export function flattenAlerts(records: ExtractedAlert[]): FlatAlert[] {
  const flat: FlatAlert[] = [];
  for (const rec of records) {
    for (const alert of rec.alerts) {
      flat.push({
        entity_id: rec.entity_id,
        campaign_phase: rec.campaign_phase,
        narrative: rec.narrative,
        advisory: rec.advisory,
        overall_severity_01: rec.overall_severity_01,
        overall_confidence_01: rec.overall_confidence_01,
        sync_index: rec.sync_index,
        ...alert,
      });
    }
    // If no individual alerts but record exists, include as a single entry
    if (rec.alerts.length === 0) {
      flat.push({
        entity_id: rec.entity_id,
        campaign_phase: rec.campaign_phase,
        narrative: rec.narrative,
        advisory: rec.advisory,
        overall_severity_01: rec.overall_severity_01,
        overall_confidence_01: rec.overall_confidence_01,
        sync_index: rec.sync_index,
        alert_kind: "",
        title: "Guardian record (no individual alerts)",
        body: "",
        severity_01: rec.overall_severity_01,
        confidence_01: rec.overall_confidence_01,
        pattern_labels: [],
        evidence_refs: [],
      });
    }
  }
  return flat;
}

export interface FlatAlert extends AlertItem {
  entity_id: string;
  campaign_phase: string;
  narrative: string;
  advisory: string;
  overall_severity_01: number;
  overall_confidence_01: number;
  sync_index: number;
}

// ─── Finding extraction (from telemetry posture_findings) ───

export interface ExtractedFinding {
  record_id: string;
  entity_id: string;
  finding_type: string;
  category: string;
  severity: string;
  severity_score: number;
  description: string;
  compliance_control: string;
  evidence: string;
  timestamp_ms: number;
}

function findingSeverityScore(raw: Record<string, unknown>): number {
  const explicit = asNumber(raw.severity_score ?? raw.risk_score ?? raw.severity_01);
  if (explicit > 0) {
    return explicit > 1 ? explicit / 10 : explicit;
  }
  const severity = asString(raw.severity).trim().toUpperCase();
  if (severity === "CRITICAL") return 0.9;
  if (severity === "HIGH") return 0.7;
  if (severity === "MEDIUM") return 0.5;
  if (severity === "LOW") return 0.2;
  return 0;
}

export function extractFindings(telemetryResponse: Record<string, unknown>): ExtractedFinding[] {
  const records = asArray(telemetryResponse.rows ?? telemetryResponse.records);
  const result: ExtractedFinding[] = [];

  for (const [rowIndex, raw] of records.entries()) {
    const obj = asObject(raw);
    const entityId = asString(obj.entity_id);
    const timestampMs = asNumber(obj.timestamp_ms || obj.created_at_ms);
    const postureFindings = asObject(obj.posture_findings);

    const nestedGroups: Array<[string, unknown[]]> = [
      ["TLS", asArray(postureFindings.tls_findings)],
      ["WAF", asArray(postureFindings.waf_findings)],
    ];

    for (const [category, findings] of nestedGroups) {
      for (const [findingIndex, item] of findings.entries()) {
        const payload = asObject(item);
        const severityScore = findingSeverityScore(payload);
        const controls = asArray(payload.compliance_controls).map(asString).filter(Boolean);
        result.push({
          record_id:
            asString(payload.finding_id || payload.id) ||
            `${entityId || "unknown"}:${category}:${rowIndex}:${findingIndex}`,
          entity_id: asString(payload.endpoint_id || payload.entity_id || entityId),
          finding_type: asString(payload.finding_id || payload.finding_type || payload.type),
          category,
          severity: severityBand(severityScore),
          severity_score: severityScore,
          description: asString(payload.description || payload.summary || payload.title || ""),
          compliance_control: controls.join(", "),
          evidence:
            typeof payload.evidence === "string"
              ? payload.evidence
              : payload.evidence != null
                ? JSON.stringify(payload.evidence)
                : "",
          timestamp_ms: asNumber(payload.timestamp_ms || timestampMs),
        });
      }
    }
  }

  return result;
}

// ─── Quantum readiness analysis (derived from endpoints + findings) ───

const PQC_ALGORITHMS = ["KYBER", "MLKEM", "ML-KEM", "DILITHIUM", "ML-DSA", "SPHINCS"];
const LEGACY_ALGORITHMS = ["RSA", "ECDSA", "ED25519", "ED448"];

/** NIST / government recommended post-quantum cipher suites */
export const RECOMMENDED_PQC_SUITES = [
  { name: "TLS_AES_256_GCM_SHA384 + X25519MLKEM768", standard: "NIST FIPS 203", status: "Standardised" },
  { name: "TLS_AES_128_GCM_SHA256 + X25519Kyber768", standard: "NIST SP 800-227", status: "Recommended" },
  { name: "TLS_CHACHA20_POLY1305_SHA256 + ML-KEM-768", standard: "CNSA 2.0", status: "Approved" },
] as const;

export const QUANTUM_COMPLIANCE_FRAMEWORKS = [
  { code: "NIST IR 8413", title: "Status Report on Post-Quantum Cryptography" },
  { code: "CNSA 2.0", title: "NSA Commercial National Security Algorithm Suite 2.0" },
  { code: "G7 Quantum Readiness", title: "G7 Fundamental Elements for Quantum Readiness" },
  { code: "RBI Advisory", title: "RBI Quantum Risk Advisory for Financial Institutions" },
  { code: "NIST FIPS 203", title: "Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)" },
] as const;

export type QuantumStatus = "ready" | "not_ready" | "unknown";

export interface QuantumEndpointAnalysis {
  entity_id: string;
  hostname: string;
  cipher: string;
  tls_version: string;
  quantum_status: QuantumStatus;
  has_pqc_algorithm: boolean;
  has_legacy_only: boolean;
  quantum_findings: ExtractedFinding[];
  hndl_risk: boolean;
  guardian_risk: number;
}

export interface QuantumSummary {
  total_endpoints: number;
  quantum_ready: number;
  quantum_not_ready: number;
  quantum_unknown: number;
  hndl_risk_count: number;
  non_compliant_count: number;
  vulnerable_endpoints: QuantumEndpointAnalysis[];
  migration_actions: string[];
}

function classifyQuantumStatus(cipher: string, tlsVersion: string): QuantumStatus {
  const combined = `${cipher} ${tlsVersion}`.toUpperCase();
  if (PQC_ALGORITHMS.some((alg) => combined.includes(alg))) return "ready";
  if (LEGACY_ALGORITHMS.some((alg) => combined.includes(alg))) return "not_ready";
  if (cipher || tlsVersion) return "not_ready"; // has crypto but no PQC
  return "unknown";
}

function isHndlRisk(quantumStatus: QuantumStatus, findings: ExtractedFinding[]): boolean {
  if (quantumStatus === "ready") return false;
  return findings.some((f) =>
    f.finding_type.includes("QUANTUM-009") || f.finding_type.includes("hndl")
  );
}

export function analyzeQuantumReadiness(
  endpoints: Array<{ entity_id: string; hostname: string; cipher: string; tls_version: string; guardian_risk: number }>,
  allFindings: ExtractedFinding[],
): QuantumSummary {
  const analyses: QuantumEndpointAnalysis[] = [];

  for (const ep of endpoints) {
    const cipher = ep.cipher || "";
    const tlsVersion = ep.tls_version || "";
    const combined = `${cipher} ${tlsVersion}`.toUpperCase();
    const quantumStatus = classifyQuantumStatus(cipher, tlsVersion);
    const epFindings = allFindings.filter(
      (f) => f.entity_id === ep.entity_id && (f.finding_type.includes("QUANTUM") || f.category === "TLS"),
    );
    const quantumFindings = epFindings.filter((f) => f.finding_type.includes("QUANTUM"));

    analyses.push({
      entity_id: ep.entity_id,
      hostname: ep.hostname,
      cipher,
      tls_version: tlsVersion,
      quantum_status: quantumStatus,
      has_pqc_algorithm: PQC_ALGORITHMS.some((alg) => combined.includes(alg)),
      has_legacy_only: LEGACY_ALGORITHMS.some((alg) => combined.includes(alg)) && !PQC_ALGORITHMS.some((alg) => combined.includes(alg)),
      quantum_findings: quantumFindings,
      hndl_risk: isHndlRisk(quantumStatus, epFindings),
      guardian_risk: ep.guardian_risk,
    });
  }

  const ready = analyses.filter((a) => a.quantum_status === "ready").length;
  const notReady = analyses.filter((a) => a.quantum_status === "not_ready").length;
  const unknown = analyses.filter((a) => a.quantum_status === "unknown").length;
  const hndlCount = analyses.filter((a) => a.hndl_risk).length;
  const nonCompliant = analyses.filter((a) => a.quantum_findings.length > 0).length;
  const vulnerable = analyses
    .filter((a) => a.quantum_status !== "ready")
    .sort((a, b) => b.guardian_risk - a.guardian_risk);

  const actions: string[] = [];
  if (notReady > 0) actions.push(`${notReady} endpoint${notReady > 1 ? "s" : ""} require PQC migration planning`);
  if (hndlCount > 0) actions.push(`${hndlCount} endpoint${hndlCount > 1 ? "s" : ""} at risk of harvest-now-decrypt-later attacks`);
  if (notReady > 0) actions.push("Evaluate hybrid TLS configurations (e.g. X25519+ML-KEM-768) for critical endpoints");
  if (notReady > 0) actions.push("Engage certificate authority for PQC-capable certificate issuance roadmap");
  if (analyses.length > 0 && ready === 0) actions.push("No endpoints are quantum-ready — initiate PQC readiness assessment");

  return {
    total_endpoints: analyses.length,
    quantum_ready: ready,
    quantum_not_ready: notReady,
    quantum_unknown: unknown,
    hndl_risk_count: hndlCount,
    non_compliant_count: nonCompliant,
    vulnerable_endpoints: vulnerable,
    migration_actions: actions,
  };
}

// ─── Cycle extraction (from bundle cycle_metadata) ───

export interface ExtractedCycle {
  cycle_id: string;
  cycle_number: number;
  timestamp_ms: number;
  duration_ms: number;
  endpoint_count: number;
  new_endpoints: number;
  removed_endpoints: number;
  status: string;
  snapshot_hash: string;
}

export function extractCycleList(bundle: Record<string, unknown>): ExtractedCycle[] {
  const metaRaw = bundle.rows ?? bundle.cycle_metadata;
  const entries = Array.isArray(metaRaw) ? metaRaw : metaRaw ? [metaRaw] : [];
  const result: ExtractedCycle[] = [];

  for (const raw of entries) {
    const obj = asObject(raw);
    result.push({
      cycle_id: asString(obj.cycle_id || obj.id),
      cycle_number: asNumber(obj.cycle_number || obj.sequence),
      timestamp_ms: asNumber(obj.timestamp_ms || obj.timestamp_unix_ms || obj.started_at_ms || obj.created_at_ms),
      duration_ms: asNumber(obj.duration_ms || obj.execution_time_ms),
      endpoint_count: asNumber(obj.endpoint_count || obj.endpoints_scanned || obj.total_endpoints),
      new_endpoints: asNumber(obj.new_endpoints || obj.discovered),
      removed_endpoints: asNumber(obj.removed_endpoints || obj.removed),
      status: asString(obj.status || "completed"),
      snapshot_hash: asString(obj.snapshot_hash || obj.hash),
    });
  }

  // Sort by timestamp descending (most recent first)
  result.sort((a, b) => b.timestamp_ms - a.timestamp_ms);
  return result;
}

// ─── Bundle section helpers ───

export function extractEndpointSnapshot(bundle: Record<string, unknown>): Record<string, unknown>[] {
  const snapshot = asObject(bundle.snapshot);
  const rawEndpoints = asArray(snapshot.endpoints || bundle.endpoint_snapshot || bundle.endpoints || bundle.snapshot).map(asObject);
  const guardianMap = new Map(
    asArray(bundle.guardian_records)
      .map((raw) => normalizeGuardianRecord(raw))
      .map((record) => [asString(record.entity_id), record]),
  );
  const temporalState = asObject(bundle.temporal_state || bundle.temporal_state_snapshot);
  const temporalMap = asObject(temporalState.endpoints);

  return rawEndpoints.map((endpoint) => {
    const entity_id = deriveEntityId(endpoint);
    const guardian = asObject(guardianMap.get(entity_id));
    const temporal = asObject(temporalMap[entity_id]);
    const times = temporalEntryTimes(temporal);
    const discoveredBy = asArray(endpoint.discovered_by ?? endpoint.discovery_source).map(asString).filter(Boolean);
    return {
      ...endpoint,
      entity_id,
      guardian_risk: asNumber(guardian.overall_severity_01 ?? guardian.severity),
      confidence: asNumber(guardian.overall_confidence_01 ?? guardian.confidence ?? endpoint.confidence),
      alert_count: asArray(guardian.alerts).length,
      volatility_score: asNumber(temporal.volatility_score),
      visibility_score: asNumber(temporal.visibility_score),
      consecutive_absence: asNumber(temporal.consecutive_absence),
      first_seen_ms: times.first_seen_ms,
      last_seen_ms: times.last_seen_ms,
      discovery_source: discoveredBy.join(", "),
    };
  });
}

export function extractTemporalState(bundle: Record<string, unknown>): Record<string, unknown>[] {
  const rawTemporal = bundle.temporal_state || bundle.temporal_state_snapshot;
  if (Array.isArray(rawTemporal)) {
    return rawTemporal.map(asObject);
  }
  const temporal = asObject(rawTemporal);
  const mappedEndpoints = asObject(temporal.endpoints);
  const rows = Object.entries(mappedEndpoints).map(([entityId, raw]) => {
    const entry = asObject(raw);
    const times = temporalEntryTimes(entry);
    return {
      ...entry,
      entity_id: asString(entry.endpoint_id) || entityId,
      first_seen_ms: times.first_seen_ms,
      last_seen_ms: times.last_seen_ms,
    };
  });
  return rows;
}

export function extractTrustGraph(bundle: Record<string, unknown>): unknown {
  return bundle.trust_graph_snapshot || bundle.trust_graph || null;
}

export function extractGuardianRecords(bundle: Record<string, unknown>): Record<string, unknown>[] {
  return asArray(bundle.guardian_records).map((raw) => normalizeGuardianRecord(raw));
}

export function extractLayer3State(bundle: Record<string, unknown>): unknown {
  return bundle.layer3_state_snapshot || bundle.layer3_state || null;
}
