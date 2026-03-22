import { create } from "zustand";
import { dataSource, Layer5ApiError } from "../lib/api";
import { asObject, asArray, asNumber, asString } from "../lib/formatters";

export interface EndpointDTO {
  entity_id: string;
  endpoint_gid: string;
  hostname: string;
  port: number;
  url: string;
  ip: string;
  asn: string;
  tls_version: string;
  cipher: string;
  cert_issuer: string;
  certificate_sha256: string;
  certificate_expiry_unix_ms: number;
  entropy_score: number;
  volatility_score: number;
  visibility_score: number;
  consecutive_absence: number;
  first_seen_ms: number;
  last_seen_ms: number;
  guardian_risk: number;
  confidence: number;
  alert_count: number;
  shared_cert_cluster_id: string;
  lb_cluster_id: string;
  identity_cluster_id: string;
  discovery_source: string;
  discovery_sources: string[];
  ownership_category: string;
  ownership_confidence: number;
  relevance_score: number;
  relevance_reason: string;
  observation_status: string;
  observation_attempted: boolean;
  recorded_in_snapshot: boolean;
  surface_tags: string[];
}

export interface HealthSummary {
  total_endpoints: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  max_severity: number;
  last_cycle_id: string;
  last_cycle_duration_ms: number;
  last_cycle_timestamp_unix_ms: number;
}

export interface DriftReport {
  new_endpoints: number;
  removed_endpoints: number;
  risk_increased: boolean;
}

export interface ObservationSummary {
  discovered_related: number;
  observation_attempts: number;
  observation_successes: number;
  observation_failures: number;
  recorded_endpoints: number;
  unverified_historical: number;
  tls_findings_count: number;
  waf_findings_count: number;
}

export interface WorkspaceInfo {
  onboarding_status: string;
  institution_name: string;
  main_url: string;
  seed_count: number;
  seed_endpoints: string[];
}

export interface DashboardData {
  tenant_id: string;
  health_summary: HealthSummary;
  observation_summary: ObservationSummary;
  risk_distribution: { critical: number; high: number; medium: number; low: number };
  drift_report: DriftReport;
  endpoints: EndpointDTO[];
  workspace: WorkspaceInfo;
  cycle_id: string;
  timestamp_ms: number;
}

export function parseEndpointDTO(raw: unknown): EndpointDTO {
  const o = asObject(raw);
  return {
    entity_id: asString(o.entity_id),
    endpoint_gid: asString(o.endpoint_gid),
    hostname: asString(o.hostname),
    port: asNumber(o.port),
    url: asString(o.url),
    ip: asString(o.ip),
    asn: asString(o.asn),
    tls_version: asString(o.tls_version),
    cipher: asString(o.cipher),
    cert_issuer: asString(o.cert_issuer),
    certificate_sha256: asString(o.certificate_sha256),
    certificate_expiry_unix_ms: asNumber(o.certificate_expiry_unix_ms),
    entropy_score: asNumber(o.entropy_score),
    volatility_score: asNumber(o.volatility_score),
    visibility_score: asNumber(o.visibility_score),
    consecutive_absence: asNumber(o.consecutive_absence),
    first_seen_ms: asNumber(o.first_seen_ms),
    last_seen_ms: asNumber(o.last_seen_ms),
    guardian_risk: asNumber(o.guardian_risk),
    confidence: asNumber(o.confidence),
    alert_count: asNumber(o.alert_count),
    shared_cert_cluster_id: asString(o.shared_cert_cluster_id),
    lb_cluster_id: asString(o.lb_cluster_id),
    identity_cluster_id: asString(o.identity_cluster_id),
    discovery_source: asString(o.discovery_source),
    discovery_sources: asArray(o.discovery_sources).map(asString).filter(Boolean),
    ownership_category: asString(o.ownership_category),
    ownership_confidence: asNumber(o.ownership_confidence),
    relevance_score: asNumber(o.relevance_score),
    relevance_reason: asString(o.relevance_reason),
    observation_status: asString(o.observation_status),
    observation_attempted: Boolean(o.observation_attempted),
    recorded_in_snapshot: Boolean(o.recorded_in_snapshot),
    surface_tags: asArray(o.surface_tags).map(asString).filter(Boolean),
  };
}

function parseDashboard(raw: Record<string, unknown>): DashboardData {
  const hs = asObject(raw.health_summary);
  const os = asObject(raw.observation_summary);
  const rd = asObject(raw.risk_distribution);
  const dr = asObject(raw.drift_report);
  const ws = asObject(raw.workspace);

  return {
    tenant_id: asString(raw.tenant_id),
    health_summary: {
      total_endpoints: asNumber(hs.total_endpoints),
      critical_count: asNumber(hs.critical_count),
      high_count: asNumber(hs.high_count),
      medium_count: asNumber(hs.medium_count),
      low_count: asNumber(hs.low_count),
      max_severity: asNumber(hs.max_severity),
      last_cycle_id: asString(hs.last_cycle_id),
      last_cycle_duration_ms: asNumber(hs.last_cycle_duration_ms),
      last_cycle_timestamp_unix_ms: asNumber(hs.last_cycle_timestamp_unix_ms),
    },
    observation_summary: {
      discovered_related: asNumber(os.discovered_related),
      observation_attempts: asNumber(os.observation_attempts),
      observation_successes: asNumber(os.observation_successes),
      observation_failures: asNumber(os.observation_failures),
      recorded_endpoints: asNumber(os.recorded_endpoints),
      unverified_historical: asNumber(os.unverified_historical),
      tls_findings_count: asNumber(os.tls_findings_count),
      waf_findings_count: asNumber(os.waf_findings_count),
    },
    risk_distribution: {
      critical: asNumber(rd.critical),
      high: asNumber(rd.high),
      medium: asNumber(rd.medium),
      low: asNumber(rd.low),
    },
    drift_report: {
      new_endpoints: asNumber(dr.new_endpoints),
      removed_endpoints: asNumber(dr.removed_endpoints),
      risk_increased: Boolean(dr.risk_increased),
    },
    endpoints: asArray(raw.endpoints).map(parseEndpointDTO),
    workspace: {
      onboarding_status: asString(ws.onboarding_status),
      institution_name: asString(ws.institution_name),
      main_url: asString(ws.main_url),
      seed_count: asNumber(ws.seed_count),
      seed_endpoints: asArray(ws.seed_endpoints).map(asString).filter(Boolean),
    },
    cycle_id: asString(raw.cycle_id),
    timestamp_ms: asNumber(raw.timestamp_ms),
  };
}

interface DashboardStore {
  data: DashboardData | null;
  loading: boolean;
  error: string | null;
  lastFetchedMs: number;

  fetchDashboard: (tenantId: string) => Promise<void>;
  clear: () => void;
}

export const useDashboardStore = create<DashboardStore>((set) => ({
  data: null,
  loading: false,
  error: null,
  lastFetchedMs: 0,

  fetchDashboard: async (tenantId) => {
    set({ loading: true, error: null });
    try {
      const raw = await dataSource.getDashboard(tenantId);
      const data = parseDashboard(raw);
      set({ data, loading: false, lastFetchedMs: Date.now() });
    } catch (err) {
      const msg = err instanceof Layer5ApiError ? err.message : String(err);
      set({ loading: false, error: msg });
    }
  },

  clear: () => set({ data: null, loading: false, error: null, lastFetchedMs: 0 }),
}));
