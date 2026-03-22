import { SessionState } from "./master_data_connector_to_layer4";

export const MOCK_SESSION: SessionState = {
  operator_id: "operator_demo",
  tenant_id: "tenant_demo",
  tenant_ids: ["tenant_demo"],
  role: "OWNER",
  session_token: "mock-token",
  issued_at_unix_ms: 1710000000000,
  expires_at_unix_ms: 1710003600000,
};

export const MOCK_DASHBOARD: Record<string, unknown> = {
  tenant_id: "tenant_demo",
  cycle_id: "cycle_000001",
  health_summary: {
    total_endpoints: 5,
    critical_count: 1,
    high_count: 1,
    medium_count: 2,
    low_count: 1,
  },
  risk_distribution: {
    critical: 1,
    high: 1,
    medium: 2,
    low: 1,
  },
  endpoints: [],
};
