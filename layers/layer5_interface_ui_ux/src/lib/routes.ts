export const ROUTES = {
  LOGIN: "/login",
  REGISTER: "/register",
  DASHBOARD: "/dashboard",
  ONBOARDING: "/onboarding",
  ENDPOINTS: "/endpoints",
  ENDPOINT_DETAIL: "/endpoints/:entityId",
  FINDINGS: "/findings",
  ALERTS: "/alerts",
  CYCLES: "/cycles",
  CYCLE_DETAIL: "/cycles/:cycleId",
  TELEMETRY: "/cycles/:cycleId/telemetry",
  GRAPH: "/graph",
  NOTES: "/notes",
  TASKS: "/tasks",
  SIMULATOR: "/simulator",
  SIMULATION_DETAIL: "/simulator/:simulationId",
  SETTINGS: "/settings/*",
} as const;

export function endpointDetailPath(entityId: string): string {
  return `/endpoints/${encodeURIComponent(entityId)}`;
}

export function cycleDetailPath(cycleId: string): string {
  return `/cycles/${encodeURIComponent(cycleId)}`;
}

export function telemetryPath(cycleId: string): string {
  return `/cycles/${encodeURIComponent(cycleId)}/telemetry`;
}

export function simulationDetailPath(simulationId: string): string {
  return `/simulator/${encodeURIComponent(simulationId)}`;
}
