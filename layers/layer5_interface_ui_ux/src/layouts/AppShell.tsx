import type { ReactNode } from "react";
import { useEffect, useRef, useState } from "react";
import { Outlet, NavLink, useNavigate } from "react-router-dom";
import { useSessionStore } from "../stores/useSessionStore";
import { useDashboardStore } from "../stores/useDashboardStore";
import { useNotesStore } from "../stores/useNotesStore";
import { BrandLotus } from "../components/BrandLotus";
import { dataSource, type ScanStatus } from "../lib/api";
import { formatDuration, formatRelativeTime, formatTimestamp, severityBand, severityColor } from "../lib/formatters";

interface NavItem {
  to: string;
  label: string;
  icon: ReactNode;
  badge?: number;
}

const OPS_NAV: NavItem[] = [
  { to: "/dashboard", label: "Dashboard", icon: <DashboardIcon /> },
  { to: "/endpoints", label: "Endpoints", icon: <EndpointsIcon /> },
  { to: "/findings", label: "Findings", icon: <FindingsIcon /> },
  { to: "/alerts", label: "Alerts", icon: <AlertsIcon /> },
];

const ANALYSIS_NAV: NavItem[] = [
  { to: "/cycles", label: "Cycles", icon: <CyclesIcon /> },
  { to: "/graph", label: "Graph", icon: <GraphIcon /> },
  { to: "/simulator", label: "Simulator", icon: <SimulatorIcon /> },
];

const WORKSPACE_NAV: NavItem[] = [
  { to: "/notes", label: "Notes", icon: <NotesIcon /> },
  { to: "/tasks", label: "Tasks", icon: <TasksIcon /> },
];

function ShellIcon({ children }: { children: ReactNode }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className="g-nav-svg"
    >
      {children}
    </svg>
  );
}

function DashboardIcon() {
  return (
    <ShellIcon>
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" />
      <rect x="14" y="14" width="7" height="7" rx="1" />
    </ShellIcon>
  );
}

function EndpointsIcon() {
  return (
    <ShellIcon>
      <circle cx="12" cy="12" r="8" />
      <path d="M12 4v16" />
      <path d="M4 12h16" />
    </ShellIcon>
  );
}

function FindingsIcon() {
  return (
    <ShellIcon>
      <path d="M12 3 2.5 20h19L12 3Z" />
      <path d="M12 9v4" />
      <path d="M12 17h.01" />
    </ShellIcon>
  );
}

function AlertsIcon() {
  return (
    <ShellIcon>
      <path d="M6 9a6 6 0 1 1 12 0c0 5 2 6 2 6H4s2-1 2-6" />
      <path d="M10 19a2 2 0 0 0 4 0" />
    </ShellIcon>
  );
}

function CyclesIcon() {
  return (
    <ShellIcon>
      <path d="M21 12a9 9 0 1 1-2.64-6.36" />
      <path d="M21 3v6h-6" />
    </ShellIcon>
  );
}

function GraphIcon() {
  return (
    <ShellIcon>
      <circle cx="6" cy="12" r="2" />
      <circle cx="18" cy="6" r="2" />
      <circle cx="18" cy="18" r="2" />
      <path d="M8 11l8-4" />
      <path d="M8 13l8 4" />
    </ShellIcon>
  );
}

function SimulatorIcon() {
  return (
    <ShellIcon>
      <path d="M9 3h6" />
      <path d="M10 3v4l-5 8a4 4 0 0 0 3.4 6h7.2A4 4 0 0 0 19 15l-5-8V3" />
      <path d="M8 15h8" />
    </ShellIcon>
  );
}

function NotesIcon() {
  return (
    <ShellIcon>
      <path d="M7 3h8l4 4v14H7z" />
      <path d="M15 3v4h4" />
      <path d="M10 12h6" />
      <path d="M10 16h6" />
    </ShellIcon>
  );
}

function TasksIcon() {
  return (
    <ShellIcon>
      <path d="M9 6h11" />
      <path d="M9 12h11" />
      <path d="M9 18h11" />
      <path d="m4 6 1.5 1.5L7.5 5" />
      <path d="m4 12 1.5 1.5L7.5 11" />
      <path d="m4 18 1.5 1.5L7.5 17" />
    </ShellIcon>
  );
}

function SettingsIcon() {
  return (
    <ShellIcon>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.7 1.7 0 0 0 .34 1.82l.03.03a2 2 0 1 1-2.83 2.83l-.03-.03a1.7 1.7 0 0 0-1.82-.34 1.7 1.7 0 0 0-1.03 1.56V21a2 2 0 1 1-4 0v-.04a1.7 1.7 0 0 0-1.03-1.56 1.7 1.7 0 0 0-1.82.34l-.03.03a2 2 0 1 1-2.83-2.83l.03-.03A1.7 1.7 0 0 0 4.6 15a1.7 1.7 0 0 0-1.56-1.03H3a2 2 0 1 1 0-4h.04A1.7 1.7 0 0 0 4.6 8.94a1.7 1.7 0 0 0-.34-1.82l-.03-.03a2 2 0 1 1 2.83-2.83l.03.03A1.7 1.7 0 0 0 8.9 4.6a1.7 1.7 0 0 0 1.03-1.56V3a2 2 0 1 1 4 0v.04a1.7 1.7 0 0 0 1.03 1.56 1.7 1.7 0 0 0 1.82-.34l.03-.03a2 2 0 1 1 2.83 2.83l-.03.03A1.7 1.7 0 0 0 19.4 8.9c.43.62.67 1.36.67 2.1s-.24 1.48-.67 2.1Z" />
    </ShellIcon>
  );
}

function LotusMark() {
  return (
    <svg
      viewBox="0 0 100 82"
      fill="none"
      stroke="currentColor"
      strokeWidth="3.2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className="g-brand-mark-svg"
    >
      {/* Back-left petal */}
      <path d="M50 72 C46 60 30 46 14 40 C12 54 20 66 38 72 C44 74 48 73 50 72Z" />
      {/* Back-right petal */}
      <path d="M50 72 C54 60 70 46 86 40 C88 54 80 66 62 72 C56 74 52 73 50 72Z" />
      {/* Front-left petal */}
      <path d="M50 74 C44 58 24 36 4 26 C2 46 14 66 38 74 C44 76 48 75 50 74Z" />
      {/* Front-right petal */}
      <path d="M50 74 C56 58 76 36 96 26 C98 46 86 66 62 74 C56 76 52 75 50 74Z" />
      {/* Centre petal — tallest, pointed tip */}
      <path d="M50 2 C44 18 40 38 40 52 C40 64 44 72 50 76 C56 72 60 64 60 52 C60 38 56 18 50 2Z" />
    </svg>
  );
}

function SidebarNavItem({ to, label, icon, badge }: NavItem) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) => `g-nav-item${isActive ? " active" : ""}`}
    >
      <span className="g-nav-icon">{icon}</span>
      <span>{label}</span>
      {badge != null && badge > 0 && <span className="g-nav-badge">{badge}</span>}
    </NavLink>
  );
}

export function AppShell() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [scanStatusOpen, setScanStatusOpen] = useState(false);
  const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
  const navigate = useNavigate();
  const session = useSessionStore((s) => s.session);
  const activeTenantId = useSessionStore((s) => s.activeTenantId);
  const logout = useSessionStore((s) => s.logout);
  const dashboard = useDashboardStore((s) => s.data);
  const fetchDashboard = useDashboardStore((s) => s.fetchDashboard);
  const notesCount = useNotesStore((s) => s.notes.length);
  const tasksCount = useNotesStore((s) => s.tasks.length);
  const lastDashboardRefreshCycleRef = useRef<string>("");

  const workspace = dashboard?.workspace;
  const health = dashboard?.health_summary;
  const resolvedTenantId = dashboard?.tenant_id || activeTenantId || session?.tenant_id || session?.tenant_ids?.[0] || "";

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  const maxSevBand = health ? severityBand(health.max_severity) : null;
  const healthColor = maxSevBand ? severityColor(maxSevBand) : "var(--muted)";
  const lastScanMs = health?.last_cycle_timestamp_unix_ms;
  const canAccessSettings = session?.role === "OWNER" || session?.role === "ADMIN";
  const scanRunning = scanStatus?.status === "running";

  useEffect(() => {
    if (!resolvedTenantId || !session?.session_token) {
      setScanStatus(null);
      return;
    }

    let cancelled = false;
    let timer: number | undefined;

    const poll = async () => {
      let nextStatus: ScanStatus | null = null;
      try {
        nextStatus = await dataSource.getScanStatus(resolvedTenantId);
        if (!cancelled) {
          setScanStatus(nextStatus);
        }
      } catch {
        if (!cancelled) {
          setScanStatus(null);
        }
      } finally {
        if (!cancelled) {
          const shouldPollFast = scanStatusOpen || nextStatus?.status === "running";
          timer = window.setTimeout(poll, shouldPollFast ? 10000 : 30000);
        }
      }
    };

    void poll();

    return () => {
      cancelled = true;
      if (timer !== undefined) {
        window.clearTimeout(timer);
      }
    };
  }, [resolvedTenantId, session?.session_token, scanStatusOpen]);

  useEffect(() => {
    if (!resolvedTenantId || !scanStatus) {
      return;
    }
    if (scanStatus.status === "running") {
      lastDashboardRefreshCycleRef.current = "";
      return;
    }
    if (scanStatus.status !== "completed" || !scanStatus.cycle_id) {
      return;
    }
    const dashboardCycleId = dashboard?.health_summary.last_cycle_id || "";
    if (dashboardCycleId === scanStatus.cycle_id) {
      lastDashboardRefreshCycleRef.current = scanStatus.cycle_id;
      return;
    }
    if (lastDashboardRefreshCycleRef.current === scanStatus.cycle_id) {
      return;
    }
    lastDashboardRefreshCycleRef.current = scanStatus.cycle_id;
    void fetchDashboard(resolvedTenantId);
  }, [
    resolvedTenantId,
    scanStatus?.status,
    scanStatus?.cycle_id,
    dashboard?.health_summary.last_cycle_id,
    fetchDashboard,
  ]);

  return (
    <div className={`g-shell${sidebarCollapsed ? " g-shell-collapsed" : ""}`}>
      <aside className="g-sidebar">
        <div className="g-sidebar-brand">
          <div className="g-sidebar-brand-main">
            <button
              type="button"
              className="g-sidebar-mark-button"
              onClick={() => setSidebarCollapsed((value) => !value)}
              aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
              title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
              <BrandLotus className="g-brand-mark-svg" />
            </button>
            <div className="g-sidebar-brand-copy">
              <div className="g-sidebar-title">Guardian</div>
            </div>
          </div>
        </div>

        <nav className="g-sidebar-nav">
          <div className="g-sidebar-section-label">Operations</div>
          {OPS_NAV.map((item) => {
            let badge: number | undefined;
            if (item.to === "/endpoints") badge = health?.total_endpoints;
            if (item.to === "/findings") {
              const tlsFindings = dashboard?.observation_summary?.tls_findings_count ?? 0;
              const wafFindings = dashboard?.observation_summary?.waf_findings_count ?? 0;
              badge = tlsFindings + wafFindings;
            }
            if (item.to === "/alerts") badge = health ? health.critical_count + health.high_count : undefined;
            return <SidebarNavItem key={item.to} {...item} badge={badge} />;
          })}

          <div className="g-sidebar-section-label" style={{ marginTop: 8 }}>
            Analysis
          </div>
          {ANALYSIS_NAV.map((item) => (
            <SidebarNavItem key={item.to} {...item} />
          ))}

          <div className="g-sidebar-section-label" style={{ marginTop: 8 }}>
            Workspace
          </div>
          {WORKSPACE_NAV.map((item) => {
            let badge: number | undefined;
            if (item.to === "/notes") badge = notesCount;
            if (item.to === "/tasks") badge = tasksCount;
            return <SidebarNavItem key={item.to} {...item} badge={badge} />;
          })}
        </nav>

        <div className="g-sidebar-footer">
          {canAccessSettings && (
            <NavLink
              to="/settings"
              className={({ isActive }) => `g-nav-item${isActive ? " active" : ""}`}
              style={{ padding: "9px 0", borderLeft: "none" }}
            >
              <span className="g-nav-icon">
                <SettingsIcon />
              </span>
              <span>Settings</span>
            </NavLink>
          )}
          <div className="g-operator-tenant">User email: {session?.email ?? "-"}</div>
          <div className="g-operator-meta">Institution Name: {workspace?.institution_name || "-"}</div>
          <button className="btn btn-neutral btn-small g-logout-btn" onClick={handleLogout}>
            Logout
          </button>
        </div>
      </aside>

      <div className="g-main">
        <header className="g-topbar">
          <div className="g-status-pill">
            <span className="g-status-dot" style={{ background: healthColor }} />
            <span>Health</span>
          </div>

          <div className="g-status-popover-wrap">
            <button
              type="button"
              className={`g-status-pill g-status-button${scanRunning ? " is-live" : ""}`}
              onClick={() => setScanStatusOpen((value) => !value)}
            >
              <span>
                {scanRunning
                  ? `Scan Running: ${formatDuration(scanStatus?.elapsed_ms ?? 0)} elapsed`
                  : `Last Scan: ${lastScanMs ? formatRelativeTime(lastScanMs) : "-"}`}
              </span>
            </button>
            {scanStatusOpen && (
              <div className="g-scan-popover">
                <div className="g-scan-popover-title">Scan Status</div>
                <div className="g-scan-popover-grid">
                  <span>Status</span>
                  <span>{scanRunning ? "Running" : (scanStatus?.status || "Idle").toUpperCase()}</span>
                  <span>Cycle ID</span>
                  <span>{scanStatus?.cycle_id || health?.last_cycle_id || "-"}</span>
                  <span>Stage</span>
                  <span>{humanizeStage(scanStatus?.stage)}</span>
                  <span>Started</span>
                  <span>{formatTimestamp(scanStatus?.started_at_unix_ms)}</span>
                  <span>Elapsed</span>
                  <span>{formatDuration(scanStatus?.elapsed_ms ?? 0)}</span>
                  <span>Stage Elapsed</span>
                  <span>{formatDuration(scanStatus?.stage_elapsed_ms ?? 0)}</span>
                  <span>Last Duration</span>
                  <span>{formatDuration(scanStatus?.last_completed_duration_ms ?? 0)}</span>
                  <span>Estimated Remaining</span>
                  <span>
                    {typeof scanStatus?.estimated_remaining_ms === "number"
                      ? formatDuration(scanStatus.estimated_remaining_ms)
                      : "-"}
                  </span>
                  <span>Stage Remaining</span>
                  <span>
                    {typeof scanStatus?.stage_estimated_remaining_ms === "number"
                      ? formatDuration(scanStatus.stage_estimated_remaining_ms)
                      : "-"}
                  </span>
                  <span>Category A Budget</span>
                  <span>
                    {typeof scanStatus?.category_a_time_budget_seconds === "number"
                      ? formatDuration(scanStatus.category_a_time_budget_seconds * 1000)
                      : "-"}
                  </span>
                  <span>BCDE Budget</span>
                  <span>
                    {typeof scanStatus?.bcde_time_budget_seconds === "number"
                      ? formatDuration(scanStatus.bcde_time_budget_seconds * 1000)
                      : "-"}
                  </span>
                  <span>Cycle Budget</span>
                  <span>
                    {typeof scanStatus?.cycle_time_budget_seconds === "number"
                      ? formatDuration(scanStatus.cycle_time_budget_seconds * 1000)
                      : "-"}
                  </span>
                  <span>Cycle Remaining</span>
                  <span>
                    {typeof scanStatus?.cycle_budget_remaining_ms === "number"
                      ? formatDuration(scanStatus.cycle_budget_remaining_ms)
                      : "-"}
                  </span>
                  <span>Progress Channel</span>
                  <span>
                    {scanStatus?.progress_channel_degraded
                      ? `Degraded${typeof scanStatus?.lock_write_warning_count === "number"
                          ? ` (${scanStatus.lock_write_warning_count} warnings)`
                          : ""}`
                      : "Healthy"}
                  </span>
                  <span>Last Lock Warning</span>
                  <span>{scanStatus?.last_lock_write_error || "-"}</span>
                  <span>Seed Endpoints</span>
                  <span>{formatOptionalCount(scanStatus?.seed_endpoint_count)}</span>
                  <span>Planned Scopes</span>
                  <span>
                    {formatProgress(
                      scanStatus?.expansion_scope_processed_count,
                      scanStatus?.planned_scope_count ?? scanStatus?.root_scope_count,
                    )}
                  </span>
                  <span>Current Window</span>
                  <span>{humanizeStage(scanStatus?.expansion_window || scanStatus?.stage)}</span>
                  <span>Window Progress</span>
                  <span>
                    {typeof scanStatus?.expansion_window_actual_elapsed_seconds === "number" ||
                    typeof scanStatus?.expansion_window_consumed_seconds === "number" ||
                    typeof scanStatus?.expansion_window_budget_seconds === "number"
                      ? `${formatOptionalCount(scanStatus?.expansion_window_actual_elapsed_seconds ?? scanStatus?.expansion_window_consumed_seconds)} / ${formatOptionalCount(scanStatus?.expansion_window_budget_seconds)}s`
                      : "-"}
                  </span>
                  <span>Window Remaining</span>
                  <span>
                    {typeof scanStatus?.expansion_window_remaining_seconds === "number"
                      ? `${formatOptionalCount(scanStatus?.expansion_window_remaining_seconds)}s`
                      : "-"}
                  </span>
                  <span>Window Pass</span>
                  <span>{humanizePassType(scanStatus?.expansion_pass_type)}</span>
                  <span>Coverage</span>
                  <span>
                    {formatProgress(
                      scanStatus?.coverage_entries_completed,
                      scanStatus?.coverage_entries_total,
                    )}
                  </span>
                  <span>Current Phase</span>
                  <span>{humanizeStage(scanStatus?.expansion_phase)}</span>
                  <span>Expansion Category</span>
                  <span>{scanStatus?.expansion_active_category || "-"}</span>
                  <span>Current Scope</span>
                  <span>{scanStatus?.expansion_current_scope || "-"}</span>
                  <span>Scope Cursor</span>
                  <span>
                    {formatProgress(
                      scanStatus?.expansion_scope_index,
                      scanStatus?.expansion_scope_total_count,
                    )}
                  </span>
                  <span>Scopes Seen Once</span>
                  <span>
                    {formatProgress(
                      scanStatus?.expansion_scope_seen_once_count,
                      scanStatus?.expansion_scope_total_count,
                    )}
                  </span>
                  <span>Phase Progress</span>
                  <span>
                    {formatProgress(
                      scanStatus?.expansion_phase_scope_completed_count,
                      scanStatus?.expansion_phase_scope_total_count,
                    )}
                  </span>
                  <span>Current Module</span>
                  <span>{scanStatus?.expansion_current_module || "-"}</span>
                  <span>Module In Scope</span>
                  <span>
                    {formatProgress(
                      scanStatus?.expansion_module_index_within_scope,
                      scanStatus?.expansion_module_total_count,
                    )}
                  </span>
                  <span>Module Turn</span>
                  <span>
                    {formatProgress(
                      scanStatus?.expansion_module_turn_index,
                      scanStatus?.expansion_module_total_count,
                    )}
                  </span>
                  <span>Completed Turns</span>
                  <span>{formatOptionalCount(scanStatus?.expansion_module_turns_completed)}</span>
                  <span>Turn Slice</span>
                  <span>
                    {typeof scanStatus?.expansion_turn_slice_seconds === "number"
                      ? `${scanStatus.expansion_turn_slice_seconds}s`
                      : "-"}
                  </span>
                  <span>Module Progress</span>
                  <span>
                    {formatProgress(
                      scanStatus?.expansion_modules_seen_once_count,
                      scanStatus?.expansion_module_total_count,
                    )}
                  </span>
                  <span>Productive A</span>
                  <span>{formatNameList(scanStatus?.expansion_productive_category_a_modules)}</span>
                  <span>Productive BCDE</span>
                  <span>{formatNameList(scanStatus?.expansion_productive_bcde_modules)}</span>
                  <span>Graph Nodes</span>
                  <span>{formatOptionalCount(scanStatus?.expansion_node_count)}</span>
                  <span>Graph Edges</span>
                  <span>{formatOptionalCount(scanStatus?.expansion_edge_count)}</span>
                  <span>Graph Endpoints</span>
                  <span>{formatOptionalCount(scanStatus?.expansion_graph_endpoint_count)}</span>
                  <span>Related Live</span>
                  <span>{formatOptionalCount(scanStatus?.discovered_related_count_live)}</span>
                  <span>In-flight Candidates</span>
                  <span>{formatOptionalCount(scanStatus?.inflight_candidate_count)}</span>
                  <span>Candidates</span>
                  <span>{formatProgress(scanStatus?.expanded_candidate_count, scanStatus?.total_candidate_count)}</span>
                  <span>Candidates By Scope</span>
                  <span>{formatScopeCounts(scanStatus?.candidate_count_by_scope)}</span>
                  <span>Observation Target</span>
                  <span>
                    {formatOptionalCount(scanStatus?.observation_target_count)}
                    {scanStatus?.observation_cap_hit ? " (capped)" : ""}
                  </span>
                  <span>Observed</span>
                  <span>
                    {formatProgress(
                      scanStatus?.observed_completed_count,
                      scanStatus?.observation_target_count,
                    )}
                  </span>
                  <span>Success / Failed</span>
                  <span>
                    {formatOptionalCount(scanStatus?.observed_successful_count)}
                    {" / "}
                    {formatOptionalCount(scanStatus?.observed_failed_count)}
                  </span>
                  <span>Snapshot Endpoints</span>
                  <span>{formatOptionalCount(scanStatus?.snapshot_endpoint_count)}</span>
                  <span>New / Removed</span>
                  <span>
                    {formatOptionalCount(scanStatus?.new_endpoint_count)}
                    {" / "}
                    {formatOptionalCount(scanStatus?.removed_endpoint_count)}
                  </span>
                </div>
                {Array.isArray(scanStatus?.stage_history) && scanStatus.stage_history.length > 0 && (
                  <div className="g-scan-popover-section">
                    <div className="g-scan-popover-title">Stage History</div>
                    <div className="g-scan-history-list">
                      {scanStatus.stage_history.slice(-6).map((row) => (
                        <div key={`${row.index || 0}-${row.stage}`} className="g-scan-history-row">
                          <span>{humanizeStage(row.stage)}</span>
                          <span>{formatTimestamp(row.started_at_unix_ms)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {Array.isArray(scanStatus?.expansion_phase_history) && scanStatus.expansion_phase_history.length > 0 && (
                  <div className="g-scan-popover-section">
                    <div className="g-scan-popover-title">Expansion Phases</div>
                    <div className="g-scan-history-list">
                      {scanStatus.expansion_phase_history.slice(-6).map((row) => (
                        <div key={`${row.phase}-${row.started_at_unix_ms || 0}`} className="g-scan-history-row">
                          <span>
                            {humanizeStage(row.phase)} · {humanizePhaseStatus(row.status)}
                          </span>
                          <span>
                            {formatProgress(row.scope_completed_count, row.scope_total_count)}
                            {typeof row.productive_scope_count === "number"
                              ? ` · productive ${row.productive_scope_count}`
                              : ""}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {workspace?.onboarding_status === "PENDING" && (
            <div className="g-status-pill" style={{ color: "var(--color-severity-medium)" }}>
              {scanRunning ? "Onboarding In Progress" : "Onboarding Pending"}
            </div>
          )}
        </header>

        <main className="g-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

function humanizeStage(stage: string | undefined): string {
  const value = String(stage || "idle").trim();
  if (!value) return "-";
  return value
    .split("_")
    .map((part) => (part ? part[0].toUpperCase() + part.slice(1) : part))
    .join(" ");
}

function formatOptionalCount(value: number | undefined): string {
  return typeof value === "number" && Number.isFinite(value) ? String(value) : "-";
}

function formatNameList(values: string[] | undefined): string {
  if (!Array.isArray(values) || values.length === 0) {
    return "-";
  }
  return values.join(", ");
}

function formatScopeCounts(values: Record<string, number> | undefined): string {
  if (!values || Object.keys(values).length === 0) {
    return "-";
  }
  return Object.entries(values)
    .map(([scope, count]) => `${scope}:${count}`)
    .join(", ");
}

function humanizePassType(value: string | undefined): string {
  const token = String(value || "").trim();
  if (!token) return "-";
  return token
    .split("_")
    .map((part) => (part ? part[0].toUpperCase() + part.slice(1) : part))
    .join(" ");
}

function humanizePhaseStatus(status: string | undefined): string {
  const value = String(status || "").trim();
  if (!value) return "-";
  return value
    .split("_")
    .map((part) => (part ? part[0].toUpperCase() + part.slice(1) : part))
    .join(" ");
}

function formatProgress(current: number | undefined, total: number | undefined): string {
  if (typeof current === "number" && typeof total === "number" && Number.isFinite(current) && Number.isFinite(total)) {
    return `${current} / ${total}`;
  }
  if (typeof current === "number" && Number.isFinite(current)) {
    return String(current);
  }
  return "-";
}
