import { Layer5ApiConnector } from "./data_connector_to_ui";

export interface SessionState {
  operator_id: string;
  email?: string;
  created_at_unix_ms?: number;
  tenant_id?: string;
  tenant_ids: string[];
  role?: string;
  session_token: string;
  issued_at_unix_ms: number;
  expires_at_unix_ms: number;
}

export interface TenantUserSummary {
  operator_id: string;
  email?: string;
  role?: string;
  status?: string;
  created_at_unix_ms?: number;
}

export interface ScanStatus {
  tenant_id: string;
  status: string;
  cycle_id: string;
  stage: string;
  started_at_unix_ms?: number;
  stage_started_at_unix_ms?: number;
  updated_at_unix_ms?: number;
  elapsed_ms: number;
  stage_elapsed_ms?: number;
  last_completed_duration_ms: number;
  last_completed_timestamp_unix_ms?: number;
  estimated_remaining_ms?: number;
  stage_estimated_remaining_ms?: number;
  category_a_time_budget_seconds?: number;
  bcde_time_budget_seconds?: number;
  cycle_time_budget_seconds?: number;
  cycle_deadline_unix_ms?: number;
  cycle_budget_remaining_ms?: number;
  seed_endpoint_count?: number;
  root_scope_count?: number;
  planned_scope_count?: number;
  expansion_scope_processed_count?: number;
  expanded_candidate_count?: number;
  total_candidate_count?: number;
  expansion_window?: string;
  expansion_window_index?: number;
  expansion_window_total_count?: number;
  expansion_window_budget_seconds?: number;
  expansion_window_actual_elapsed_seconds?: number;
  expansion_window_consumed_seconds?: number;
  expansion_window_remaining_seconds?: number;
  expansion_active_category?: string;
  expansion_phase?: string;
  expansion_pass_type?: "initial_pass" | "follow_up_pass" | string;
  initial_pass_completed?: boolean;
  coverage_entries_total?: number;
  coverage_entries_completed?: number;
  expansion_current_scope?: string;
  expansion_phase_scope_completed_count?: number;
  expansion_phase_scope_total_count?: number;
  expansion_scope_index?: number;
  expansion_scope_total_count?: number;
  expansion_scope_seen_once_count?: number;
  expansion_current_module?: string;
  expansion_modules_completed_count?: number;
  expansion_module_total_count?: number;
  expansion_module_index_within_scope?: number;
  expansion_modules_seen_once_count?: number;
  expansion_module_turn_index?: number;
  expansion_module_turns_completed?: number;
  expansion_turn_slice_seconds?: number;
  expansion_node_count?: number;
  expansion_edge_count?: number;
  expansion_graph_endpoint_count?: number;
  discovered_related_count_live?: number;
  inflight_candidate_count?: number;
  candidate_count_by_scope?: Record<string, number>;
  progress_channel_degraded?: boolean;
  lock_write_warning_count?: number;
  last_lock_write_error?: string;
  expansion_productive_category_a_modules?: string[];
  expansion_productive_bcde_modules?: string[];
  observation_target_count?: number;
  observation_cap_hit?: boolean;
  observed_completed_count?: number;
  observed_successful_count?: number;
  observed_failed_count?: number;
  snapshot_endpoint_count?: number;
  new_endpoint_count?: number;
  removed_endpoint_count?: number;
  scheduler_last_run_unix_ms?: number;
  scheduler_next_run_unix_ms?: number;
  scheduler_last_status?: string;
  scheduler_consecutive_failures?: number;
  scheduler_last_error?: string;
  stage_history?: Array<{
    index?: number;
    stage: string;
    started_at_unix_ms?: number;
  }>;
  expansion_phase_history?: Array<{
    phase: string;
    window?: string;
    status: string;
    reason?: string;
    scope_total_count?: number;
    scope_completed_count?: number;
    productive_scope_count?: number;
    module_turn_count?: number;
    budget_allocated_seconds?: number;
    budget_consumed_seconds?: number;
    budget_remaining_seconds?: number;
    logical_turn_budget_seconds?: number;
    actual_elapsed_seconds?: number;
    idle_gap_seconds?: number;
    initial_pass_completed?: boolean;
    coverage_entries_total?: number;
    coverage_entries_completed?: number;
    modules_seen_once_count?: number;
    scopes_seen_once_count?: number;
    started_at_unix_ms?: number;
    ended_at_unix_ms?: number;
  }>;
}

function parseOptionalNumber(payload: Record<string, unknown>, key: string): number | undefined {
  if (!(key in payload)) return undefined;
  const value = payload[key];
  if (value == null || value === "") return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function asObject(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

export class Layer5DataSource {
  private readonly connector: Layer5ApiConnector;
  private session: SessionState | null = null;

  constructor(connector: Layer5ApiConnector) {
    this.connector = connector;
  }

  getSession(): SessionState | null {
    return this.session ? { ...this.session } : null;
  }

  async login(operatorId: string, password: string): Promise<SessionState> {
    const payload = await this.connector.login(operatorId, password);
    const session = this.parseSession(payload);
    this.session = session;
    return session;
  }

  async registerAccount(payload: {
    email: string;
    password: string;
    institution_name?: string;
    created_at_unix_ms?: number;
    status?: string;
  }): Promise<Record<string, unknown>> {
    return this.connector.registerAccount(payload);
  }

  async resetPassword(identifier: string, newPassword: string): Promise<Record<string, unknown>> {
    return this.connector.resetPassword(identifier, newPassword);
  }

  async logout(): Promise<void> {
    const session = this.session;
    this.session = null;
    if (!session) {
      return;
    }
    await this.connector.logout(session.session_token);
  }

  async refreshSession(): Promise<SessionState> {
    this.requireSession();
    const payload = await this.connector.me(this.session!.session_token);
    const session: SessionState = {
      ...this.session!,
      operator_id: String(payload.operator_id || this.session!.operator_id),
      email: String(payload.email || this.session!.email || "").trim() || undefined,
      created_at_unix_ms:
        Number(payload.created_at_unix_ms || this.session!.created_at_unix_ms || 0) || undefined,
      tenant_id: String(payload.tenant_id || this.session!.tenant_id || "").trim() || undefined,
      tenant_ids: Array.isArray(payload.tenant_ids)
        ? payload.tenant_ids.map((v) => String(v))
        : (
            String(payload.tenant_id || this.session!.tenant_id || "").trim()
              ? [String(payload.tenant_id || this.session!.tenant_id || "").trim()]
              : this.session!.tenant_ids
          ),
      role: String(payload.role || this.session!.role || "").trim() || undefined,
    };
    this.session = session;
    return session;
  }

  async registerOperator(payload: {
    operator_id?: string;
    email: string;
    password: string;
    created_at_unix_ms: number;
    tenant_id?: string;
    role?: string;
    master_password?: string;
    status?: string;
  }): Promise<Record<string, unknown>> {
    return this.connector.registerOperator(payload, this.session?.session_token);
  }

  async registerTenant(payload: {
    institution_name: string;
    main_url: string;
    seed_endpoints?: string[];
    password?: string;
    registration_metadata?: Record<string, unknown>;
    created_at_unix_ms?: number;
  }): Promise<Record<string, unknown>> {
    return this.connector.registerTenant(payload, this.requireSession().session_token);
  }

  async listUsers(tenantId?: string): Promise<TenantUserSummary[]> {
    const payload = await this.connector.listUsers(this.requireSession().session_token, tenantId);
    const rawUsers = Array.isArray(payload.users) ? payload.users : [];
    return rawUsers.map((raw) => {
      const record = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
      return {
        operator_id: String(record.operator_id || "").trim(),
        email: String(record.email || "").trim() || undefined,
        role: String(record.role || "").trim() || undefined,
        status: String(record.status || "").trim() || undefined,
        created_at_unix_ms: Number(record.created_at_unix_ms || 0) || undefined,
      };
    });
  }

  async deleteUser(
    operatorId: string,
    currentPassword: string,
    tenantId?: string,
  ): Promise<Record<string, unknown>> {
    return this.connector.deleteUser(
      operatorId,
      this.requireSession().session_token,
      currentPassword,
      tenantId,
    );
  }

  async changeUserPassword(
    operatorId: string,
    currentPassword: string,
    newPassword: string,
    tenantId?: string,
  ): Promise<Record<string, unknown>> {
    return this.connector.changeUserPassword(
      operatorId,
      this.requireSession().session_token,
      currentPassword,
      newPassword,
      tenantId,
    );
  }

  async deleteCurrentUser(currentPassword: string): Promise<Record<string, unknown>> {
    return this.connector.deleteCurrentUser(
      this.requireSession().session_token,
      currentPassword,
    );
  }

  async resetWorkspace(currentPassword: string, tenantId?: string): Promise<Record<string, unknown>> {
    return this.connector.resetWorkspace(
      this.requireSession().session_token,
      currentPassword,
      tenantId,
    );
  }

  async onboardAndScan(
    tenantId: string,
    payload: {
      institution_name: string;
      main_url: string;
      seed_endpoints?: string[];
    },
  ): Promise<Record<string, unknown>> {
    return this.connector.onboardAndScan(tenantId, payload, this.requireSession().session_token);
  }

  async updateProfile(payload: {
    tenant_id: string;
    current_password: string;
    email?: string;
    institution_name?: string;
  }): Promise<Record<string, unknown>> {
    return this.connector.updateProfile(payload, this.requireSession().session_token);
  }

  async changePassword(payload: {
    current_password: string;
    new_password: string;
  }): Promise<Record<string, unknown>> {
    return this.connector.changePassword(payload, this.requireSession().session_token);
  }

  async getDashboard(tenantId: string): Promise<Record<string, unknown>> {
    return this.connector.getDashboard(tenantId, this.requireSession().session_token);
  }

  async getEndpointPage(
    tenantId: string,
    params?: {
      page?: number;
      pageSize?: number;
    },
  ): Promise<Record<string, unknown>> {
    return this.connector.getEndpointPage(
      tenantId,
      this.requireSession().session_token,
      params,
    );
  }

  async getEndpointDetail(
    tenantId: string,
    entityId: string,
  ): Promise<Record<string, unknown>> {
    return this.connector.getEndpointDetail(
      tenantId,
      entityId,
      this.requireSession().session_token,
    );
  }

  async getAllEndpointPages(
    tenantId: string,
    params?: {
      pageSize?: number;
      maxPages?: number;
    },
  ): Promise<Record<string, unknown>> {
    const pageSize = Math.max(1, Math.min(Number(params?.pageSize ?? 1000) || 1000, 5_000));
    const maxPages = Math.max(1, Math.min(Number(params?.maxPages ?? 20) || 20, 100));
    const first = await this.getEndpointPage(tenantId, {
      page: 1,
      pageSize,
    });
    const total = Number(first.total || 0) || 0;
    const rows = Array.isArray(first.rows) ? [...first.rows] : [];
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    const pagesToFetch = Math.min(totalPages, maxPages);
    for (let page = 2; page <= pagesToFetch; page += 1) {
      const next = await this.getEndpointPage(tenantId, {
        page,
        pageSize,
      });
      if (Array.isArray(next.rows)) {
        rows.push(...next.rows);
      }
    }
    return {
      ...first,
      page: 1,
      page_size: pageSize,
      rows,
      fetched_pages: pagesToFetch,
      truncated: totalPages > pagesToFetch,
    };
  }

  async getScanStatus(tenantId: string): Promise<ScanStatus> {
    const payload = await this.connector.getScanStatus(tenantId, this.requireSession().session_token);
    const estimatedRemainingMs = parseOptionalNumber(payload, "estimated_remaining_ms");
    return {
      tenant_id: String(payload.tenant_id || "").trim(),
      status: String(payload.status || "idle").trim() || "idle",
      cycle_id: String(payload.cycle_id || "").trim(),
      stage: String(payload.stage || "idle").trim() || "idle",
      started_at_unix_ms: parseOptionalNumber(payload, "started_at_unix_ms"),
      stage_started_at_unix_ms: parseOptionalNumber(payload, "stage_started_at_unix_ms"),
      updated_at_unix_ms: parseOptionalNumber(payload, "updated_at_unix_ms"),
      elapsed_ms: parseOptionalNumber(payload, "elapsed_ms") ?? 0,
      stage_elapsed_ms: parseOptionalNumber(payload, "stage_elapsed_ms"),
      last_completed_duration_ms: parseOptionalNumber(payload, "last_completed_duration_ms") ?? 0,
      last_completed_timestamp_unix_ms: parseOptionalNumber(payload, "last_completed_timestamp_unix_ms"),
      estimated_remaining_ms: estimatedRemainingMs,
      stage_estimated_remaining_ms: parseOptionalNumber(payload, "stage_estimated_remaining_ms"),
      category_a_time_budget_seconds: parseOptionalNumber(payload, "category_a_time_budget_seconds"),
      bcde_time_budget_seconds: parseOptionalNumber(payload, "bcde_time_budget_seconds"),
      cycle_time_budget_seconds: parseOptionalNumber(payload, "cycle_time_budget_seconds"),
      cycle_deadline_unix_ms: parseOptionalNumber(payload, "cycle_deadline_unix_ms"),
      cycle_budget_remaining_ms: parseOptionalNumber(payload, "cycle_budget_remaining_ms"),
      seed_endpoint_count: parseOptionalNumber(payload, "seed_endpoint_count"),
      root_scope_count: parseOptionalNumber(payload, "root_scope_count"),
      planned_scope_count: parseOptionalNumber(payload, "planned_scope_count"),
      expansion_scope_processed_count: parseOptionalNumber(payload, "expansion_scope_processed_count"),
      expanded_candidate_count: parseOptionalNumber(payload, "expanded_candidate_count"),
      total_candidate_count: parseOptionalNumber(payload, "total_candidate_count"),
      expansion_window:
        String(payload.expansion_window || "").trim() || undefined,
      expansion_window_index: parseOptionalNumber(payload, "expansion_window_index"),
      expansion_window_total_count: parseOptionalNumber(payload, "expansion_window_total_count"),
      expansion_window_budget_seconds: parseOptionalNumber(payload, "expansion_window_budget_seconds"),
      expansion_window_actual_elapsed_seconds: parseOptionalNumber(payload, "expansion_window_actual_elapsed_seconds"),
      expansion_window_consumed_seconds: parseOptionalNumber(payload, "expansion_window_consumed_seconds"),
      expansion_window_remaining_seconds: parseOptionalNumber(payload, "expansion_window_remaining_seconds"),
      expansion_active_category:
        String(payload.expansion_active_category || "").trim() || undefined,
      expansion_phase:
        String(payload.expansion_phase || "").trim() || undefined,
      expansion_pass_type:
        String(payload.expansion_pass_type || "").trim() || undefined,
      initial_pass_completed:
        payload.initial_pass_completed == null ? undefined : Boolean(payload.initial_pass_completed),
      coverage_entries_total: parseOptionalNumber(payload, "coverage_entries_total"),
      coverage_entries_completed: parseOptionalNumber(payload, "coverage_entries_completed"),
      expansion_current_scope:
        String(payload.expansion_current_scope || "").trim() || undefined,
      expansion_phase_scope_completed_count: parseOptionalNumber(payload, "expansion_phase_scope_completed_count"),
      expansion_phase_scope_total_count: parseOptionalNumber(payload, "expansion_phase_scope_total_count"),
      expansion_scope_index: parseOptionalNumber(payload, "expansion_scope_index"),
      expansion_scope_total_count: parseOptionalNumber(payload, "expansion_scope_total_count"),
      expansion_scope_seen_once_count: parseOptionalNumber(payload, "expansion_scope_seen_once_count"),
      expansion_current_module:
        String(payload.expansion_current_module || "").trim() || undefined,
      expansion_modules_completed_count: parseOptionalNumber(payload, "expansion_modules_completed_count"),
      expansion_module_total_count: parseOptionalNumber(payload, "expansion_module_total_count"),
      expansion_module_index_within_scope: parseOptionalNumber(payload, "expansion_module_index_within_scope"),
      expansion_modules_seen_once_count: parseOptionalNumber(payload, "expansion_modules_seen_once_count"),
      expansion_module_turn_index: parseOptionalNumber(payload, "expansion_module_turn_index"),
      expansion_module_turns_completed: parseOptionalNumber(payload, "expansion_module_turns_completed"),
      expansion_turn_slice_seconds: parseOptionalNumber(payload, "expansion_turn_slice_seconds"),
      expansion_node_count: parseOptionalNumber(payload, "expansion_node_count"),
      expansion_edge_count: parseOptionalNumber(payload, "expansion_edge_count"),
      expansion_graph_endpoint_count: parseOptionalNumber(payload, "expansion_graph_endpoint_count"),
      discovered_related_count_live: parseOptionalNumber(payload, "discovered_related_count_live"),
      inflight_candidate_count: parseOptionalNumber(payload, "inflight_candidate_count"),
      progress_channel_degraded:
        payload.progress_channel_degraded == null
          ? undefined
          : Boolean(payload.progress_channel_degraded),
      lock_write_warning_count: parseOptionalNumber(payload, "lock_write_warning_count"),
      last_lock_write_error:
        String(payload.last_lock_write_error || "").trim() || undefined,
      candidate_count_by_scope:
        payload.candidate_count_by_scope &&
        typeof payload.candidate_count_by_scope === "object" &&
        !Array.isArray(payload.candidate_count_by_scope)
          ? Object.fromEntries(
              Object.entries(payload.candidate_count_by_scope as Record<string, unknown>)
                .map(([key, value]) => [String(key || "").trim(), Number(value)])
                .filter(([key, value]) => key && Number.isFinite(value)),
            )
          : undefined,
      expansion_productive_category_a_modules: Array.isArray(payload.expansion_productive_category_a_modules)
        ? payload.expansion_productive_category_a_modules
            .map((value) => String(value || "").trim())
            .filter(Boolean)
        : undefined,
      expansion_productive_bcde_modules: Array.isArray(payload.expansion_productive_bcde_modules)
        ? payload.expansion_productive_bcde_modules
            .map((value) => String(value || "").trim())
            .filter(Boolean)
        : undefined,
      observation_target_count: parseOptionalNumber(payload, "observation_target_count"),
      observation_cap_hit:
        payload.observation_cap_hit == null ? undefined : Boolean(payload.observation_cap_hit),
      observed_completed_count: parseOptionalNumber(payload, "observed_completed_count"),
      observed_successful_count: parseOptionalNumber(payload, "observed_successful_count"),
      observed_failed_count: parseOptionalNumber(payload, "observed_failed_count"),
      snapshot_endpoint_count: parseOptionalNumber(payload, "snapshot_endpoint_count"),
      new_endpoint_count: parseOptionalNumber(payload, "new_endpoint_count"),
      removed_endpoint_count: parseOptionalNumber(payload, "removed_endpoint_count"),
      scheduler_last_run_unix_ms: parseOptionalNumber(payload, "scheduler_last_run_unix_ms"),
      scheduler_next_run_unix_ms: parseOptionalNumber(payload, "scheduler_next_run_unix_ms"),
      scheduler_last_status:
        String(payload.scheduler_last_status || "").trim() || undefined,
      scheduler_consecutive_failures: parseOptionalNumber(payload, "scheduler_consecutive_failures"),
      scheduler_last_error:
        String(payload.scheduler_last_error || "").trim() || undefined,
      stage_history: Array.isArray(payload.stage_history)
        ? payload.stage_history.map((value) => {
            const row = asObject(value);
            return {
              index: parseOptionalNumber(row, "index"),
              stage: String(row.stage || "").trim(),
              started_at_unix_ms: parseOptionalNumber(row, "started_at_unix_ms"),
            };
          }).filter((row) => row.stage)
        : undefined,
      expansion_phase_history: Array.isArray(payload.expansion_phase_history)
        ? payload.expansion_phase_history.map((value) => {
            const row = asObject(value);
            return {
              phase: String(row.phase || "").trim(),
              window: String(row.window || "").trim() || undefined,
              status: String(row.status || "").trim() || "unknown",
              reason: String(row.reason || "").trim() || undefined,
              scope_total_count: parseOptionalNumber(row, "scope_total_count"),
              scope_completed_count: parseOptionalNumber(row, "scope_completed_count"),
              productive_scope_count: parseOptionalNumber(row, "productive_scope_count"),
              module_turn_count: parseOptionalNumber(row, "module_turn_count"),
              budget_allocated_seconds: parseOptionalNumber(row, "budget_allocated_seconds"),
              budget_consumed_seconds: parseOptionalNumber(row, "budget_consumed_seconds"),
              budget_remaining_seconds: parseOptionalNumber(row, "budget_remaining_seconds"),
              logical_turn_budget_seconds: parseOptionalNumber(row, "logical_turn_budget_seconds"),
              actual_elapsed_seconds: parseOptionalNumber(row, "actual_elapsed_seconds"),
              idle_gap_seconds: parseOptionalNumber(row, "idle_gap_seconds"),
              initial_pass_completed:
                row.initial_pass_completed == null ? undefined : Boolean(row.initial_pass_completed),
              coverage_entries_total: parseOptionalNumber(row, "coverage_entries_total"),
              coverage_entries_completed: parseOptionalNumber(row, "coverage_entries_completed"),
              modules_seen_once_count: parseOptionalNumber(row, "modules_seen_once_count"),
              scopes_seen_once_count: parseOptionalNumber(row, "scopes_seen_once_count"),
              started_at_unix_ms: parseOptionalNumber(row, "started_at_unix_ms"),
              ended_at_unix_ms: parseOptionalNumber(row, "ended_at_unix_ms"),
            };
          }).filter((row) => row.phase)
        : undefined,
    };
  }

  async getCycleBundle(tenantId: string, cycleId: string): Promise<Record<string, unknown>> {
    return this.connector.getCycleBundle(tenantId, cycleId, this.requireSession().session_token);
  }

  async listCycles(
    tenantId: string,
    params?: {
      page?: number;
      pageSize?: number;
    },
  ): Promise<Record<string, unknown>> {
    return this.connector.listCycles(
      tenantId,
      this.requireSession().session_token,
      params,
    );
  }

  async getCycleTelemetry(
    tenantId: string,
    cycleId: string,
    params?: {
      recordType?: "all" | "fingerprints" | "posture_signals" | "posture_findings";
      page?: number;
      pageSize?: number;
    },
  ): Promise<Record<string, unknown>> {
    return this.connector.getCycleTelemetry(
      tenantId,
      cycleId,
      this.requireSession().session_token,
      params,
    );
  }

  async getAllCycleTelemetry(
    tenantId: string,
    cycleId: string,
    params?: {
      recordType?: "all" | "fingerprints" | "posture_signals" | "posture_findings";
      pageSize?: number;
      maxPages?: number;
    },
  ): Promise<Record<string, unknown>> {
    const pageSize = Math.max(1, Math.min(Number(params?.pageSize ?? 1000) || 1000, 10_000));
    const maxPages = Math.max(1, Math.min(Number(params?.maxPages ?? 20) || 20, 100));
    const first = await this.getCycleTelemetry(tenantId, cycleId, {
      recordType: params?.recordType,
      page: 1,
      pageSize,
    });
    const total = Number(first.total || 0) || 0;
    const rows = Array.isArray(first.rows) ? [...first.rows] : [];
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    const pagesToFetch = Math.min(totalPages, maxPages);
    for (let page = 2; page <= pagesToFetch; page += 1) {
      const next = await this.getCycleTelemetry(tenantId, cycleId, {
        recordType: params?.recordType,
        page,
        pageSize,
      });
      if (Array.isArray(next.rows)) {
        rows.push(...next.rows);
      }
    }
    return {
      ...first,
      page: 1,
      page_size: pageSize,
      rows,
      fetched_pages: pagesToFetch,
      truncated: totalPages > pagesToFetch,
    };
  }

  async listSimulations(
    tenantId: string,
    params?: { page?: number; pageSize?: number },
  ): Promise<Record<string, unknown>> {
    return this.connector.listSimulations(tenantId, this.requireSession().session_token, params);
  }

  async getSimulationDetail(tenantId: string, simulationId: string): Promise<Record<string, unknown>> {
    return this.connector.getSimulationDetail(
      tenantId,
      simulationId,
      this.requireSession().session_token,
    );
  }

  async listScenarios(): Promise<Record<string, unknown>> {
    return this.connector.listScenarios(this.requireSession().session_token);
  }

  async runSimulation(
    tenantId: string,
    payload: {
      scenario_id: string;
      scenario_params?: Record<string, unknown>;
      path_mode?: string;
    },
  ): Promise<Record<string, unknown>> {
    return this.connector.runSimulation(tenantId, payload, this.requireSession().session_token);
  }

  private parseSession(payload: Record<string, unknown>): SessionState {
    const operatorId = String(payload.operator_id || "").trim();
    const token = String(payload.session_token || "").trim();
    if (!operatorId || !token) {
      throw new Error("invalid session payload");
    }
    const tenantIds = Array.isArray(payload.tenant_ids)
      ? payload.tenant_ids.map((v) => String(v))
      : (String(payload.tenant_id || "").trim() ? [String(payload.tenant_id || "").trim()] : []);
    const tenantId = String(payload.tenant_id || tenantIds[0] || "").trim() || undefined;
    return {
      operator_id: operatorId,
      email: String(payload.email || "").trim() || undefined,
      created_at_unix_ms: Number(payload.created_at_unix_ms || 0) || undefined,
      tenant_id: tenantId,
      tenant_ids: tenantIds,
      role: String(payload.role || "").trim() || undefined,
      session_token: token,
      issued_at_unix_ms: Number(payload.issued_at_unix_ms || 0),
      expires_at_unix_ms: Number(payload.expires_at_unix_ms || 0),
    };
  }

  private requireSession(): SessionState {
    if (!this.session) {
      throw new Error("session required");
    }
    return this.session;
  }
}
