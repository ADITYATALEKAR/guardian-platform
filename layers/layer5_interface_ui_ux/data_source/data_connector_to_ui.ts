export type HttpMethod = "GET" | "POST" | "DELETE";

export interface ApiErrorShape {
  code: string;
  message: string;
}

export interface ApiSuccessEnvelope<T> {
  data: T;
}

export interface ApiErrorEnvelope {
  error: ApiErrorShape;
}

export type ApiEnvelope<T> = ApiSuccessEnvelope<T> | ApiErrorEnvelope;

export interface Layer5RequestOptions {
  query?: Record<string, string | number | boolean | undefined>;
  body?: Record<string, unknown>;
  sessionToken?: string;
  timeoutMs?: number;
}

export class Layer5ApiError extends Error {
  public readonly statusCode: number;
  public readonly code: string;

  constructor(statusCode: number, code: string, message: string) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.name = "Layer5ApiError";
  }
}

type FetchLike = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

export class Layer5ApiConnector {
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;

  constructor(baseUrl: string, fetchImpl?: FetchLike) {
    const normalized = String(baseUrl || "").trim().replace(/\/+$/, "");
    if (!normalized) {
      throw new Error("baseUrl is required");
    }
    this.baseUrl = normalized;
    this.fetchImpl =
      fetchImpl ??
      ((input: RequestInfo | URL, init?: RequestInit) => {
        return globalThis.fetch(input, init);
      });
  }

  async login(operatorId: string, password: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("POST", "/v1/auth/login", {
      body: {
        operator_id: String(operatorId || "").trim(),
        password: String(password || ""),
      },
    });
  }

  async registerAccount(payload: {
    email: string;
    password: string;
    institution_name?: string;
    created_at_unix_ms?: number;
    status?: string;
  }): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("POST", "/v1/auth/register", {
      body: payload,
    });
  }

  async resetPassword(identifier: string, newPassword: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("POST", "/v1/auth/reset-password", {
      body: {
        identifier: String(identifier || "").trim(),
        new_password: String(newPassword || ""),
      },
    });
  }

  async logout(sessionToken: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("POST", "/v1/auth/logout", {
      sessionToken,
    });
  }

  async me(sessionToken: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("GET", "/v1/auth/me", {
      sessionToken,
    });
  }

  async registerOperator(
    payload: {
      operator_id?: string;
      email: string;
      password: string;
      created_at_unix_ms: number;
      tenant_id?: string;
      role?: string;
      master_password?: string;
      status?: string;
    },
    sessionToken?: string,
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("POST", "/v1/admin/operators/register", {
      sessionToken,
      body: payload,
    });
  }

  async registerTenant(
    payload: {
      institution_name: string;
      main_url: string;
      seed_endpoints?: string[];
      password?: string;
      registration_metadata?: Record<string, unknown>;
      created_at_unix_ms?: number;
    },
    sessionToken: string,
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("POST", "/v1/admin/tenants/register", {
      sessionToken,
      body: payload,
    });
  }

  async listUsers(
    sessionToken: string,
    tenantId?: string,
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("GET", "/v1/admin/users", {
      sessionToken,
      query: tenantId ? { tenant_id: tenantId } : undefined,
    });
  }

  async deleteUser(
    operatorId: string,
    sessionToken: string,
    currentPassword: string,
    tenantId?: string,
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      "DELETE",
      `/v1/admin/users/${encodeURIComponent(operatorId)}`,
      {
        sessionToken,
        query: tenantId ? { tenant_id: tenantId } : undefined,
        body: { current_password: currentPassword },
      },
    );
  }

  async changeUserPassword(
    operatorId: string,
    sessionToken: string,
    currentPassword: string,
    newPassword: string,
    tenantId?: string,
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      "POST",
      `/v1/admin/users/${encodeURIComponent(operatorId)}/change-password`,
      {
        sessionToken,
        query: tenantId ? { tenant_id: tenantId } : undefined,
        body: {
          current_password: currentPassword,
          new_password: newPassword,
        },
      },
    );
  }

  async deleteCurrentUser(
    sessionToken: string,
    currentPassword: string,
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("DELETE", "/v1/admin/me", {
      sessionToken,
      body: { current_password: currentPassword },
    });
  }

  async resetWorkspace(
    sessionToken: string,
    currentPassword: string,
    tenantId?: string,
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("POST", "/v1/admin/workspace/reset", {
      sessionToken,
      query: tenantId ? { tenant_id: tenantId } : undefined,
      body: { current_password: currentPassword },
    });
  }

  async onboardAndScan(
    tenantId: string,
    payload: {
      institution_name: string;
      main_url: string;
      seed_endpoints?: string[];
    },
    sessionToken: string,
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      "POST",
      `/v1/tenants/${encodeURIComponent(tenantId)}/onboard-and-scan`,
      {
        sessionToken,
        body: payload,
        timeoutMs: 10 * 60 * 1000,
      },
    );
  }

  async updateProfile(
    payload: {
      tenant_id: string;
      current_password: string;
      email?: string;
      institution_name?: string;
    },
    sessionToken: string,
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("POST", "/v1/admin/profile/update", {
      sessionToken,
      body: payload,
    });
  }

  async changePassword(
    payload: {
      current_password: string;
      new_password: string;
    },
    sessionToken: string,
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      "POST",
      "/v1/admin/credentials/change-password",
      {
        sessionToken,
        body: payload,
      },
    );
  }

  async getDashboard(tenantId: string, sessionToken: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      "GET",
      `/v1/tenants/${encodeURIComponent(tenantId)}/dashboard`,
      { sessionToken },
    );
  }

  async getEndpointPage(
    tenantId: string,
    sessionToken: string,
    params?: {
      page?: number;
      pageSize?: number;
    },
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      "GET",
      `/v1/tenants/${encodeURIComponent(tenantId)}/endpoints`,
      {
        sessionToken,
        query: {
          page: params?.page ?? 1,
          page_size: params?.pageSize ?? 200,
        },
      },
    );
  }

  async getEndpointDetail(
    tenantId: string,
    entityId: string,
    sessionToken: string,
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      "GET",
      `/v1/tenants/${encodeURIComponent(tenantId)}/endpoints/${encodeURIComponent(entityId)}`,
      { sessionToken },
    );
  }

  async getScanStatus(tenantId: string, sessionToken: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      "GET",
      `/v1/tenants/${encodeURIComponent(tenantId)}/scan-status`,
      { sessionToken },
    );
  }

  async getCycleBundle(
    tenantId: string,
    cycleId: string,
    sessionToken: string,
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      "GET",
      `/v1/tenants/${encodeURIComponent(tenantId)}/cycles/${encodeURIComponent(cycleId)}/bundle`,
      { sessionToken, timeoutMs: 60000 },
    );
  }

  async listCycles(
    tenantId: string,
    sessionToken: string,
    params?: {
      page?: number;
      pageSize?: number;
    },
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      "GET",
      `/v1/tenants/${encodeURIComponent(tenantId)}/cycles`,
      {
        sessionToken,
        query: {
          page: params?.page ?? 1,
          page_size: params?.pageSize ?? 200,
        },
      },
    );
  }

  async getCycleTelemetry(
    tenantId: string,
    cycleId: string,
    sessionToken: string,
    params?: {
      recordType?: "all" | "fingerprints" | "posture_signals" | "posture_findings";
      page?: number;
      pageSize?: number;
    },
  ): Promise<Record<string, unknown>> {
    const query = {
      record_type: params?.recordType ?? "all",
      page: params?.page ?? 1,
      page_size: params?.pageSize ?? 500,
    };
    return this.request<Record<string, unknown>>(
      "GET",
      `/v1/tenants/${encodeURIComponent(tenantId)}/cycles/${encodeURIComponent(cycleId)}/telemetry`,
      {
        sessionToken,
        query,
      },
    );
  }

  async listSimulations(
    tenantId: string,
    sessionToken: string,
    params?: {
      page?: number;
      pageSize?: number;
    },
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      "GET",
      `/v1/tenants/${encodeURIComponent(tenantId)}/simulations`,
      {
        sessionToken,
        query: {
          page: params?.page ?? 1,
          page_size: params?.pageSize ?? 100,
        },
      },
    );
  }

  async getSimulationDetail(
    tenantId: string,
    simulationId: string,
    sessionToken: string,
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      "GET",
      `/v1/tenants/${encodeURIComponent(tenantId)}/simulations/${encodeURIComponent(simulationId)}`,
      { sessionToken },
    );
  }

  async listScenarios(sessionToken: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("GET", "/v1/scenarios", {
      sessionToken,
    });
  }

  async runSimulation(
    tenantId: string,
    payload: {
      scenario_id: string;
      scenario_params?: Record<string, unknown>;
      path_mode?: string;
    },
    sessionToken: string,
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      "POST",
      `/v1/tenants/${encodeURIComponent(tenantId)}/simulations`,
      {
        sessionToken,
        body: payload,
        timeoutMs: 5 * 60 * 1000,
      },
    );
  }

  private async request<T>(
    method: HttpMethod,
    path: string,
    options?: Layer5RequestOptions,
  ): Promise<T> {
    const controller = new AbortController();
    const timeoutMs = options?.timeoutMs ?? 30000;
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const url = this.buildUrl(path, options?.query);
      const headers: Record<string, string> = {
        "content-type": "application/json",
      };
      if (options?.sessionToken) {
        headers.authorization = `Bearer ${options.sessionToken}`;
      }

      const response = await this.fetchImpl(url, {
        method,
        headers,
        body: options?.body ? JSON.stringify(options.body) : undefined,
        signal: controller.signal,
      });

      let payload: ApiEnvelope<T> | null = null;
      let rawText = "";
      try {
        rawText = await response.text();
        if (rawText) {
          payload = JSON.parse(rawText) as ApiEnvelope<T>;
        }
      } catch {
        // Fall through; non-JSON error bodies are handled below.
      }

      if (!response.ok) {
        const err = payload && "error" in payload ? payload.error : undefined;
        throw new Layer5ApiError(
          response.status,
          err?.code ?? "http_error",
          err?.message ?? (rawText.trim() || `HTTP ${response.status}`),
        );
      }

      if (!payload || !("data" in payload)) {
        throw new Layer5ApiError(500, "invalid_payload", "missing data envelope");
      }
      return payload.data;
    } catch (error) {
      if (error instanceof Layer5ApiError) {
        throw error;
      }
      if (error instanceof DOMException && error.name === "AbortError") {
        throw new Layer5ApiError(0, "timeout", "request timeout");
      }
      const detail = error instanceof Error && error.message ? ` (${error.message})` : "";
      throw new Layer5ApiError(
        0,
        "network_error",
        `network failure: cannot reach ${this.baseUrl}${detail}`,
      );
    } finally {
      clearTimeout(timeout);
    }
  }

  private buildUrl(path: string, query?: Layer5RequestOptions["query"]): string {
    const p = String(path || "").trim();
    if (!p.startsWith("/")) {
      throw new Error("path must start with '/'");
    }
    const url = new URL(`${this.baseUrl}${p}`);
    for (const [key, value] of Object.entries(query || {})) {
      if (value === undefined || value === null) {
        continue;
      }
      url.searchParams.set(key, String(value));
    }
    return url.toString();
  }
}
