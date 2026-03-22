import { create } from "zustand";
import { dataSource, Layer5ApiError } from "../lib/api";
import type { SessionState } from "../lib/api";

const STORAGE_KEY = "guardian_session";

interface SessionStore {
  session: SessionState | null;
  activeTenantId: string | null;
  busy: boolean;
  error: { code: string; message: string } | null;

  login: (identifier: string, password: string) => Promise<void>;
  register: (payload: {
    email: string;
    password: string;
    institution_name?: string;
  }) => Promise<{ tenant_id?: string }>;
  logout: () => Promise<void>;
  setActiveTenant: (tenantId: string) => void;
  restoreSession: () => void;
  clearError: () => void;
}

function persistSession(session: SessionState | null, tenantId: string | null) {
  if (session) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ session, tenantId }));
  } else {
    localStorage.removeItem(STORAGE_KEY);
  }
}

export const useSessionStore = create<SessionStore>((set, get) => ({
  session: null,
  activeTenantId: null,
  busy: false,
  error: null,

  login: async (identifier, password) => {
    set({ busy: true, error: null });
    try {
      const session = await dataSource.login(identifier, password);
      const tenantId = session.tenant_id ?? session.tenant_ids[0] ?? null;
      persistSession(session, tenantId);
      set({ session, activeTenantId: tenantId, busy: false });
    } catch (err) {
      const e = err instanceof Layer5ApiError
        ? { code: err.code, message: err.message }
        : { code: "unknown", message: String(err) };
      set({ busy: false, error: e });
      throw err;
    }
  },

  register: async (payload) => {
    set({ busy: true, error: null });
    try {
      const result = await dataSource.registerAccount(payload);
      set({ busy: false });
      const tenantId = typeof result.tenant_id === "string" ? result.tenant_id : undefined;
      return { tenant_id: tenantId };
    } catch (err) {
      const e = err instanceof Layer5ApiError
        ? { code: err.code, message: err.message }
        : { code: "unknown", message: String(err) };
      set({ busy: false, error: e });
      throw err;
    }
  },

  logout: async () => {
    try {
      await dataSource.logout();
    } catch {
      // Ignore logout errors
    }
    persistSession(null, null);
    set({ session: null, activeTenantId: null, error: null });
  },

  setActiveTenant: (tenantId) => {
    const { session } = get();
    if (session?.tenant_id && tenantId !== session.tenant_id) {
      return;
    }
    persistSession(session, tenantId);
    set({ activeTenantId: tenantId });
  },

  restoreSession: () => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      const data = JSON.parse(raw);
      if (data?.session?.session_token && data?.session?.operator_id) {
        // Restore into data source
        (dataSource as any).session = data.session;
        const restoredTenantId =
          data.tenantId ?? data.session.tenant_id ?? data.session.tenant_ids?.[0] ?? null;
        set({
          session: data.session,
          activeTenantId: restoredTenantId,
        });
      }
    } catch {
      localStorage.removeItem(STORAGE_KEY);
    }
  },

  clearError: () => set({ error: null }),
}));
