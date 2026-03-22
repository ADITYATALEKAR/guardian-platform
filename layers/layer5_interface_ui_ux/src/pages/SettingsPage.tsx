import { useEffect, useMemo, useState } from "react";
import { Routes, Route, NavLink, Navigate, useNavigate } from "react-router-dom";
import { useSessionStore } from "../stores/useSessionStore";
import { useDashboardStore } from "../stores/useDashboardStore";
import { dataSource } from "../lib/api";
import { formatTimestamp } from "../lib/formatters";
import { Layer5ApiError } from "../../data_source/data_connector_to_ui";
import type { TenantUserSummary } from "../../data_source/master_data_connector_to_layer4";

type ToastState = { type: "success" | "error"; message: string } | null;

function humanizeSettingsError(error: unknown): string {
  if (error instanceof Layer5ApiError) {
    if (error.code === "invalid_credentials") {
      return "Please enter correct password.";
    }
    return error.message;
  }
  return String(error);
}

function Toast({ toast, onDismiss }: { toast: ToastState; onDismiss: () => void }) {
  if (!toast) return null;
  return (
    <div
      style={{
        padding: "8px 12px",
        marginBottom: 12,
        background:
          toast.type === "success"
            ? "var(--color-severity-low)"
            : "var(--color-severity-critical)",
        color: "var(--black)",
        fontFamily: "var(--font-mono)",
        fontSize: "var(--font-size-caption)",
        display: "flex",
        alignItems: "center",
        gap: 8,
      }}
    >
      <span style={{ flex: 1 }}>{toast.message}</span>
      <button
        onClick={onDismiss}
        style={{
          background: "none",
          border: "none",
          cursor: "pointer",
          color: "var(--black)",
          fontWeight: 600,
        }}
      >
        x
      </button>
    </div>
  );
}

const SUB_NAVS = [
  { to: "/settings/profile", label: "Profile" },
  { to: "/settings/security", label: "Security" },
  { to: "/settings/workspace", label: "Workspace" },
  { to: "/settings/admin", label: "Admin" },
];

export function SettingsPage() {
  const session = useSessionStore((s) => s.session);
  const [toast, setToast] = useState<ToastState>(null);
  const canAccessSettings = session?.role === "OWNER" || session?.role === "ADMIN";

  if (!canAccessSettings) {
    return <Navigate to="/dashboard" replace />;
  }

  return (
    <div>
      <div className="g-section-label">Settings</div>

      <div style={{ display: "grid", gridTemplateColumns: "160px 1fr", gap: 16 }}>
        <nav style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          {SUB_NAVS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              style={({ isActive }) => ({
                display: "block",
                padding: "8px 12px",
                fontFamily: "var(--font-mono)",
                fontSize: "var(--font-size-caption)",
                letterSpacing: "0.08em",
                textTransform: "uppercase",
                color: isActive ? "var(--pure)" : "var(--muted)",
                background: isActive ? "var(--surface)" : "transparent",
                borderLeft: isActive ? "2px solid var(--pure)" : "2px solid transparent",
                textDecoration: "none",
                cursor: "pointer",
              })}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div>
          <Toast toast={toast} onDismiss={() => setToast(null)} />
          <Routes>
            <Route index element={<Navigate to="profile" replace />} />
            <Route path="profile" element={<ProfileTab onToast={setToast} />} />
            <Route path="security" element={<SecurityTab onToast={setToast} />} />
            <Route path="workspace" element={<WorkspaceTab onToast={setToast} />} />
            <Route path="admin" element={<AdminTab onToast={setToast} />} />
          </Routes>
        </div>
      </div>
    </div>
  );
}

function ProfileTab({ onToast }: { onToast: (t: ToastState) => void }) {
  const session = useSessionStore((s) => s.session);
  const logout = useSessionStore((s) => s.logout);
  const tenantId = useSessionStore((s) => s.activeTenantId);
  const clearDashboard = useDashboardStore((s) => s.clear);
  const navigate = useNavigate();

  const [email, setEmail] = useState(session?.email ?? "");
  const [institutionName, setInstitutionName] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [deletePassword, setDeletePassword] = useState("");
  const [deleteBusy, setDeleteBusy] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!tenantId || !currentPassword) {
      onToast({ type: "error", message: "Current password is required." });
      return;
    }
    setBusy(true);
    try {
      await dataSource.updateProfile({
        tenant_id: tenantId,
        current_password: currentPassword,
        ...(email ? { email } : {}),
        ...(institutionName ? { institution_name: institutionName } : {}),
      });
      onToast({ type: "success", message: "Profile updated successfully." });
      setCurrentPassword("");
    } catch (err) {
      onToast({ type: "error", message: String(err) });
    } finally {
      setBusy(false);
    }
  }

  async function handleDeleteAccount(e: React.FormEvent) {
    e.preventDefault();
    if (!deletePassword) {
      onToast({ type: "error", message: "Current password is required." });
      return;
    }
    setDeleteBusy(true);
    try {
      await dataSource.deleteCurrentUser(deletePassword);
      clearDashboard();
      await logout();
      navigate("/login", { replace: true });
    } catch (err) {
      onToast({ type: "error", message: humanizeSettingsError(err) });
    } finally {
      setDeleteBusy(false);
    }
  }

  return (
    <div>
      <SectionTitle label="Profile" />

      <div
        style={{
          marginBottom: 16,
          padding: "8px 12px",
          background: "var(--panel)",
          border: "1px solid var(--border)",
        }}
      >
        <FieldReadOnly label="User ID" value={session?.operator_id ?? "-"} />
        <FieldReadOnly label="Tenant ID" value={tenantId ?? "-"} />
        <FieldReadOnly label="Email" value={session?.email ?? "-"} />
        <FieldReadOnly label="Role" value={session?.role ?? "-"} />
      </div>

      <form
        onSubmit={handleSubmit}
        style={{ display: "flex", flexDirection: "column", gap: 12, maxWidth: 400 }}
      >
        <FormField label="Email" type="email" value={email} onChange={setEmail} placeholder="New email" />
        <FormField
          label="Institution Name"
          type="text"
          value={institutionName}
          onChange={setInstitutionName}
          placeholder="New institution name"
        />
        <FormField
          label="Current Password"
          type="password"
          value={currentPassword}
          onChange={setCurrentPassword}
          placeholder="Required to confirm changes"
          required
        />
        <button
          className="btn btn-small btn-primary"
          type="submit"
          disabled={busy}
          style={{ alignSelf: "flex-start" }}
        >
          {busy ? "Updating..." : "Update Profile"}
        </button>
      </form>

      <div
        style={{
          marginTop: 20,
          padding: "12px",
          background: "var(--panel)",
          border: "1px solid var(--border)",
          maxWidth: 460,
        }}
      >
        <SectionTitle label="Delete My Account" compact />
        <div
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "var(--font-size-caption)",
            color: "var(--muted)",
            marginBottom: 12,
          }}
        >
          This deletes your user account, removes its tenant link, and signs you out. Workspace data is retained.
        </div>
        <form
          onSubmit={handleDeleteAccount}
          style={{ display: "flex", flexDirection: "column", gap: 12 }}
        >
          <FormField
            label="Current Password"
            type="password"
            value={deletePassword}
            onChange={setDeletePassword}
            placeholder="Required to confirm account deletion"
            required
          />
          <button
            className="btn btn-small btn-neutral"
            type="submit"
            disabled={deleteBusy}
            style={{ alignSelf: "flex-start" }}
          >
            {deleteBusy ? "Deleting..." : "Delete My Account"}
          </button>
        </form>
      </div>
    </div>
  );
}

function SecurityTab({ onToast }: { onToast: (t: ToastState) => void }) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!currentPassword || !newPassword) {
      onToast({ type: "error", message: "All fields are required." });
      return;
    }
    if (newPassword !== confirmPassword) {
      onToast({ type: "error", message: "New passwords do not match." });
      return;
    }
    if (newPassword.length < 12) {
      onToast({ type: "error", message: "Password must be at least 12 characters." });
      return;
    }
    setBusy(true);
    try {
      await dataSource.changePassword({ current_password: currentPassword, new_password: newPassword });
      onToast({ type: "success", message: "Password changed successfully." });
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } catch (err) {
      onToast({ type: "error", message: String(err) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <SectionTitle label="Change Password" />
      <form
        onSubmit={handleSubmit}
        style={{ display: "flex", flexDirection: "column", gap: 12, maxWidth: 400 }}
      >
        <FormField label="Current Password" type="password" value={currentPassword} onChange={setCurrentPassword} required />
        <FormField label="New Password" type="password" value={newPassword} onChange={setNewPassword} required />
        <FormField label="Confirm New Password" type="password" value={confirmPassword} onChange={setConfirmPassword} required />
        <button
          className="btn btn-small btn-primary"
          type="submit"
          disabled={busy}
          style={{ alignSelf: "flex-start" }}
        >
          {busy ? "Changing..." : "Change Password"}
        </button>
      </form>
    </div>
  );
}

function WorkspaceTab({ onToast }: { onToast: (t: ToastState) => void }) {
  const navigate = useNavigate();
  const session = useSessionStore((s) => s.session);
  const tenantId = useSessionStore((s) => s.activeTenantId);
  const dashboard = useDashboardStore((s) => s.data);
  const clearDashboard = useDashboardStore((s) => s.clear);
  const ws = dashboard?.workspace;
  const [currentPassword, setCurrentPassword] = useState("");
  const [busy, setBusy] = useState(false);

  async function handleResetWorkspace(e: React.FormEvent) {
    e.preventDefault();
    if (!tenantId) {
      onToast({ type: "error", message: "Tenant context is required." });
      return;
    }
    if (!currentPassword) {
      onToast({ type: "error", message: "Current password is required to reset the workspace." });
      return;
    }
    setBusy(true);
    try {
      await dataSource.resetWorkspace(currentPassword, tenantId);
      clearDashboard();
      onToast({ type: "success", message: "Workspace reset. Complete onboarding to start a fresh scan." });
      setCurrentPassword("");
      navigate("/onboarding");
    } catch (err) {
      onToast({ type: "error", message: String(err) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <SectionTitle label="Workspace" />
      <div
        style={{
          padding: "8px 12px",
          background: "var(--panel)",
          border: "1px solid var(--border)",
          display: "flex",
          flexDirection: "column",
          gap: 8,
        }}
      >
        <FieldReadOnly label="Institution" value={ws?.institution_name || "-"} />
        <FieldReadOnly label="Main URL" value={ws?.main_url || "-"} />
        <FieldReadOnly label="Onboarding Status" value={ws?.onboarding_status || "-"} />
        <FieldReadOnly label="Seed Endpoints" value={String(ws?.seed_count ?? "-")} />
      </div>

      {session?.role === "OWNER" && tenantId && (
        <div
          style={{
            marginTop: 16,
            padding: "12px",
            background: "var(--panel)",
            border: "1px solid var(--border)",
            maxWidth: 460,
          }}
        >
          <SectionTitle label="Reset Workspace" compact />
          <div
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "var(--font-size-caption)",
              color: "var(--muted)",
              marginBottom: 12,
            }}
          >
            This clears scans, telemetry, cycles, guardian output, and simulation data for this tenant. User accounts and the tenant ID stay the same.
          </div>
          <form
            onSubmit={handleResetWorkspace}
            style={{ display: "flex", flexDirection: "column", gap: 12 }}
          >
            <FormField
              label="Current Password"
              type="password"
              value={currentPassword}
              onChange={setCurrentPassword}
              placeholder="Required to confirm reset"
              required
            />
            <button
              className="btn btn-small btn-neutral"
              type="submit"
              disabled={busy}
              style={{ alignSelf: "flex-start" }}
            >
              {busy ? "Resetting..." : "Reset Workspace"}
            </button>
          </form>
        </div>
      )}
    </div>
  );
}

function AdminTab({ onToast }: { onToast: (t: ToastState) => void }) {
  const session = useSessionStore((s) => s.session);
  const tenantId = useSessionStore((s) => s.activeTenantId);
  const [users, setUsers] = useState<TenantUserSummary[]>([]);
  const [loadingUsers, setLoadingUsers] = useState(false);

  const canManageUsers = session?.role === "OWNER";

  const refreshUsers = async () => {
    if (!tenantId || !canManageUsers) {
      setUsers([]);
      return;
    }
    setLoadingUsers(true);
    try {
      const nextUsers = await dataSource.listUsers(tenantId);
      setUsers(
        [...nextUsers].sort((left, right) => {
          const leftRank = roleRank(left.role);
          const rightRank = roleRank(right.role);
          if (leftRank !== rightRank) return leftRank - rightRank;
          return left.operator_id.localeCompare(right.operator_id);
        }),
      );
    } catch (err) {
      onToast({ type: "error", message: String(err) });
    } finally {
      setLoadingUsers(false);
    }
  };

  useEffect(() => {
    void refreshUsers();
  }, [tenantId, canManageUsers]);

  return (
    <div>
      <SectionTitle label="Administration" />

      {!tenantId && (
        <InfoPanel message="Tenant context is required before user management is available." />
      )}

      {tenantId && !canManageUsers && (
        <InfoPanel message="Only the tenant owner can add or remove users." />
      )}

      {tenantId && canManageUsers && (
        <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
          <AddUserForm tenantId={tenantId} onToast={onToast} onUserAdded={refreshUsers} />
          <TenantUsersPanel
            currentOperatorId={session?.operator_id ?? ""}
            loading={loadingUsers}
            onRefresh={refreshUsers}
            onToast={onToast}
            tenantId={tenantId}
            users={users}
          />
        </div>
      )}
    </div>
  );
}

function AddUserForm({
  tenantId,
  onToast,
  onUserAdded,
}: {
  tenantId: string;
  onToast: (t: ToastState) => void;
  onUserAdded: () => Promise<void>;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [role, setRole] = useState<"ADMIN" | "MEMBER">("MEMBER");
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!email || !password || !confirmPassword) {
      onToast({ type: "error", message: "All fields are required." });
      return;
    }
    if (password !== confirmPassword) {
      onToast({ type: "error", message: "Passwords do not match." });
      return;
    }
    if (password.length < 12) {
      onToast({ type: "error", message: "Password must be at least 12 characters." });
      return;
    }
    setBusy(true);
    try {
      const created = await dataSource.registerOperator({
        email,
        password,
        created_at_unix_ms: Date.now(),
        tenant_id: tenantId,
        role,
      });
      const createdOperatorId =
        String(
          (created && typeof created === "object" ? (created as Record<string, unknown>).operator_id : "") || "",
        ).trim() || "new user";
      onToast({ type: "success", message: `User "${createdOperatorId}" added to this tenant.` });
      setEmail("");
      setPassword("");
      setConfirmPassword("");
      setRole("MEMBER");
      await onUserAdded();
    } catch (err) {
      onToast({ type: "error", message: humanizeSettingsError(err) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ padding: 12, background: "var(--panel)", border: "1px solid var(--border)" }}>
      <SectionTitle label="Add User" compact />
      <form
        onSubmit={handleSubmit}
        style={{ display: "flex", flexDirection: "column", gap: 10, maxWidth: 400 }}
      >
        <FormField label="Email" type="email" value={email} onChange={setEmail} required />
        <FormField label="Password" type="password" value={password} onChange={setPassword} required />
        <FormField
          label="Confirm Password"
          type="password"
          value={confirmPassword}
          onChange={setConfirmPassword}
          required
        />
        <SelectField
          label="Authority"
          value={role}
          onChange={(value) => setRole(value === "ADMIN" ? "ADMIN" : "MEMBER")}
          options={[
            { value: "ADMIN", label: "Admin" },
            { value: "MEMBER", label: "Member" },
          ]}
        />
        <button
          className="btn btn-small btn-primary"
          type="submit"
          disabled={busy}
          style={{ alignSelf: "flex-start" }}
        >
          {busy ? "Adding..." : "Add User"}
        </button>
      </form>
    </div>
  );
}

function TenantUsersPanel({
  currentOperatorId,
  loading,
  onRefresh,
  onToast,
  tenantId,
  users,
}: {
  currentOperatorId: string;
  loading: boolean;
  onRefresh: () => Promise<void>;
  onToast: (t: ToastState) => void;
  tenantId: string;
  users: TenantUserSummary[];
}) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [deletingOperatorId, setDeletingOperatorId] = useState<string | null>(null);
  const [changingOperatorId, setChangingOperatorId] = useState<string | null>(null);
  const [passwordDrafts, setPasswordDrafts] = useState<
    Record<string, { newPassword: string; confirmPassword: string }>
  >({});

  const visibleUsers = useMemo(
    () => users.filter((user) => user.operator_id),
    [users],
  );

  function updatePasswordDraft(
    operatorId: string,
    field: "newPassword" | "confirmPassword",
    value: string,
  ) {
    setPasswordDrafts((current) => ({
      ...current,
      [operatorId]: {
        newPassword: current[operatorId]?.newPassword ?? "",
        confirmPassword: current[operatorId]?.confirmPassword ?? "",
        [field]: value,
      },
    }));
  }

  async function handleDelete(targetOperatorId: string) {
    if (!currentPassword) {
      onToast({ type: "error", message: "Current password is required to manage users." });
      return;
    }
    if (targetOperatorId === currentOperatorId) {
      onToast({ type: "error", message: "Delete your own account in a dedicated account flow, not from user management." });
      return;
    }
    setDeletingOperatorId(targetOperatorId);
    try {
      await dataSource.deleteUser(targetOperatorId, currentPassword, tenantId);
      onToast({ type: "success", message: `User "${targetOperatorId}" deleted.` });
      setCurrentPassword("");
      await onRefresh();
    } catch (err) {
      onToast({ type: "error", message: humanizeSettingsError(err) });
    } finally {
      setDeletingOperatorId(null);
    }
  }

  async function handleChangePassword(targetOperatorId: string) {
    if (!currentPassword) {
      onToast({ type: "error", message: "Current password is required to manage users." });
      return;
    }
    const draft = passwordDrafts[targetOperatorId] ?? { newPassword: "", confirmPassword: "" };
    if (!draft.newPassword || !draft.confirmPassword) {
      onToast({ type: "error", message: "New password and confirm password are required." });
      return;
    }
    if (draft.newPassword !== draft.confirmPassword) {
      onToast({ type: "error", message: "Passwords do not match." });
      return;
    }
    if (draft.newPassword.length < 12) {
      onToast({ type: "error", message: "Password must be at least 12 characters." });
      return;
    }
    if (targetOperatorId === currentOperatorId) {
      onToast({ type: "error", message: "Use the Security tab to change your own password." });
      return;
    }
    setChangingOperatorId(targetOperatorId);
    try {
      await dataSource.changeUserPassword(targetOperatorId, currentPassword, draft.newPassword, tenantId);
      onToast({ type: "success", message: `Password changed for "${targetOperatorId}".` });
      setCurrentPassword("");
      setPasswordDrafts((current) => ({
        ...current,
        [targetOperatorId]: { newPassword: "", confirmPassword: "" },
      }));
    } catch (err) {
      onToast({ type: "error", message: humanizeSettingsError(err) });
    } finally {
      setChangingOperatorId(null);
    }
  }

  return (
    <div style={{ padding: 12, background: "var(--panel)", border: "1px solid var(--border)" }}>
      <SectionTitle label="Users" compact />
      <div style={{ marginBottom: 12, maxWidth: 400 }}>
        <FormField
          label="Current Password"
          type="password"
          value={currentPassword}
          onChange={setCurrentPassword}
          placeholder="Required to manage users"
        />
      </div>

      {loading ? (
        <div style={{ fontFamily: "var(--font-mono)", color: "var(--muted)", fontSize: "var(--font-size-caption)" }}>
          Loading users...
        </div>
      ) : visibleUsers.length === 0 ? (
        <div style={{ fontFamily: "var(--font-mono)", color: "var(--muted)", fontSize: "var(--font-size-caption)" }}>
          No additional users are linked to this tenant yet.
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {visibleUsers.map((user) => {
            const isCurrentUser = user.operator_id === currentOperatorId;
            return (
              <div
                key={user.operator_id}
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: 12,
                  padding: "10px 12px",
                  background: "var(--surface)",
                  border: "1px solid var(--border)",
                }}
              >
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "minmax(0, 1.4fr) minmax(0, 1.4fr) 120px 160px auto",
                    gap: 12,
                    alignItems: "center",
                  }}
                >
                  <div>
                    <div style={userPrimaryStyle}>{user.operator_id}</div>
                    {isCurrentUser && <div style={userMetaStyle}>Current user</div>}
                  </div>
                  <div style={userPrimaryStyle}>{user.email || "-"}</div>
                  <div style={userPrimaryStyle}>{user.role || "-"}</div>
                  <div style={userMetaStyle}>{formatTimestamp(user.created_at_unix_ms)}</div>
                  <button
                    className="btn btn-small btn-neutral"
                    type="button"
                    disabled={isCurrentUser || deletingOperatorId === user.operator_id}
                    onClick={() => void handleDelete(user.operator_id)}
                    style={{ justifySelf: "start" }}
                  >
                    {deletingOperatorId === user.operator_id ? "Deleting..." : "Delete User"}
                  </button>
                </div>
                {!isCurrentUser && (
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1fr) auto",
                      gap: 12,
                      alignItems: "end",
                    }}
                  >
                    <FormField
                      label="New Password"
                      type="password"
                      value={passwordDrafts[user.operator_id]?.newPassword ?? ""}
                      onChange={(value) => updatePasswordDraft(user.operator_id, "newPassword", value)}
                      placeholder="Set a new password"
                    />
                    <FormField
                      label="Confirm Password"
                      type="password"
                      value={passwordDrafts[user.operator_id]?.confirmPassword ?? ""}
                      onChange={(value) => updatePasswordDraft(user.operator_id, "confirmPassword", value)}
                      placeholder="Confirm the new password"
                    />
                    <button
                      className="btn btn-small btn-primary"
                      type="button"
                      disabled={changingOperatorId === user.operator_id}
                      onClick={() => void handleChangePassword(user.operator_id)}
                      style={{ justifySelf: "start" }}
                    >
                      {changingOperatorId === user.operator_id ? "Changing..." : "Change Password"}
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function InfoPanel({ message }: { message: string }) {
  return (
    <div
      style={{
        padding: "10px 12px",
        background: "var(--panel)",
        border: "1px solid var(--border)",
        fontFamily: "var(--font-mono)",
        fontSize: "var(--font-size-caption)",
        color: "var(--muted)",
      }}
    >
      {message}
    </div>
  );
}

function SectionTitle({ label, compact = false }: { label: string; compact?: boolean }) {
  return (
    <div
      style={{
        fontFamily: "var(--font-mono)",
        fontSize: "var(--font-size-label)",
        color: "var(--muted)",
        textTransform: "uppercase",
        letterSpacing: "0.2em",
        marginBottom: compact ? 8 : 12,
      }}
    >
      {label}
    </div>
  );
}

function FormField({
  label,
  type,
  value,
  onChange,
  placeholder,
  required,
}: {
  label: string;
  type: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  required?: boolean;
}) {
  return (
    <div>
      <label
        style={{
          fontFamily: "var(--font-mono)",
          fontSize: "var(--font-size-label)",
          color: "var(--muted)",
          textTransform: "uppercase",
          letterSpacing: "0.1em",
          display: "block",
          marginBottom: 4,
        }}
      >
        {label}
      </label>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        required={required}
        style={{
          width: "100%",
          padding: "6px 8px",
          background: "var(--black)",
          border: "1px solid var(--border)",
          color: "var(--white)",
          fontFamily: "var(--font-mono)",
          fontSize: "var(--font-size-caption)",
        }}
      />
    </div>
  );
}

function SelectField({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: Array<{ value: string; label: string }>;
}) {
  return (
    <div>
      <label
        style={{
          fontFamily: "var(--font-mono)",
          fontSize: "var(--font-size-label)",
          color: "var(--muted)",
          textTransform: "uppercase",
          letterSpacing: "0.1em",
          display: "block",
          marginBottom: 4,
        }}
      >
        {label}
      </label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={{
          width: "100%",
          padding: "6px 8px",
          background: "var(--black)",
          border: "1px solid var(--border)",
          color: "var(--white)",
          fontFamily: "var(--font-mono)",
          fontSize: "var(--font-size-caption)",
        }}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  );
}

function FieldReadOnly({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: "flex", gap: 12, alignItems: "baseline" }}>
      <span
        style={{
          fontFamily: "var(--font-mono)",
          fontSize: "var(--font-size-label)",
          color: "var(--muted)",
          textTransform: "uppercase",
          letterSpacing: "0.1em",
          minWidth: 120,
        }}
      >
        {label}
      </span>
      <span
        style={{
          fontFamily: "var(--font-mono)",
          fontSize: "var(--font-size-caption)",
          color: "var(--ghost)",
          wordBreak: "break-all",
        }}
      >
        {value}
      </span>
    </div>
  );
}

function roleRank(role?: string): number {
  switch ((role || "").toUpperCase()) {
    case "OWNER":
      return 0;
    case "ADMIN":
      return 1;
    case "MEMBER":
      return 2;
    default:
      return 3;
  }
}

const userPrimaryStyle = {
  fontFamily: "var(--font-mono)",
  fontSize: "var(--font-size-caption)",
  color: "var(--ghost)",
  wordBreak: "break-all" as const,
};

const userMetaStyle = {
  fontFamily: "var(--font-mono)",
  fontSize: "var(--font-size-label)",
  color: "var(--muted)",
  letterSpacing: "0.08em",
  textTransform: "uppercase" as const,
};

const settingsPanelStyle = {
  padding: "12px",
  background: "var(--panel)",
  border: "1px solid var(--border)",
  display: "flex",
  flexDirection: "column" as const,
  gap: 12,
  marginBottom: 16,
};

const settingsListStyle = {
  display: "flex",
  flexDirection: "column" as const,
  gap: 8,
};

const settingsCardStyle = {
  padding: "12px",
  background: "var(--panel)",
  border: "1px solid var(--border)",
  display: "flex",
  flexDirection: "column" as const,
  gap: 10,
};

const settingsCardHeaderStyle = {
  display: "flex",
  alignItems: "flex-start",
  gap: 12,
};

const settingsToolbarStyle = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: 12,
  flexWrap: "wrap" as const,
};

const settingsCardTextStyle = {
  fontFamily: "var(--font-mono)",
  fontSize: "var(--font-size-caption)",
  color: "var(--white)",
  whiteSpace: "pre-wrap" as const,
  wordBreak: "break-word" as const,
};

const settingsIntroStyle = {
  fontFamily: "var(--font-mono)",
  fontSize: "var(--font-size-caption)",
  color: "var(--muted)",
  lineHeight: 1.6,
};

const settingsMetaStyle = {
  fontFamily: "var(--font-mono)",
  fontSize: "var(--font-size-label)",
  color: "var(--muted)",
  letterSpacing: "0.08em",
  textTransform: "uppercase" as const,
};

const settingsTextareaStyle = {
  width: "100%",
  padding: "8px 10px",
  background: "var(--black)",
  border: "1px solid var(--border)",
  color: "var(--white)",
  fontFamily: "var(--font-mono)",
  fontSize: "var(--font-size-caption)",
  resize: "vertical" as const,
  minHeight: 88,
};

const settingsPillStyle = {
  border: "1px solid var(--border)",
  padding: "4px 8px",
  fontFamily: "var(--font-mono)",
  fontSize: "var(--font-size-label)",
  color: "var(--ghost)",
  textTransform: "uppercase" as const,
  letterSpacing: "0.08em",
};
