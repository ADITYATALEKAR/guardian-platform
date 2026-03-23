import { useEffect, useMemo, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useSessionStore } from "../stores/useSessionStore";
import { dataSource, Layer5ApiError, type ScanStatus } from "../lib/api";

export function OnboardingPage() {
  const navigate = useNavigate();
  const tenantId = useSessionStore((s) => s.activeTenantId);

  const [institutionName, setInstitutionName] = useState("");
  const [mainUrl, setMainUrl] = useState("");
  const [seedEndpoints, setSeedEndpoints] = useState("");
  const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scanRunning = scanStatus?.status === "running";
  const scanCompleted = scanStatus?.status === "completed";
  const scanStatusText = useMemo(() => {
    if (!scanRunning) return null;
    const cycleId = scanStatus?.cycle_id || "-";
    const stage = String(scanStatus?.stage || "running")
      .split("_")
      .map((part) => (part ? part[0].toUpperCase() + part.slice(1) : part))
      .join(" ");
    const elapsedSeconds = Math.max(0, Math.floor((scanStatus?.elapsed_ms ?? 0) / 1000));
    const pieces = [`Cycle ${cycleId} is already running (${stage}, ${elapsedSeconds}s elapsed).`];

    if (scanStatus?.expansion_window) {
      pieces.push(`Window: ${scanStatus.expansion_window}`);
    }
    if (scanStatus?.expansion_pass_type) {
      pieces.push(`Pass: ${scanStatus.expansion_pass_type}`);
    }
    if (scanStatus?.expansion_active_category || scanStatus?.expansion_current_module) {
      const category = scanStatus?.expansion_active_category || "Expansion";
      const moduleName = scanStatus?.expansion_current_module || "starting";
      pieces.push(`${category}: ${moduleName}`);
    }
    if (
      typeof scanStatus?.coverage_entries_completed === "number" ||
      typeof scanStatus?.coverage_entries_total === "number"
    ) {
      pieces.push(
        `Coverage: ${scanStatus?.coverage_entries_completed ?? "-"} / ${scanStatus?.coverage_entries_total ?? "-"}`,
      );
    }
    if (
      typeof scanStatus?.expansion_scope_index === "number" ||
      typeof scanStatus?.expansion_scope_total_count === "number"
    ) {
      pieces.push(
        `Scope: ${scanStatus?.expansion_scope_index ?? "-"} / ${scanStatus?.expansion_scope_total_count ?? "-"}`,
      );
    }
    if (
      typeof scanStatus?.expansion_module_turn_index === "number" ||
      typeof scanStatus?.expansion_module_turns_completed === "number"
    ) {
      const turnIndex = scanStatus?.expansion_module_turn_index;
      const turnsCompleted = scanStatus?.expansion_module_turns_completed;
      const totalTurns = scanStatus?.expansion_module_total_count;
      pieces.push(
        typeof turnIndex === "number" && typeof totalTurns === "number"
          ? `Turns: ${turnIndex}/${totalTurns}`
          : `Turns completed: ${turnsCompleted ?? "-"}`,
      );
    }
    if (
      typeof scanStatus?.expansion_modules_completed_count === "number" ||
      typeof scanStatus?.expansion_module_total_count === "number"
    ) {
      const completed = scanStatus?.expansion_modules_completed_count;
      const total = scanStatus?.expansion_module_total_count;
      pieces.push(
        typeof completed === "number" && typeof total === "number"
          ? `Modules: ${completed}/${total}`
          : `Modules: ${completed ?? "-"}`,
      );
    }
    if (typeof scanStatus?.expansion_graph_endpoint_count === "number") {
      pieces.push(`Graph endpoints: ${scanStatus.expansion_graph_endpoint_count}`);
    }
    if (typeof scanStatus?.expansion_node_count === "number" && typeof scanStatus?.expansion_edge_count === "number") {
      pieces.push(`Graph: ${scanStatus.expansion_node_count} nodes / ${scanStatus.expansion_edge_count} edges`);
    }
    if (typeof scanStatus?.expanded_candidate_count === "number") {
      pieces.push(`Candidates: ${scanStatus.expanded_candidate_count}`);
    }
    if (typeof scanStatus?.discovered_related_count_live === "number") {
      pieces.push(`Live related: ${scanStatus.discovered_related_count_live}`);
    }
    if (typeof scanStatus?.inflight_candidate_count === "number") {
      pieces.push(`In-flight endpoints: ${scanStatus.inflight_candidate_count}`);
    }
    if (typeof scanStatus?.observation_target_count === "number") {
      pieces.push(`Observation target: ${scanStatus.observation_target_count}`);
    }
    if (typeof scanStatus?.observed_completed_count === "number") {
      const total = scanStatus.observation_target_count;
      pieces.push(
        typeof total === "number"
          ? `Observed: ${scanStatus.observed_completed_count}/${total}`
          : `Observed: ${scanStatus.observed_completed_count}`,
      );
    }
    if (typeof scanStatus?.stage_estimated_remaining_ms === "number") {
      pieces.push(`Stage remaining: ${Math.max(0, Math.floor(scanStatus.stage_estimated_remaining_ms / 1000))}s`);
    }
    if (typeof scanStatus?.cycle_budget_remaining_ms === "number") {
      pieces.push(`Cycle remaining: ${Math.max(0, Math.floor(scanStatus.cycle_budget_remaining_ms / 1000))}s`);
    }
    if (scanStatus?.progress_channel_degraded) {
      const warningCount =
        typeof scanStatus?.lock_write_warning_count === "number"
          ? ` (${scanStatus.lock_write_warning_count})`
          : "";
      pieces.push(`Progress channel degraded${warningCount}`);
      if (scanStatus?.last_lock_write_error) {
        pieces.push(`Lock warning: ${scanStatus.last_lock_write_error}`);
      }
    }

    return pieces.join(" ");
  }, [scanRunning, scanStatus]);

  useEffect(() => {
    if (!tenantId) return;
    let cancelled = false;

    const hydrate = async () => {
      try {
        const raw = await dataSource.getDashboard(tenantId);
        const workspace =
          raw && typeof raw.workspace === "object" && raw.workspace
            ? (raw.workspace as Record<string, unknown>)
            : {};
        const savedInstitutionName = String(workspace.institution_name || "").trim();
        const savedMainUrl = String(workspace.main_url || "").trim();
        const savedSeeds = Array.isArray(workspace.seed_endpoints)
          ? workspace.seed_endpoints
              .map((row) => String(row || "").trim())
              .filter(Boolean)
          : [];

        if (cancelled) return;
        setInstitutionName((prev) => prev || savedInstitutionName);
        setMainUrl((prev) => prev || savedMainUrl);
        setSeedEndpoints((prev) => prev || savedSeeds.join("\n"));
      } catch {
        // Ignore hydration failures; the form remains editable.
      }
    };

    void hydrate();
    return () => {
      cancelled = true;
    };
  }, [tenantId]);

  useEffect(() => {
    if (!tenantId) {
      setScanStatus(null);
      return;
    }

    let cancelled = false;
    let timer: number | undefined;

    const poll = async () => {
      try {
        const nextStatus = await dataSource.getScanStatus(tenantId);
        if (!cancelled) {
          setScanStatus(nextStatus);
        }
      } catch {
        if (!cancelled) {
          setScanStatus(null);
        }
      } finally {
        if (!cancelled) {
          timer = window.setTimeout(poll, 10000);
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
  }, [tenantId]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!tenantId || !mainUrl.trim()) return;
    if (scanRunning) {
      setError("A discovery scan is already running. Please wait for it to finish.");
      return;
    }

    setBusy(true);
    setError(null);
    try {
      const seeds = seedEndpoints
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);

      await dataSource.onboardAndScan(tenantId, {
        institution_name: institutionName.trim(),
        main_url: mainUrl.trim(),
        seed_endpoints: seeds.length > 0 ? seeds : undefined,
      });

      navigate("/dashboard");
    } catch (err) {
      if (err instanceof Layer5ApiError) {
        if (err.code === "timeout") {
          setError("Discovery scan started and is still running. Please wait, then refresh the dashboard.");
        } else if (String(err.message || "").toLowerCase().includes("active cycle already running")) {
          setError("A discovery scan is already running. Please wait for it to finish, then refresh the dashboard.");
        } else {
          setError(err.message);
        }
      } else {
        setError(String(err));
      }
    } finally {
      setBusy(false);
    }
  };

  if (!tenantId) {
    return (
      <div className="g-empty">No tenant selected. Please register first.</div>
    );
  }

  // Scan already completed — redirect to dashboard instead of showing the form again.
  if (scanCompleted) {
    return (
      <div style={{ maxWidth: 560, margin: "0 auto" }}>
        <div
          style={{
            fontFamily: "var(--font-display)",
            fontSize: "var(--font-size-h2)",
            fontWeight: 800,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            color: "var(--pure)",
            marginBottom: 8,
          }}
        >
          Workspace Setup
        </div>
        <div
          style={{
            padding: "8px 12px",
            marginBottom: 16,
            background: "rgba(34, 197, 94, 0.08)",
            border: "1px solid rgba(34, 197, 94, 0.25)",
            fontFamily: "var(--font-mono)",
            fontSize: "var(--font-size-caption)",
            color: "var(--color-severity-ok)",
          }}
        >
          Discovery scan completed. Your workspace is already configured.
        </div>
        <button
          className="btn btn-primary"
          style={{ width: "100%", marginTop: 8 }}
          onClick={() => navigate("/dashboard")}
        >
          Go to Dashboard
        </button>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 560, margin: "0 auto" }}>
      <div
        style={{
          fontFamily: "var(--font-display)",
          fontSize: "var(--font-size-h2)",
          fontWeight: 800,
          letterSpacing: "0.08em",
          textTransform: "uppercase",
          color: "var(--pure)",
          marginBottom: 8,
        }}
      >
        Workspace Setup
      </div>
      <div
        style={{
          fontFamily: "var(--font-mono)",
          fontSize: "var(--font-size-caption)",
          color: "var(--muted)",
          marginBottom: 24,
        }}
      >
        Configure your institution details and seed endpoints to start the first discovery scan.
      </div>

      {error && (
        <div
          style={{
            padding: "8px 12px",
            marginBottom: 16,
            background: "rgba(218, 54, 51, 0.08)",
            border: "1px solid rgba(218, 54, 51, 0.25)",
            fontFamily: "var(--font-mono)",
            fontSize: "var(--font-size-caption)",
            color: "var(--color-severity-critical)",
          }}
        >
          {error}
        </div>
      )}
      {!error && scanStatusText && (
        <div
          style={{
            padding: "8px 12px",
            marginBottom: 16,
            background: "rgba(234, 179, 8, 0.08)",
            border: "1px solid rgba(234, 179, 8, 0.25)",
            fontFamily: "var(--font-mono)",
            fontSize: "var(--font-size-caption)",
            color: "var(--color-severity-medium)",
          }}
        >
          {scanStatusText}
        </div>
      )}

      <form onSubmit={handleSubmit}>
        <FieldLabel label="Institution Name" />
        <input
          type="text"
          value={institutionName}
          onChange={(e) => setInstitutionName(e.target.value)}
          placeholder="e.g., Acme Bank"
          disabled={scanRunning}
          style={inputStyle}
        />

        <FieldLabel label="Main URL" required />
        <input
          type="text"
          value={mainUrl}
          onChange={(e) => setMainUrl(e.target.value)}
          placeholder="e.g., https://www.acmebank.com"
          disabled={scanRunning}
          style={inputStyle}
        />

        <FieldLabel label="Seed Endpoints (one per line)" />
        <textarea
          value={seedEndpoints}
          onChange={(e) => setSeedEndpoints(e.target.value)}
          placeholder="Optional; one hostname[:port] per line"
          rows={6}
          disabled={scanRunning}
          style={{
            ...inputStyle,
            height: "auto",
            padding: "10px 12px",
            fontFamily: "var(--font-mono)",
            resize: "vertical",
          }}
        />

        <button
          type="submit"
          className="btn btn-primary"
          disabled={busy || scanRunning || !mainUrl.trim()}
          style={{ width: "100%", marginTop: 8 }}
        >
          {busy ? "Starting scan..." : scanRunning ? "Discovery Scan Running" : "Start Discovery Scan"}
        </button>
      </form>
    </div>
  );
}

function FieldLabel({ label, required }: { label: string; required?: boolean }) {
  return (
    <label
      style={{
        display: "block",
        fontFamily: "var(--font-mono)",
        fontSize: "var(--font-size-label)",
        letterSpacing: "0.2em",
        textTransform: "uppercase",
        color: "var(--muted)",
        marginBottom: 6,
        marginTop: 16,
      }}
    >
      {label}
      {required && <span style={{ color: "var(--color-severity-critical)", marginLeft: 4 }}>*</span>}
    </label>
  );
}

const inputStyle: React.CSSProperties = {
  width: "100%",
  height: "var(--control-height-default)",
  background: "var(--black)",
  border: "1px solid var(--dim)",
  borderRadius: 2,
  padding: "0 12px",
  color: "var(--white)",
  fontFamily: "var(--font-mono)",
  fontSize: "var(--font-size-body)",
  outline: "none",
};
