import { useEffect, useState, useCallback, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { useSessionStore } from "../stores/useSessionStore";
import { ErrorBanner } from "../components/feedback/ErrorBanner";
import { SkeletonLoader } from "../components/feedback/SkeletonLoader";
import { dataSource } from "../lib/api";
import { asObject, asArray, asString, asNumber, formatTimestamp } from "../lib/formatters";
import { simulationDetailPath } from "../lib/routes";

/* ================================================================== */
/*  Types                                                              */
/* ================================================================== */

interface Scenario {
  id: string;
  injection_type: string;
  description: string;
}

interface SimulationRow {
  simulation_id: string;
  scenario_id: string;
  baseline_cycle_id: string;
  status: string;
  created_at_ms: number;
  endpoint_count: number;
}

type RunState = "idle" | "running" | "done" | "error";

/* ================================================================== */
/*  Parsers                                                            */
/* ================================================================== */

function parseSimulation(raw: unknown): SimulationRow {
  const o = asObject(raw);
  return {
    simulation_id: asString(o.simulation_id || o.id),
    scenario_id: asString(o.scenario_id || o.scenario),
    baseline_cycle_id: asString(o.baseline_cycle_id || o.cycle_id),
    status: asString(o.status || "unknown"),
    created_at_ms: asNumber(o.created_at_ms || o.created_at_unix_ms || o.timestamp_ms),
    endpoint_count: asNumber(o.endpoint_count || o.total_endpoints),
  };
}

/* ================================================================== */
/*  Icons                                                              */
/* ================================================================== */

const iconProps = { width: 20, height: 20, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.5, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };

function ScenarioIcon({ type }: { type: string }) {
  switch (type) {
    case "compromised_endpoint":
      return <svg {...iconProps}><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>;
    case "certificate_compromise":
      return <svg {...iconProps}><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>;
    case "coordinated_entropy_spike":
      return <svg {...iconProps}><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" /></svg>;
    case "structural_lateral_movement":
      return <svg {...iconProps}><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></svg>;
    case "persistent_low_signal_exfiltration":
      return <svg {...iconProps}><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" /></svg>;
    default:
      return <svg {...iconProps}><circle cx="12" cy="12" r="10" /></svg>;
  }
}

/* ================================================================== */
/*  Helpers                                                            */
/* ================================================================== */

function scenarioLabel(id: string): string {
  return id.split("_").map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
}

function sevColor(v: number): string {
  if (v >= 0.7) return "#ff4d4f";
  if (v >= 0.4) return "#faad14";
  if (v > 0.01) return "#52c41a";
  return "var(--muted)";
}

function pct(v: number): string { return `${(v * 100).toFixed(1)}%`; }
function fmt3(v: number): string { return v.toFixed(3); }

/* ================================================================== */
/*  Shared style tokens                                                */
/* ================================================================== */

const MONO: React.CSSProperties = { fontFamily: "var(--font-mono)" };
const CAP: React.CSSProperties = { ...MONO, fontSize: 11 };
const LABEL: React.CSSProperties = { ...MONO, fontSize: 10, letterSpacing: "0.2em", textTransform: "uppercase", color: "var(--muted)" };
const CARD: React.CSSProperties = { border: "1px solid var(--border)", background: "var(--panel)" };

/* ================================================================== */
/*  Stat Pill                                                          */
/* ================================================================== */

function Pill({ label, value, color, wide }: { label: string; value: string; color?: string; wide?: boolean }) {
  return (
    <div style={{ ...CARD, padding: "14px 16px", flex: wide ? "1 1 180px" : "0 1 140px", minWidth: 100 }}>
      <div style={{ ...LABEL, marginBottom: 6 }}>{label}</div>
      <div style={{ ...MONO, fontSize: 17, fontWeight: 600, color: color ?? "var(--white)" }}>{value}</div>
    </div>
  );
}

/* ================================================================== */
/*  Report: Blast Radius                                               */
/* ================================================================== */

function BlastRadiusCard({ data }: { data: Record<string, unknown> }) {
  const impacted = asNumber(data.impacted_nodes ?? data.affected_count ?? 0);
  const depth = asNumber(data.depth ?? 0);
  const spread = asNumber(data.spread_pct ?? 0);
  const amp = asNumber(data.amplification ?? 0);
  const score = asNumber(data.score ?? 0);
  const confDrop = asNumber(data.confidence_drop ?? 0);

  return (
    <div style={{ ...CARD, padding: 18 }}>
      <div style={{ ...LABEL, marginBottom: 14 }}>Blast Radius Analysis</div>
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        <Pill label="Impacted Nodes" value={String(impacted)} color={impacted > 0 ? "#ff4d4f" : "var(--muted)"} />
        <Pill label="Propagation Depth" value={String(depth)} />
        <Pill label="Spread" value={pct(spread)} color={sevColor(spread)} />
        <Pill label="Amplification" value={fmt3(amp)} color={sevColor(amp)} />
        <Pill label="Score" value={fmt3(score)} color={sevColor(score)} />
        <Pill label="Confidence Drop" value={fmt3(confDrop)} />
      </div>
      {/* Spread bar */}
      <div style={{ marginTop: 14, height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 2, overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${Math.min(spread * 100, 100)}%`, background: sevColor(spread), borderRadius: 2, transition: "width 0.6s ease" }} />
      </div>
    </div>
  );
}

/* ================================================================== */
/*  Report: Guardian Comparison                                        */
/* ================================================================== */

function GuardianCompare({ baseline, simulated }: { baseline: Record<string, unknown>; simulated: Record<string, unknown> }) {
  const bSev = asNumber(baseline.overall_severity_01 ?? 0);
  const sSev = asNumber(simulated.overall_severity_01 ?? 0);
  const bConf = asNumber(baseline.overall_confidence_01 ?? 0);
  const sConf = asNumber(simulated.overall_confidence_01 ?? 0);
  const entityCount = asNumber(baseline.entity_count ?? simulated.entity_count ?? 0);

  return (
    <div style={{ ...CARD, padding: 18 }}>
      <div style={{ ...LABEL, marginBottom: 14 }}>Guardian Decision Comparison</div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 100px 100px 100px", gap: 8, ...CAP }}>
        <div style={{ color: "var(--muted)" }}>Metric</div>
        <div style={{ color: "var(--muted)", textAlign: "right" }}>Baseline</div>
        <div style={{ color: "var(--muted)", textAlign: "right" }}>Simulated</div>
        <div style={{ color: "var(--muted)", textAlign: "right" }}>Delta</div>

        <div style={{ color: "var(--white)" }}>Overall Severity</div>
        <div style={{ textAlign: "right", color: "var(--ghost)" }}>{fmt3(bSev)}</div>
        <div style={{ textAlign: "right", color: sevColor(sSev) }}>{fmt3(sSev)}</div>
        <div style={{ textAlign: "right", color: sSev - bSev > 0 ? "#ff4d4f" : sSev - bSev < 0 ? "#52c41a" : "var(--muted)", fontWeight: 600 }}>
          {sSev - bSev > 0 ? "+" : ""}{fmt3(sSev - bSev)}
        </div>

        <div style={{ color: "var(--white)" }}>Overall Confidence</div>
        <div style={{ textAlign: "right", color: "var(--ghost)" }}>{fmt3(bConf)}</div>
        <div style={{ textAlign: "right", color: "var(--ghost)" }}>{fmt3(sConf)}</div>
        <div style={{ textAlign: "right", color: sConf - bConf < 0 ? "#faad14" : "var(--muted)", fontWeight: 600 }}>
          {sConf - bConf > 0 ? "+" : ""}{fmt3(sConf - bConf)}
        </div>

        <div style={{ color: "var(--white)" }}>Entity Count</div>
        <div style={{ textAlign: "right", color: "var(--ghost)" }}>{entityCount}</div>
        <div style={{ textAlign: "right", color: "var(--ghost)" }}>{entityCount}</div>
        <div style={{ textAlign: "right", color: "var(--muted)" }}>-</div>
      </div>
    </div>
  );
}

/* ================================================================== */
/*  Report: Risk Deltas Table                                          */
/* ================================================================== */

function DeltasTable({ deltas }: { deltas: Record<string, unknown> }) {
  const rows = useMemo(() => {
    const out: { entity: string; sevDelta: number; confDelta: number }[] = [];
    for (const [entity, val] of Object.entries(deltas)) {
      const d = asObject(val);
      out.push({
        entity,
        sevDelta: asNumber(d.severity_delta ?? d.delta ?? 0),
        confDelta: asNumber(d.confidence_delta ?? 0),
      });
    }
    out.sort((a, b) => Math.abs(b.sevDelta) - Math.abs(a.sevDelta));
    return out;
  }, [deltas]);

  const [showAll, setShowAll] = useState(false);
  const displayed = showAll ? rows : rows.slice(0, 20);

  if (rows.length === 0) return <div style={{ ...CAP, color: "var(--muted)", padding: 12 }}>No entity-level deltas recorded.</div>;

  return (
    <div style={{ ...CARD }}>
      <div style={{ ...LABEL, padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
        Entity Risk Deltas ({rows.length} entities)
      </div>
      {/* Header */}
      <div style={{ display: "grid", gridTemplateColumns: "2fr 100px 100px", gap: 8, padding: "8px 16px", borderBottom: "1px solid var(--border)", ...LABEL }}>
        <span>Entity</span><span style={{ textAlign: "right" }}>Severity &Delta;</span><span style={{ textAlign: "right" }}>Confidence &Delta;</span>
      </div>
      {displayed.map((r) => (
        <div key={r.entity} style={{ display: "grid", gridTemplateColumns: "2fr 100px 100px", gap: 8, padding: "6px 16px", borderBottom: "1px solid rgba(255,255,255,0.04)", ...CAP }}>
          <span style={{ color: "var(--white)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.entity}</span>
          <span style={{ textAlign: "right", color: r.sevDelta > 0 ? "#ff4d4f" : r.sevDelta < 0 ? "#52c41a" : "var(--muted)", fontWeight: r.sevDelta !== 0 ? 600 : 400 }}>
            {r.sevDelta > 0 ? "+" : ""}{fmt3(r.sevDelta)}
          </span>
          <span style={{ textAlign: "right", color: r.confDelta < 0 ? "#faad14" : r.confDelta > 0 ? "#52c41a" : "var(--muted)" }}>
            {r.confDelta > 0 ? "+" : ""}{fmt3(r.confDelta)}
          </span>
        </div>
      ))}
      {rows.length > 20 && (
        <div style={{ padding: "8px 16px", textAlign: "center" }}>
          <button onClick={() => setShowAll(!showAll)} style={{ all: "unset", cursor: "pointer", ...CAP, color: "var(--accent)" }}>
            {showAll ? "Show Less" : `Show All ${rows.length} Entities`}
          </button>
        </div>
      )}
    </div>
  );
}

/* ================================================================== */
/*  Report: Attack Paths                                               */
/* ================================================================== */

function AttackPathsList({ paths }: { paths: unknown[] }) {
  const [expanded, setExpanded] = useState<number | null>(null);
  if (paths.length === 0) return (
    <div style={{ ...CARD, padding: 18 }}>
      <div style={{ ...LABEL, marginBottom: 8 }}>Attack Paths</div>
      <div style={{ ...CAP, color: "var(--muted)" }}>No exploitable attack paths identified in this scenario.</div>
    </div>
  );

  return (
    <div style={{ ...CARD }}>
      <div style={{ ...LABEL, padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>Attack Paths ({paths.length})</div>
      {paths.slice(0, 25).map((raw, i) => {
        const p = asObject(raw);
        const weight = asNumber(p.weight ?? p.score ?? 0);
        const hops = asArray(p.hops ?? p.nodes ?? p.path ?? []);
        const desc = asString(p.description ?? p.label ?? "");
        const open = expanded === i;
        return (
          <div key={i} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
            <div onClick={() => setExpanded(open ? null : i)} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 16px", cursor: "pointer" }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(255,255,255,0.02)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            >
              <span style={{ ...CAP, color: "var(--muted)", width: 24 }}>#{i + 1}</span>
              <span style={{ ...CAP, flex: 1, color: "var(--white)" }}>{desc || `${hops.length}-hop path`}</span>
              <span style={{ ...CAP, color: sevColor(weight), fontWeight: 600 }}>{pct(weight)}</span>
              <span style={{ color: "var(--muted)", fontSize: 9, transition: "transform 0.2s", transform: open ? "rotate(180deg)" : "" }}>&#9660;</span>
            </div>
            {open && hops.length > 0 && (
              <div style={{ padding: "4px 16px 10px 50px", display: "flex", flexWrap: "wrap", gap: 4, alignItems: "center" }}>
                {hops.map((h, j) => (
                  <span key={j} style={{ display: "flex", alignItems: "center", gap: 4 }}>
                    <span style={{ ...CAP, color: "var(--accent)", background: "rgba(255,255,255,0.04)", padding: "2px 6px", borderRadius: 2 }}>{asString(h)}</span>
                    {j < hops.length - 1 && <span style={{ color: "var(--muted)", fontSize: 10 }}>&rarr;</span>}
                  </span>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* ================================================================== */
/*  Report: Narrative                                                  */
/* ================================================================== */

function NarrativeCard({ narrative }: { narrative: Record<string, unknown> }) {
  const summary = asString(narrative.summary ?? "");
  const blast = asString(narrative.blast ?? "");
  const delta = asString(narrative.delta ?? "");
  const pathText = asString(narrative.path ?? "");

  if (!summary && !blast) return null;

  const sections = [
    { label: "Summary", text: summary },
    { label: "Blast Analysis", text: blast },
    { label: "Risk Delta", text: delta },
    { label: "Path Analysis", text: pathText },
  ].filter((s) => s.text);

  return (
    <div style={{ ...CARD, padding: 18 }}>
      <div style={{ ...LABEL, marginBottom: 14 }}>Simulation Narrative</div>
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {sections.map((s, i) => (
          <div key={i}>
            <div style={{ ...CAP, color: "var(--accent)", marginBottom: 4, fontWeight: 600 }}>{s.label}</div>
            <div style={{ ...CAP, color: "var(--ghost)", lineHeight: 1.6 }}>{s.text}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ================================================================== */
/*  Report: Concentration                                              */
/* ================================================================== */

function ConcentrationCard({ data }: { data: Record<string, unknown> }) {
  const ca = asObject(data.ca_concentration);
  const dep = asObject(data.dependency_centrality);
  const spof = asObject(data.single_point_of_failure);

  const topIssuer = asString(ca.top_issuer ?? "");
  const topIssuerPct = asNumber(ca.top_issuer_pct ?? 0);
  const hhi = asNumber(ca.hhi ?? 0);
  const nodeCount = asNumber(dep.node_count ?? 0);
  const edgeCount = asNumber(dep.edge_count ?? 0);
  const topDropPct = asNumber(spof.top_drop_pct ?? 0);
  const spofCandidates = asArray(spof.candidates ?? []);

  return (
    <div style={{ ...CARD, padding: 18 }}>
      <div style={{ ...LABEL, marginBottom: 14 }}>Infrastructure Concentration</div>
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 14 }}>
        <Pill label="CA Concentration (HHI)" value={fmt3(hhi)} color={hhi > 0.5 ? "#faad14" : "var(--muted)"} />
        {topIssuer && <Pill label="Top Issuer" value={topIssuer} wide />}
        <Pill label="Top Issuer Share" value={pct(topIssuerPct)} color={topIssuerPct > 0.8 ? "#ff4d4f" : "var(--muted)"} />
        <Pill label="Graph Nodes" value={String(nodeCount)} />
        <Pill label="Graph Edges" value={String(edgeCount)} />
        <Pill label="Max SPOF Impact" value={pct(topDropPct)} color={sevColor(topDropPct)} />
      </div>
      {spofCandidates.length > 0 && (
        <>
          <div style={{ ...LABEL, marginBottom: 8 }}>Single Points of Failure</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            {spofCandidates.slice(0, 10).map((c, i) => {
              const o = asObject(c);
              const nodeId = asString(o.node_id ?? "").replace("endpoint:", "");
              const dropPct = asNumber(o.drop_pct ?? 0);
              return (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 0" }}>
                  <div style={{ flex: 1, ...CAP, color: "var(--white)" }}>{nodeId}</div>
                  <div style={{ width: 120, height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 2, overflow: "hidden" }}>
                    <div style={{ height: "100%", width: `${Math.min(dropPct * 100 * 10, 100)}%`, background: sevColor(dropPct * 5), borderRadius: 2 }} />
                  </div>
                  <div style={{ ...CAP, color: sevColor(dropPct * 5), fontWeight: 600, width: 50, textAlign: "right" }}>{pct(dropPct)}</div>
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}

/* ================================================================== */
/*  Report: Multi-Cycle Projection                                     */
/* ================================================================== */

function ProjectionCard({ data }: { data: Record<string, unknown> }) {
  const cycles = asArray(data.cycles ?? []);
  const peakSev = asNumber(data.peak_severity ?? 0);
  const finalSev = asNumber(data.final_severity ?? 0);

  return (
    <div style={{ ...CARD, padding: 18 }}>
      <div style={{ ...LABEL, marginBottom: 14 }}>Multi-Cycle Projection</div>
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: cycles.length > 1 ? 14 : 0 }}>
        <Pill label="Peak Severity" value={fmt3(peakSev)} color={sevColor(peakSev)} />
        <Pill label="Final Severity" value={fmt3(finalSev)} color={sevColor(finalSev)} />
        <Pill label="Cycles Projected" value={String(cycles.length)} />
      </div>
      {cycles.length > 1 && (
        <div style={{ display: "flex", alignItems: "flex-end", gap: 4, height: 40, marginTop: 8 }}>
          {cycles.map((c, i) => {
            const o = asObject(c);
            const sev = asNumber(o.overall_severity_01 ?? 0);
            const h = Math.max(2, sev * 40);
            return <div key={i} title={`Cycle ${i + 1}: ${fmt3(sev)}`} style={{ flex: 1, height: h, background: sevColor(sev), borderRadius: "2px 2px 0 0", transition: "height 0.3s" }} />;
          })}
        </div>
      )}
    </div>
  );
}

/* ================================================================== */
/*  Full Report View                                                   */
/* ================================================================== */

function SimulationReport({ result, onBack }: { result: Record<string, unknown>; onBack: () => void }) {
  const [tab, setTab] = useState("overview");
  const scenarioId = asString(result.scenario_id ?? "");
  const simId = asString(result.simulation_id ?? "");
  const baselineCycle = asString(result.baseline_cycle_id ?? "");

  const blastRadius = asObject(result.blast_radius);
  const attackPaths = asArray(result.attack_paths ?? []);
  const deltas = asObject(result.deltas);
  const narrative = asObject(result.narrative);
  const concentration = asObject(result.concentration_metrics);
  const projection = asObject(result.multi_cycle_projection);
  const baselineGuardian = asObject(result.baseline_guardian);
  const simulatedGuardian = asObject(result.simulated_guardian);
  const criticalImpact = asObject(result.critical_impact_summary);

  const impacted = asNumber(blastRadius.impacted_nodes ?? 0);
  const entityCount = Object.keys(deltas).length;

  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "blast", label: "Blast Radius" },
    { id: "paths", label: `Paths (${attackPaths.length})` },
    { id: "deltas", label: `Deltas (${entityCount})` },
    { id: "infra", label: "Infrastructure" },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
      {/* Header bar */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", paddingBottom: 14, borderBottom: "1px solid var(--border)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ width: 36, height: 36, display: "flex", alignItems: "center", justifyContent: "center", border: "1px solid var(--border)", color: "#52c41a" }}>
            <ScenarioIcon type={scenarioId} />
          </div>
          <div>
            <div style={{ ...MONO, fontSize: 14, color: "var(--white)", fontWeight: 600 }}>
              {scenarioLabel(scenarioId)}
            </div>
            <div style={{ ...CAP, color: "var(--muted)", marginTop: 2 }}>
              {simId.slice(0, 12)}... &middot; baseline {baselineCycle}
            </div>
          </div>
        </div>
        <button className="btn btn-small btn-neutral" onClick={onBack} style={{ ...MONO, fontSize: 11 }}>
          &larr; New Simulation
        </button>
      </div>

      {/* Quick stats */}
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", padding: "14px 0" }}>
        <Pill label="Impacted Nodes" value={String(impacted)} color={impacted > 0 ? "#ff4d4f" : "#52c41a"} />
        <Pill label="Attack Paths" value={String(attackPaths.length)} color={attackPaths.length > 0 ? "#faad14" : "var(--muted)"} />
        <Pill label="Entities Analyzed" value={String(entityCount)} />
        <Pill label="Critical Impact" value={`${asNumber(criticalImpact.impacted_count ?? 0)}/${asNumber(criticalImpact.total_critical ?? 0)}`} />
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 0, borderBottom: "1px solid var(--border)" }}>
        {tabs.map((t) => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            all: "unset", cursor: "pointer", padding: "8px 18px", ...CAP,
            color: tab === t.id ? "var(--white)" : "var(--muted)",
            borderBottom: tab === t.id ? "2px solid var(--accent)" : "2px solid transparent",
            transition: "all 0.15s",
          }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div style={{ paddingTop: 16, display: "flex", flexDirection: "column", gap: 14 }}>
        {tab === "overview" && (
          <>
            <NarrativeCard narrative={narrative} />
            <GuardianCompare baseline={baselineGuardian} simulated={simulatedGuardian} />
            <BlastRadiusCard data={blastRadius} />
            <ProjectionCard data={projection} />
          </>
        )}
        {tab === "blast" && (
          <>
            <BlastRadiusCard data={blastRadius} />
            <NarrativeCard narrative={{ summary: asString(narrative.blast ?? "") }} />
          </>
        )}
        {tab === "paths" && <AttackPathsList paths={attackPaths} />}
        {tab === "deltas" && <DeltasTable deltas={deltas} />}
        {tab === "infra" && <ConcentrationCard data={concentration} />}
      </div>
    </div>
  );
}

/* ================================================================== */
/*  Running Animation                                                  */
/* ================================================================== */

function RunningOverlay({ elapsed }: { elapsed: number }) {
  const sec = Math.floor(elapsed / 1000);
  const stages = ["Loading baseline snapshot", "Injecting attack scenario", "Running analysis pipeline", "Computing blast radius", "Building narrative"];
  const stageIdx = Math.min(Math.floor(sec / 3), stages.length - 1);

  return (
    <div style={{ ...CARD, padding: 32, display: "flex", flexDirection: "column", alignItems: "center", gap: 16 }}>
      {/* Spinner */}
      <div style={{ width: 40, height: 40, border: "2px solid var(--border)", borderTop: "2px solid var(--accent)", borderRadius: "50%", animation: "spin 1s linear infinite" }} />
      <div style={{ ...MONO, fontSize: 14, color: "var(--white)" }}>Running Simulation...</div>
      <div style={{ ...CAP, color: "var(--accent)" }}>{stages[stageIdx]}</div>
      <div style={{ ...CAP, color: "var(--muted)" }}>{sec}s elapsed</div>
      {/* Progress dots */}
      <div style={{ display: "flex", gap: 6, marginTop: 4 }}>
        {stages.map((_, i) => (
          <div key={i} style={{
            width: 8, height: 8, borderRadius: "50%",
            background: i <= stageIdx ? "var(--accent)" : "var(--border)",
            transition: "background 0.3s",
          }} />
        ))}
      </div>
    </div>
  );
}

/* ================================================================== */
/*  Main Component                                                     */
/* ================================================================== */

export function SimulatorPage() {
  const navigate = useNavigate();
  const tenantId = useSessionStore((s) => s.activeTenantId);

  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [scenariosLoading, setScenariosLoading] = useState(false);
  const [selectedScenario, setSelectedScenario] = useState<string | null>(null);

  const [runState, setRunState] = useState<RunState>("idle");
  const [runError, setRunError] = useState<string | null>(null);
  const [runResult, setRunResult] = useState<Record<string, unknown> | null>(null);
  const [elapsedMs, setElapsedMs] = useState(0);

  const [simulations, setSimulations] = useState<SimulationRow[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [simsLoading, setSimsLoading] = useState(false);
  const [simsError, setSimsError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const pageSize = 50;

  /* Load scenarios */
  useEffect(() => {
    setScenariosLoading(true);
    dataSource.listScenarios()
      .then((res) => {
        const arr = asArray(asObject(res).scenarios ?? []);
        const parsed = arr.map((r) => { const o = asObject(r); return { id: asString(o.id), injection_type: asString(o.injection_type), description: asString(o.description) }; });
        setScenarios(parsed);
        if (parsed.length > 0 && !selectedScenario) setSelectedScenario(parsed[0].id);
      })
      .catch(() => {
        const fb: Scenario[] = [
          { id: "compromised_endpoint", injection_type: "compromised_endpoint", description: "Simulated endpoint compromise with elevated entropy and fallback stress." },
          { id: "certificate_compromise", injection_type: "certificate_compromise", description: "Simulated certificate compromise / downgrade scenario." },
          { id: "coordinated_entropy_spike", injection_type: "coordinated_entropy_spike", description: "Simulated coordinated entropy spike across multiple endpoints." },
          { id: "structural_lateral_movement", injection_type: "structural_lateral_movement", description: "Simulated lateral movement pressure on adjacent endpoints." },
          { id: "persistent_low_signal_exfiltration", injection_type: "persistent_low_signal_exfiltration", description: "Simulated persistent low-signal exfiltration pattern." },
        ];
        setScenarios(fb);
        if (!selectedScenario) setSelectedScenario(fb[0].id);
      })
      .finally(() => setScenariosLoading(false));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  /* Load past simulations */
  const loadSims = useCallback(() => {
    if (!tenantId) return;
    setSimsLoading(true); setSimsError(null);
    dataSource.listSimulations(tenantId, { page, pageSize })
      .then((res) => {
        const obj = asObject(res);
        const rows = asArray(obj.rows ?? obj.simulations ?? obj.items ?? []);
        setSimulations(rows.map(parseSimulation));
        setTotalCount(asNumber(obj.total_count ?? obj.total ?? rows.length));
      })
      .catch((e) => setSimsError(String(e)))
      .finally(() => setSimsLoading(false));
  }, [tenantId, page]);

  useEffect(() => { loadSims(); }, [loadSims]);

  /* Elapsed timer */
  useEffect(() => {
    if (runState !== "running") return;
    const t0 = Date.now(); setElapsedMs(0);
    const id = setInterval(() => setElapsedMs(Date.now() - t0), 250);
    return () => clearInterval(id);
  }, [runState]);

  /* Run */
  const handleRun = useCallback(async () => {
    if (!tenantId || !selectedScenario || runState === "running") return;
    setRunState("running"); setRunError(null); setRunResult(null);
    try {
      const r = await dataSource.runSimulation(tenantId, { scenario_id: selectedScenario });
      setRunResult(r); setRunState("done"); loadSims();
    } catch (e) {
      setRunError(e instanceof Error ? e.message : String(e)); setRunState("error");
    }
  }, [tenantId, selectedScenario, runState, loadSims]);

  const totalPages = Math.max(1, Math.ceil(totalCount / pageSize));

  /* ---- Report view ---- */
  if (runState === "done" && runResult) {
    return (
      <div>
        <div className="g-section-label">Simulator</div>
        <div style={{ marginTop: 12 }}>
          <SimulationReport result={runResult} onBack={() => { setRunState("idle"); setRunResult(null); }} />
        </div>
        <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
      </div>
    );
  }

  /* ---- Default view ---- */
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <div className="g-section-label">Simulator</div>

      {/* Scenario cards */}
      <div>
        <div style={{ ...LABEL, marginBottom: 10 }}>Select Attack Scenario</div>
        {scenariosLoading ? <SkeletonLoader variant="table" count={3} /> : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))", gap: 8 }}>
            {scenarios.map((sc) => {
              const sel = selectedScenario === sc.id;
              return (
                <button key={sc.id} onClick={() => setSelectedScenario(sc.id)} style={{
                  all: "unset", cursor: "pointer", display: "flex", flexDirection: "column", gap: 8,
                  padding: "14px 16px",
                  border: sel ? "1px solid var(--accent)" : "1px solid var(--border)",
                  background: sel ? "rgba(255,255,255,0.03)" : "transparent",
                  transition: "all 0.15s",
                }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ color: sel ? "var(--accent)" : "var(--muted)" }}><ScenarioIcon type={sc.injection_type} /></span>
                    <span style={{ ...MONO, fontSize: 12, color: sel ? "var(--white)" : "var(--ghost)", fontWeight: sel ? 600 : 400 }}>
                      {scenarioLabel(sc.id)}
                    </span>
                  </div>
                  <span style={{ ...CAP, color: "var(--muted)", lineHeight: 1.5 }}>{sc.description}</span>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Run section */}
      {runState === "running" ? (
        <RunningOverlay elapsed={elapsedMs} />
      ) : (
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <button className="btn btn-primary" disabled={!selectedScenario || !tenantId} onClick={handleRun}
            style={{ ...MONO, fontSize: 12, letterSpacing: "0.15em", padding: "10px 32px", textTransform: "uppercase" }}>
            Run Simulation
          </button>
          {runState === "error" && (
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ ...CAP, color: "#ff4d4f" }}>{runError}</span>
              <button className="btn btn-small btn-neutral" onClick={() => setRunState("idle")}>Dismiss</button>
            </div>
          )}
        </div>
      )}

      {/* Past simulations */}
      <div>
        <div style={{ ...LABEL, marginBottom: 10 }}>
          Past Simulations{totalCount > 0 && ` (${totalCount})`}
        </div>
        {simsError && <ErrorBanner message={simsError} onRetry={loadSims} />}
        {simsLoading && simulations.length === 0 ? <SkeletonLoader variant="table" count={4} /> : simulations.length === 0 ? (
          <div style={{ ...CAP, color: "var(--muted)", padding: "12px 0" }}>No simulations yet.</div>
        ) : (
          <>
            <div style={{ border: "1px solid var(--border)" }}>
              <div style={{ display: "grid", gridTemplateColumns: "2fr 1.5fr 1.5fr 80px 120px", gap: 8, padding: "8px 12px", background: "var(--panel)", borderBottom: "1px solid var(--border)", ...LABEL }}>
                <span>ID</span><span>Scenario</span><span>Baseline</span><span>Status</span><span>Created</span>
              </div>
              {simulations.map((s) => (
                <div key={s.simulation_id} onClick={() => navigate(simulationDetailPath(s.simulation_id))}
                  style={{ display: "grid", gridTemplateColumns: "2fr 1.5fr 1.5fr 80px 120px", gap: 8, padding: "7px 12px", borderBottom: "1px solid var(--border)", cursor: "pointer", transition: "background 0.1s", ...CAP, color: "var(--white)" }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                >
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.simulation_id}</span>
                  <span style={{ color: "var(--ghost)" }}>{s.scenario_id ? scenarioLabel(s.scenario_id) : "-"}</span>
                  <span style={{ color: "var(--ghost)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.baseline_cycle_id || "-"}</span>
                  <span style={{ color: s.status === "completed" ? "#52c41a" : "var(--muted)" }}>{s.status}</span>
                  <span style={{ color: "var(--ghost)" }}>{s.created_at_ms ? formatTimestamp(s.created_at_ms) : "-"}</span>
                </div>
              ))}
            </div>
            {totalPages > 1 && (
              <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 12, padding: "10px 0" }}>
                <button className="btn btn-small btn-neutral" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Prev</button>
                <span style={{ ...CAP, color: "var(--muted)" }}>Page {page}/{totalPages}</span>
                <button className="btn btn-small btn-neutral" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>Next</button>
              </div>
            )}
          </>
        )}
      </div>

      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );
}
