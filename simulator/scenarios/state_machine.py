"""
Scenario State Machine
======================

Deterministic multi-step scenario engine.

Constraints:
- No wall clock usage
- No randomness
- No TrustGraph mutation
- No Layer 0–4 changes
- Bounded execution (max steps, repeats, injections, pipeline runs)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple
from collections import deque

from simulator.scenarios.scenario_catalog import AttackScenario
from simulator.scenarios.scenario_injector import ScenarioInjector
from simulator.core.observation_adapter import ObservationAdapter
from simulator.core.runtime_pipeline import RuntimePipeline, PipelineOutputs
from simulator.analysis.blast_radius import compute_blast_radius


@dataclass(frozen=True, slots=True)
class ScenarioStep:
    name: str
    max_repeat: int
    _pre: Callable[[Dict[str, Any]], bool]
    _inj: Callable[[Dict[str, Any]], Dict[str, Any]]
    _post: Callable[[Dict[str, Any]], bool]

    def precondition(self, sim_outputs: Dict[str, Any]) -> bool:
        return bool(self._pre(sim_outputs))

    def injection_payload(self, sim_outputs: Dict[str, Any]) -> Dict[str, Any]:
        payload = self._inj(sim_outputs)
        return dict(payload or {})

    def postcondition(self, sim_outputs: Dict[str, Any]) -> bool:
        return bool(self._post(sim_outputs))


class ScenarioStateMachine:
    def __init__(self, steps: List[ScenarioStep], max_steps: int = 5) -> None:
        self.steps = list(steps or [])
        self.max_steps = max(0, int(max_steps))

    def execute(
        self,
        *,
        baseline_outputs: PipelineOutputs,
        baseline_dicts: List[Dict[str, Any]],
        scenario: AttackScenario,
        injector: ScenarioInjector,
        adapter: ObservationAdapter,
        pipeline: RuntimePipeline,
        tenant_id: str,
        cycle_id: str,
        cycle_number: int,
        trust_graph_snapshot: Dict[str, Any],
        layer3_snapshot: Optional[Dict[str, Any]],
        severity_threshold: float,
        critical_entities: List[Dict[str, Any]],
        origin_entity: Optional[str],
        max_steps: int = 5,
        max_repeat: int = 2,
        max_total_injections: int = 10,
        max_pipeline_runs: int = 10,
    ) -> Tuple[PipelineOutputs, List[Dict[str, Any]], List[Dict[str, Any]]]:
        # hard caps
        max_steps = min(max(0, int(max_steps)), 5)
        max_repeat = min(max(0, int(max_repeat)), 2)
        max_total_injections = min(max(0, int(max_total_injections)), 10)
        max_pipeline_runs = min(max(0, int(max_pipeline_runs)), 10)

        current_dicts = list(baseline_dicts)
        current_outputs = baseline_outputs
        previous_outputs: Optional[PipelineOutputs] = None

        progression: List[Dict[str, Any]] = []
        injections = 0
        runs = 0

        steps = self.steps[:max_steps]

        for idx, step in enumerate(steps):
            triggered = False
            repeats = 0

            while repeats < step.max_repeat and injections < max_total_injections and runs < max_pipeline_runs:
                ctx = _build_context(
                    baseline_outputs=baseline_outputs,
                    current_outputs=current_outputs,
                    previous_outputs=previous_outputs,
                    severity_threshold=severity_threshold,
                    critical_entities=critical_entities,
                    origin_entity=origin_entity,
                )

                if not step.precondition(ctx):
                    break

                payload = step.injection_payload(ctx)
                if not payload:
                    break

                # apply deterministic injection to current observations
                step_scenario = AttackScenario(
                    id=scenario.id,
                    injection_type=scenario.injection_type,
                    target_selector=dict(scenario.target_selector or {}),
                    injection_payload=dict(payload),
                    description=step.name,
                )
                current_dicts = injector.inject(current_dicts, step_scenario)

                # re-run pipeline
                current_records = [adapter.from_dict(d) for d in current_dicts]
                current_raw = [adapter.to_protocol_raw(r) for r in current_records]
                previous_outputs = current_outputs
                current_outputs = pipeline.run_from_observations(
                    tenant_id=tenant_id,
                    cycle_id=cycle_id,
                    cycle_number=cycle_number,
                    raw_observations=current_raw,
                    trust_graph_snapshot=trust_graph_snapshot,
                    layer3_state_snapshot=layer3_snapshot,
                )
                runs += 1
                injections += 1

                ctx_after = _build_context(
                    baseline_outputs=baseline_outputs,
                    current_outputs=current_outputs,
                    previous_outputs=previous_outputs,
                    severity_threshold=severity_threshold,
                    critical_entities=critical_entities,
                    origin_entity=origin_entity,
                )

                if step.postcondition(ctx_after):
                    triggered = True
                    break

                repeats += 1

            progression.append(
                {
                    "step_index": int(idx),
                    "step_name": step.name,
                    "triggered": bool(triggered),
                    "metrics_snapshot": _metrics_snapshot(
                        baseline_outputs=baseline_outputs,
                        current_outputs=current_outputs,
                        severity_threshold=severity_threshold,
                        critical_entities=critical_entities,
                        origin_entity=origin_entity,
                    ),
                }
            )

            if injections >= max_total_injections or runs >= max_pipeline_runs:
                break

        return current_outputs, current_dicts, progression


def _overall_severity(guardians: Dict[str, Any]) -> float:
    vals: List[float] = []
    for eid in sorted(guardians.keys()):
        g = guardians[eid]
        vals.append(float(getattr(g, "overall_severity_01", 0.0)))
    return (sum(vals) / float(len(vals))) if vals else 0.0


def _critical_entity_ids(critical_entities: List[Dict[str, Any]]) -> List[str]:
    ids: List[str] = []
    for v in critical_entities or []:
        eid = str(v.get("entity_id", "")).strip()
        if eid:
            ids.append(eid)
    return ids


def _critical_weights(critical_entities: List[Dict[str, Any]]) -> Dict[str, float]:
    out: Dict[str, float] = {}
    for v in critical_entities or []:
        eid = str(v.get("entity_id", "")).strip()
        if not eid:
            continue
        try:
            w = float(v.get("weight", 1.0))
        except Exception:
            w = 1.0
        if w < 0.0:
            w = 0.0
        out[eid] = float(w)
    return out


def _critical_severity_max(guardians: Dict[str, Any], critical_entities: List[Dict[str, Any]]) -> float:
    ids = _critical_entity_ids(critical_entities)
    if not ids:
        return 0.0
    vals: List[float] = []
    for eid in ids:
        g = guardians.get(eid)
        if g is None:
            continue
        vals.append(float(getattr(g, "overall_severity_01", 0.0)))
    return max(vals) if vals else 0.0


def _critical_weighted_impact_pct(
    guardians: Dict[str, Any],
    critical_entities: List[Dict[str, Any]],
    *,
    threshold: float,
) -> float:
    ids = _critical_entity_ids(critical_entities)
    weights = _critical_weights(critical_entities)
    if not ids:
        return 0.0
    total_w = sum(float(weights.get(eid, 0.0)) for eid in ids)
    if total_w <= 0.0:
        return 0.0
    impacted_w = 0.0
    for eid in ids:
        g = guardians.get(eid)
        sev = float(getattr(g, "overall_severity_01", 0.0)) if g else 0.0
        if sev >= float(threshold):
            impacted_w += float(weights.get(eid, 0.0))
    return impacted_w / total_w


def _reachable_nodes(outputs: PipelineOutputs, origin_entity: Optional[str]) -> int:
    graph = outputs.trust_graph
    if not origin_entity:
        return int(len(graph.nodes))
    origin = f"endpoint:{origin_entity}"
    if origin not in graph.nodes:
        return int(len(graph.nodes))
    visited = set([origin])
    q = deque([origin])
    while q:
        node = q.popleft()
        for nxt in graph.get_outgoing(node):
            if nxt in visited:
                continue
            visited.add(nxt)
            q.append(nxt)
    return int(len(visited))


def _metrics_snapshot(
    *,
    baseline_outputs: PipelineOutputs,
    current_outputs: PipelineOutputs,
    severity_threshold: float,
    critical_entities: List[Dict[str, Any]],
    origin_entity: Optional[str],
) -> Dict[str, Any]:
    blast = compute_blast_radius(
        trust_graph=current_outputs.trust_graph,
        predictions=current_outputs.predictions,
        baseline_predictions=baseline_outputs.predictions,
        severity_threshold=severity_threshold,
    )
    crit_weighted_pct = _critical_weighted_impact_pct(
        current_outputs.guardians,
        critical_entities,
        threshold=severity_threshold,
    )
    return {
        "overall_severity": round(float(_overall_severity(current_outputs.guardians)), 6),
        "critical_severity_max": round(float(_critical_severity_max(current_outputs.guardians, critical_entities)), 6),
        "blast_radius_score": round(float(blast.score), 6),
        "reachable_nodes": int(_reachable_nodes(current_outputs, origin_entity)),
        "critical_impact_weighted_pct": round(float(crit_weighted_pct), 6),
    }


def _build_context(
    *,
    baseline_outputs: PipelineOutputs,
    current_outputs: PipelineOutputs,
    previous_outputs: Optional[PipelineOutputs],
    severity_threshold: float,
    critical_entities: List[Dict[str, Any]],
    origin_entity: Optional[str],
) -> Dict[str, Any]:
    prev_metrics = None
    if previous_outputs is not None:
        prev_metrics = _metrics_snapshot(
            baseline_outputs=baseline_outputs,
            current_outputs=previous_outputs,
            severity_threshold=severity_threshold,
            critical_entities=critical_entities,
            origin_entity=origin_entity,
        )
    return {
        "baseline_outputs": baseline_outputs,
        "current_outputs": current_outputs,
        "previous_outputs": previous_outputs,
        "metrics": _metrics_snapshot(
            baseline_outputs=baseline_outputs,
            current_outputs=current_outputs,
            severity_threshold=severity_threshold,
            critical_entities=critical_entities,
            origin_entity=origin_entity,
        ),
        "previous_metrics": prev_metrics,
    }
