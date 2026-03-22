"""
Simulation Service
==================

Deterministic end-to-end simulator integration spine.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

from simulator.core.simulation_request import SimulationRequest
from simulator.core.simulation_response import SimulationResponse
from simulator.core.baseline_loader import BaselineFilesystemLoader
from simulator.core.observation_adapter import ObservationAdapter
from simulator.scenarios.scenario_catalog import get_default_scenarios, AttackScenario
from simulator.scenarios.scenario_injector import ScenarioInjector
from simulator.scenarios.state_machine import ScenarioStateMachine, ScenarioStep
from simulator.mitigation.mitigation_actions import MitigationAction
from simulator.mitigation.mitigation_engine import MitigationEngine
from simulator.core.runtime_pipeline import RuntimePipeline
from simulator.analysis.blast_radius import compute_blast_radius, BlastRadius
from simulator.analysis.concentration import compute_concentration_metrics
from simulator.analysis.attack_paths import rank_paths
from simulator.narrative.narrative_planner import build_narrative
from simulator.storage.simulation_storage import SimulationStorage
from simulator.core.validation import SimulationValidator
from simulator.core.runtime_pipeline import PipelineOutputs


class SimulationService:
    """
    Canonical simulator spine.
    """

    MAX_PATHS = 100
    MAX_MITIGATIONS = 5
    MAX_GRAPH_NODES = 200000
    ANALYSIS_MAX_WORKERS = 3
    PATH_MODES = {
        "SAFE": {"max_depth": 6, "top_k_edges": None, "weight_min": 0.0, "max_expansions": 10_000},
        "EXTENDED": {"max_depth": 10, "top_k_edges": 5, "weight_min": 0.01, "max_expansions": 25_000},
        "DEEP": {"max_depth": 15, "top_k_edges": 3, "weight_min": 0.02, "max_expansions": 50_000},
    }

    def __init__(self, *, production_root: str, simulation_root: str) -> None:
        self._baseline_loader = BaselineFilesystemLoader(production_root)
        self._adapter = ObservationAdapter()
        self._injector = ScenarioInjector()
        self._mitigation = MitigationEngine()
        self._pipeline = RuntimePipeline()
        self._storage = SimulationStorage(simulation_root)
        self._validator = SimulationValidator()

    def run(self, request: SimulationRequest) -> SimulationResponse:
        # --------------------------------------------------
        # Deterministic request validation & clamping
        # --------------------------------------------------
        if not request.tenant_id:
            raise ValueError("tenant_id cannot be empty")
        if not request.baseline_cycle_id:
            raise ValueError("baseline_cycle_id cannot be empty")
        if not request.scenario_id:
            raise ValueError("scenario_id cannot be empty")

        path_mode = str(request.path_mode or "SAFE").upper()
        if path_mode not in self.PATH_MODES:
            raise ValueError("path_mode invalid")
        mode_cfg = dict(self.PATH_MODES[path_mode])
        max_paths = min(max(1, int(request.max_paths)), self.MAX_PATHS)
        max_mitigations = min(max(0, int(request.max_mitigations)), self.MAX_MITIGATIONS)
        replay_cycles = min(max(1, int(request.replay_cycles)), 5)

        # --------------------------------------------------
        # Isolation guard
        # --------------------------------------------------
        isolation = self._validator.validate_isolation(
            sim_root=str(self._storage._mgr.base_path),
            prod_root=str(self._baseline_loader.production_root),
        )
        if not isolation.ok:
            raise RuntimeError("Simulation storage isolation violation")

        # --------------------------------------------------
        # Baseline load
        # --------------------------------------------------
        baseline = self._baseline_loader.load_baseline(
            tenant_id=request.tenant_id,
            cycle_id=request.baseline_cycle_id,
        )

        baseline_validation = self._validator.validate_baseline(baseline)
        if not baseline_validation.ok:
            raise RuntimeError("Baseline snapshot invalid")

        # --------------------------------------------------
        # Baseline integrity + isolation guards
        # --------------------------------------------------
        prod_files_before = _list_production_files(
            production_root=str(self._baseline_loader.production_root),
            tenant_id=request.tenant_id,
        )
        layer3_hash_before = _stable_json(baseline.layer3_snapshot or {})

        stored_hash = str(baseline.layer0_snapshot.get("snapshot_hash_sha256", "")).strip()
        if stored_hash:
            baseline_hash = stored_hash
        else:
            baseline_hash = _snapshot_hash(baseline.layer0_snapshot)
        sim_id = self._storage.compute_simulation_id(
            tenant_id=request.tenant_id,
            baseline_cycle_id=request.baseline_cycle_id,
            baseline_snapshot_hash=baseline_hash,
            scenario_id=request.scenario_id,
            scenario_params=request.scenario_params,
            mitigation_params=request.mitigation or {},
        )
        cached_payload = self._storage.load(request.tenant_id, sim_id)
        if isinstance(cached_payload, dict):
            return _response_from_cached_payload(cached_payload)

        node_count = len(baseline.trust_graph_snapshot.get("nodes", []) or [])
        if node_count > self.MAX_GRAPH_NODES:
            raise RuntimeError("Simulation graph too large")

        # --------------------------------------------------
        # Build baseline observations (deterministic replay)
        # --------------------------------------------------
        baseline_records = self._adapter.observations_from_snapshot(baseline.layer0_snapshot)
        baseline_dicts = [self._adapter.to_dict(r) for r in baseline_records]
        baseline_raw = [self._adapter.to_protocol_raw(r) for r in baseline_records]

        # --------------------------------------------------
        # Scenario selection
        # --------------------------------------------------
        scenario = self._resolve_scenario(request.scenario_id, request.scenario_params)

        # --------------------------------------------------
        # Baseline pipeline run
        # --------------------------------------------------
        baseline_outputs = self._pipeline.run_from_observations(
            tenant_id=request.tenant_id,
            cycle_id=request.baseline_cycle_id,
            cycle_number=request.cycle_number,
            raw_observations=baseline_raw,
            trust_graph_snapshot=baseline.trust_graph_snapshot,
            layer3_state_snapshot=baseline.layer3_snapshot,
        )

        # --------------------------------------------------
        # Scenario execution (single-step or multi-step)
        # --------------------------------------------------
        scenario_progression: List[Dict[str, Any]] = []
        simulated_dicts: List[Dict[str, Any]] = []

        if scenario.id == "compromised_endpoint":
            state_machine = ScenarioStateMachine(
                steps=_build_compromised_endpoint_steps(severity_threshold=float(request.severity_threshold)),
                max_steps=5,
            )
            origin_entity = _scenario_origin_entity(scenario)
            simulated_outputs, simulated_dicts, scenario_progression = state_machine.execute(
                baseline_outputs=baseline_outputs,
                baseline_dicts=baseline_dicts,
                scenario=scenario,
                injector=self._injector,
                adapter=self._adapter,
                pipeline=self._pipeline,
                tenant_id=request.tenant_id,
                cycle_id=request.baseline_cycle_id,
                cycle_number=request.cycle_number,
                trust_graph_snapshot=baseline.trust_graph_snapshot,
                layer3_snapshot=baseline.layer3_snapshot,
                severity_threshold=float(request.severity_threshold),
                critical_entities=_normalize_critical_entities(request.critical_entities),
                origin_entity=origin_entity,
                max_steps=5,
                max_repeat=2,
                max_total_injections=10,
                max_pipeline_runs=10,
            )
        else:
            # single-step injection (legacy behavior)
            simulated_dicts = self._injector.inject(baseline_dicts, scenario)
            simulated_records = [self._adapter.from_dict(d) for d in simulated_dicts]
            simulated_raw = [self._adapter.to_protocol_raw(r) for r in simulated_records]
            simulated_outputs = self._pipeline.run_from_observations(
                tenant_id=request.tenant_id,
                cycle_id=request.baseline_cycle_id,
                cycle_number=request.cycle_number,
                raw_observations=simulated_raw,
                trust_graph_snapshot=baseline.trust_graph_snapshot,
                layer3_state_snapshot=baseline.layer3_snapshot,
            )

        # --------------------------------------------------
        # Blast radius + paths + narrative
        # --------------------------------------------------
        critical_entities = _normalize_critical_entities(request.critical_entities)
        critical_ids = _critical_entity_ids(critical_entities)
        critical_nodes = [f"endpoint:{eid}" for eid in critical_ids]
        origin_entity = _scenario_origin_entity(scenario)
        origin_node_id = f"endpoint:{origin_entity}" if origin_entity else ""
        critical_summary = _critical_impact_summary(
            simulated_outputs.guardians,
            critical_entities,
            threshold=float(request.severity_threshold),
        )

        analysis_workers = max(1, min(int(self.ANALYSIS_MAX_WORKERS), 8))
        if analysis_workers > 1:
            with ThreadPoolExecutor(max_workers=analysis_workers) as executor:
                blast_future = executor.submit(
                    compute_blast_radius,
                    trust_graph=simulated_outputs.trust_graph,
                    predictions=simulated_outputs.predictions,
                    baseline_predictions=baseline_outputs.predictions,
                    severity_threshold=float(request.severity_threshold),
                )
                paths_future = executor.submit(
                    _rank_paths_payload,
                    trust_graph=simulated_outputs.trust_graph,
                    origin_node_id=origin_node_id,
                    max_depth=int(mode_cfg["max_depth"]),
                    max_paths=max_paths,
                    max_expansions=int(mode_cfg["max_expansions"]),
                    top_k_edges=mode_cfg["top_k_edges"],
                    weight_min=float(mode_cfg["weight_min"]),
                    critical_nodes=critical_nodes,
                )
                concentration_future = executor.submit(
                    compute_concentration_metrics,
                    simulated_outputs.trust_graph,
                )
                blast = blast_future.result()
                paths = paths_future.result()
                concentration = concentration_future.result()
        else:
            blast = compute_blast_radius(
                trust_graph=simulated_outputs.trust_graph,
                predictions=simulated_outputs.predictions,
                baseline_predictions=baseline_outputs.predictions,
                severity_threshold=float(request.severity_threshold),
            )
            paths = _rank_paths_payload(
                trust_graph=simulated_outputs.trust_graph,
                origin_node_id=origin_node_id,
                max_depth=int(mode_cfg["max_depth"]),
                max_paths=max_paths,
                max_expansions=int(mode_cfg["max_expansions"]),
                top_k_edges=mode_cfg["top_k_edges"],
                weight_min=float(mode_cfg["weight_min"]),
                critical_nodes=critical_nodes,
            )
            concentration = compute_concentration_metrics(simulated_outputs.trust_graph)

        deltas = _compare_guardians(
            baseline_outputs.guardians,
            simulated_outputs.guardians,
        )
        critical_deltas = _critical_entity_deltas(
            baseline_outputs.guardians,
            simulated_outputs.guardians,
            critical_entities,
        )

        # rebuild simulated_raw from final simulated_dicts
        simulated_records = [self._adapter.from_dict(d) for d in simulated_dicts]
        simulated_raw = [self._adapter.to_protocol_raw(r) for r in simulated_records]

        mitigation_analysis, mitigation_guardian = _mitigation_analysis(
            request=request,
            max_mitigations=max_mitigations,
            baseline_outputs=baseline_outputs,
            simulated_outputs=simulated_outputs,
            simulated_dicts=simulated_dicts,
            trust_graph_snapshot=baseline.trust_graph_snapshot,
            layer3_snapshot=baseline.layer3_snapshot,
            severity_threshold=float(request.severity_threshold),
            critical_entities=critical_entities,
            simulated_blast=blast,
            adapter=self._adapter,
            mitigation_engine=self._mitigation,
            pipeline=self._pipeline,
        )

        multi_cycle = _multi_cycle_projection(
            replay_cycles=replay_cycles,
            request=request,
            simulated_raw=simulated_raw,
            trust_graph_snapshot=baseline.trust_graph_snapshot,
            layer3_snapshot=baseline.layer3_snapshot,
            critical_entities=critical_entities,
            severity_threshold=float(request.severity_threshold),
            pipeline=self._pipeline,
        )

        narrative = build_narrative(
            blast_radius=_blast_to_dict(blast),
            top_paths=paths[:1],
            deltas=deltas,
        )

        # --------------------------------------------------
        # Simulation ID + persist
        # --------------------------------------------------
        blast_dict = _blast_to_dict(blast)
        if "impacted_weight_pct" in critical_summary:
            blast_dict["critical_weighted_impact_pct"] = float(critical_summary.get("impacted_weight_pct", 0.0))
            blast_dict["critical_weighted_score"] = round(
                float(blast.score) * float(critical_summary.get("impacted_weight_pct", 0.0)), 6
            )

        response = SimulationResponse(
            simulation_id=sim_id,
            tenant_id=request.tenant_id,
            baseline_cycle_id=request.baseline_cycle_id,
            scenario_id=request.scenario_id,
            scenario_params=dict(request.scenario_params),
            baseline_guardian=_guardian_summary(baseline_outputs.guardians),
            simulated_guardian=_guardian_summary(simulated_outputs.guardians),
            mitigation_guardian=mitigation_guardian,
            deltas=deltas,
            blast_radius=blast_dict,
            attack_paths=paths,
            critical_impact_summary=critical_summary,
            critical_entity_deltas=critical_deltas,
            concentration_metrics=concentration,
            mitigation_analysis=mitigation_analysis,
            multi_cycle_projection=multi_cycle,
            narrative=narrative,
            scenario_progression=scenario_progression,
        )

        self._storage.persist(request.tenant_id, sim_id, response.to_dict())

        # --------------------------------------------------
        # State leak assertions (post-run)
        # --------------------------------------------------
        layer3_hash_after = _stable_json(baseline.layer3_snapshot or {})
        if layer3_hash_after != layer3_hash_before:
            raise RuntimeError("Layer3 snapshot mutated during simulation")

        prod_files_after = _list_production_files(
            production_root=str(self._baseline_loader.production_root),
            tenant_id=request.tenant_id,
        )
        if prod_files_after != prod_files_before:
            raise RuntimeError("Production storage modified during simulation")

        return response

    def assert_deterministic(self, request: SimulationRequest) -> None:
        a = self.run(request)
        b = self.run(request)
        h1 = _hash_response(a)
        h2 = _hash_response(b)
        if h1 != h2:
            raise RuntimeError("Determinism check failed")

    def _resolve_scenario(self, scenario_id: str, params: Dict[str, Any]) -> AttackScenario:
        scenarios = {s.id: s for s in get_default_scenarios()}
        if scenario_id not in scenarios:
            raise ValueError(f"Unknown scenario_id: {scenario_id}")

        base = scenarios[scenario_id]
        target_selector = params.get("target_selector", base.target_selector)
        injection_payload = params.get("injection_payload", base.injection_payload)

        return AttackScenario(
            id=base.id,
            injection_type=base.injection_type,
            target_selector=dict(target_selector),
            injection_payload=dict(injection_payload),
            description=base.description,
        )

    def _build_mitigation_action(self, data: Dict[str, Any]) -> MitigationAction:
        return MitigationAction(
            action_type=str(data.get("action_type", "unknown")),
            target=dict(data.get("target", {})),
            delta=dict(data.get("delta", {})),
            description=str(data.get("description", "")),
        )


def _guardian_summary(guardians: Dict[str, Any]) -> Dict[str, Any]:
    # Deterministic aggregate summary (mean severity/confidence)
    severities = []
    confidences = []
    for eid in sorted(guardians.keys()):
        g = guardians[eid]
        severities.append(float(getattr(g, "overall_severity_01", 0.0)))
        confidences.append(float(getattr(g, "overall_confidence_01", 0.0)))

    sev = sum(severities) / float(len(severities)) if severities else 0.0
    conf = sum(confidences) / float(len(confidences)) if confidences else 0.0

    return {
        "overall_severity_01": round(sev, 6),
        "overall_confidence_01": round(conf, 6),
        "entity_count": len(guardians),
    }


def _compare_guardians(baseline: Dict[str, Any], simulated: Dict[str, Any]) -> Dict[str, Dict[str, float]]:
    out: Dict[str, Dict[str, float]] = {}
    entity_ids = sorted(set(baseline.keys()) | set(simulated.keys()))
    for eid in entity_ids:
        b = baseline.get(eid)
        s = simulated.get(eid)
        b_sev = float(getattr(b, "overall_severity_01", 0.0)) if b else 0.0
        b_conf = float(getattr(b, "overall_confidence_01", 0.0)) if b else 0.0
        s_sev = float(getattr(s, "overall_severity_01", 0.0)) if s else 0.0
        s_conf = float(getattr(s, "overall_confidence_01", 0.0)) if s else 0.0
        out[eid] = {
            "severity_delta": s_sev - b_sev,
            "confidence_delta": s_conf - b_conf,
        }
    return out


def _scenario_origin_entity(scenario: AttackScenario) -> str | None:
    selector = scenario.target_selector or {}
    if "entity_id" in selector:
        return str(selector.get("entity_id"))
    return None


def _normalize_critical_entities(values: Optional[List[Any]]) -> List[Dict[str, Any]]:
    if not values:
        return []
    weights: Dict[str, float] = {}
    for v in values:
        if isinstance(v, dict):
            eid = str(v.get("entity_id", "")).strip()
            if not eid:
                continue
            w_raw = v.get("weight", 1.0)
            try:
                w = float(w_raw)
            except Exception:
                w = 1.0
            if w < 0.0:
                w = 0.0
            weights[eid] = max(weights.get(eid, 0.0), float(w))
        else:
            s = str(v).strip()
            if not s:
                continue
            weights[s] = max(weights.get(s, 0.0), 1.0)
    out: List[Dict[str, Any]] = []
    for eid in sorted(weights.keys()):
        out.append({"entity_id": eid, "weight": round(float(weights[eid]), 6)})
    return out


def _critical_entity_ids(values: List[Dict[str, Any]]) -> List[str]:
    return [str(v.get("entity_id", "")) for v in values if str(v.get("entity_id", "")).strip()]


def _critical_weights(values: List[Dict[str, Any]]) -> Dict[str, float]:
    out: Dict[str, float] = {}
    for v in values:
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


def _critical_impact_summary(
    guardians: Dict[str, Any],
    critical_entities: List[Dict[str, Any]],
    *,
    threshold: float,
) -> Dict[str, Any]:
    critical_ids = _critical_entity_ids(critical_entities)
    weights = _critical_weights(critical_entities)
    total = len(critical_ids)
    total_weight = sum(weights.get(eid, 0.0) for eid in critical_ids)
    impacted = 0
    impacted_weight = 0.0
    for eid in critical_ids:
        g = guardians.get(eid)
        sev = float(getattr(g, "overall_severity_01", 0.0)) if g else 0.0
        if sev >= float(threshold):
            impacted += 1
            impacted_weight += float(weights.get(eid, 0.0))
    pct = (impacted / float(total)) if total > 0 else 0.0
    impacted_weight_pct = (impacted_weight / float(total_weight)) if total_weight > 0.0 else 0.0
    return {
        "total_critical": int(total),
        "impacted_count": int(impacted),
        "impacted_pct": round(pct, 6),
        "total_weight": round(float(total_weight), 6),
        "impacted_weight": round(float(impacted_weight), 6),
        "impacted_weight_pct": round(float(impacted_weight_pct), 6),
        "severity_threshold": float(threshold),
    }


def _critical_entity_deltas(
    baseline: Dict[str, Any],
    simulated: Dict[str, Any],
    critical_entities: List[Dict[str, Any]],
) -> Dict[str, Dict[str, float]]:
    out: Dict[str, Dict[str, float]] = {}
    for eid in _critical_entity_ids(critical_entities):
        b = baseline.get(eid)
        s = simulated.get(eid)
        b_sev = float(getattr(b, "overall_severity_01", 0.0)) if b else 0.0
        b_conf = float(getattr(b, "overall_confidence_01", 0.0)) if b else 0.0
        s_sev = float(getattr(s, "overall_severity_01", 0.0)) if s else 0.0
        s_conf = float(getattr(s, "overall_confidence_01", 0.0)) if s else 0.0
        out[eid] = {
            "severity_delta": s_sev - b_sev,
            "confidence_delta": s_conf - b_conf,
        }
    return out


def _critical_severity_max(guardians: Dict[str, Any], critical_entities: List[Dict[str, Any]]) -> float:
    ids = _critical_entity_ids(critical_entities)
    if not ids:
        return 0.0
    vals = []
    for eid in ids:
        g = guardians.get(eid)
        if g is None:
            continue
        vals.append(float(getattr(g, "overall_severity_01", 0.0)))
    return max(vals) if vals else 0.0


def _critical_weighted_severity_avg(guardians: Dict[str, Any], critical_entities: List[Dict[str, Any]]) -> float:
    ids = _critical_entity_ids(critical_entities)
    weights = _critical_weights(critical_entities)
    if not ids:
        return 0.0
    total_w = 0.0
    acc = 0.0
    for eid in ids:
        g = guardians.get(eid)
        sev = float(getattr(g, "overall_severity_01", 0.0)) if g else 0.0
        w = float(weights.get(eid, 0.0))
        total_w += w
        acc += w * sev
    if total_w <= 0.0:
        return 0.0
    return acc / total_w


def _multi_cycle_projection(
    *,
    replay_cycles: int,
    request: SimulationRequest,
    simulated_raw: List[Any],
    trust_graph_snapshot: Dict[str, Any],
    layer3_snapshot: Optional[Dict[str, Any]],
    critical_entities: List[Dict[str, Any]],
    severity_threshold: float,
    pipeline: RuntimePipeline,
) -> Dict[str, Any]:
    cycles: List[Dict[str, Any]] = []
    state_map = None
    peak_sev = 0.0
    peak_crit = 0.0
    final_sev = 0.0

    for idx in range(replay_cycles):
        cycle_number = int(request.cycle_number) + idx
        outputs, state_map = pipeline.run_from_observations(
            tenant_id=request.tenant_id,
            cycle_id=request.baseline_cycle_id,
            cycle_number=cycle_number,
            raw_observations=simulated_raw,
            trust_graph_snapshot=trust_graph_snapshot,
            layer3_state_snapshot=layer3_snapshot if idx == 0 else None,
            layer3_state_map=state_map,
            return_state=True,
        )

        summary = _guardian_summary(outputs.guardians)
        sev = float(summary.get("overall_severity_01", 0.0))
        crit_max = _critical_severity_max(outputs.guardians, critical_entities)
        crit_summary = _critical_impact_summary(
            outputs.guardians,
            critical_entities,
            threshold=severity_threshold,
        )
        crit_pct = float(crit_summary.get("impacted_pct", 0.0))
        crit_weighted_pct = float(crit_summary.get("impacted_weight_pct", 0.0))

        cycles.append(
            {
                "cycle_index": int(idx + 1),
                "overall_severity_01": round(sev, 6),
                "critical_severity_max": round(float(crit_max), 6),
                "critical_impact_pct": round(float(crit_pct), 6),
                "critical_impact_weighted_pct": round(float(crit_weighted_pct), 6),
            }
        )

        if sev > peak_sev:
            peak_sev = sev
        if crit_max > peak_crit:
            peak_crit = crit_max
        final_sev = sev

    return {
        "cycles": cycles,
        "peak_severity": round(float(peak_sev), 6),
        "peak_critical_severity": round(float(peak_crit), 6),
        "final_severity": round(float(final_sev), 6),
    }


def _extract_mitigation_candidates(mitigation: Any) -> List[Dict[str, Any]]:
    if mitigation is None:
        return []
    if isinstance(mitigation, list):
        return [m for m in mitigation if isinstance(m, dict)]
    if isinstance(mitigation, dict):
        if isinstance(mitigation.get("candidates"), list):
            return [m for m in mitigation.get("candidates") if isinstance(m, dict)]
        return [mitigation]
    return []


def _is_single_mitigation(mitigation: Any) -> bool:
    if not isinstance(mitigation, dict):
        return False
    if isinstance(mitigation.get("candidates"), list):
        return False
    return True


def _stable_action_key(action: Dict[str, Any]) -> str:
    parts = {
        "action_type": str(action.get("action_type", "")),
        "target": dict(action.get("target", {})),
        "delta": dict(action.get("delta", {})),
        "description": str(action.get("description", "")),
    }
    return _stable_json(parts)


def _stable_json(payload: Dict[str, Any]) -> str:
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _build_compromised_endpoint_steps(*, severity_threshold: float) -> List[ScenarioStep]:
    thresh = float(severity_threshold)

    def _endpoint_pairs(ctx: Dict[str, Any]) -> List[Tuple[str, Optional[str], Optional[str]]]:
        outputs = ctx.get("current_outputs")
        if outputs is None:
            return []
        pairs: List[Tuple[str, Optional[str], Optional[str]]] = []
        for ep in list(outputs.snapshot.endpoints or []):
            try:
                eid = ep.endpoint_id()
            except Exception:
                continue
            tls_v = getattr(ep, "tls_version", None)
            cipher = getattr(ep, "cipher", None)
            tls_s = str(tls_v).strip() if tls_v is not None else None
            if tls_s == "":
                tls_s = None
            cipher_s = str(cipher).strip() if cipher is not None else None
            if cipher_s == "":
                cipher_s = None
            if tls_s is None and cipher_s is None:
                continue
            pairs.append((str(eid), tls_s, cipher_s))
        pairs.sort(key=lambda t: (str(t[0]), str(t[1] or ""), str(t[2] or "")))
        return pairs

    def _infer_target_entity(ctx: Dict[str, Any]) -> Optional[str]:
        current = ctx.get("current_outputs")
        if current is None or not getattr(current, "guardians", None):
            return None
        baseline = ctx.get("baseline_outputs")
        deltas: List[Tuple[float, str]] = []
        for eid in sorted(current.guardians.keys()):
            g = current.guardians.get(eid)
            s_sev = float(getattr(g, "overall_severity_01", 0.0)) if g else 0.0
            b_sev = 0.0
            if baseline and getattr(baseline, "guardians", None):
                b = baseline.guardians.get(eid)
                if b is not None:
                    b_sev = float(getattr(b, "overall_severity_01", 0.0))
            deltas.append((s_sev - b_sev, str(eid)))
        if not deltas:
            return None
        deltas.sort(key=lambda t: (-float(t[0]), str(t[1])))
        return deltas[0][1]

    def _select_pair(ctx: Dict[str, Any], *, prefer: str) -> Tuple[Optional[str], Optional[str]]:
        pairs = _endpoint_pairs(ctx)
        if not pairs:
            return None, None

        counts: Dict[Tuple[Optional[str], Optional[str]], List[str]] = {}
        for eid, tls_v, cipher in pairs:
            key = (tls_v, cipher)
            counts.setdefault(key, []).append(str(eid))

        target = _infer_target_entity(ctx)
        exclude: Optional[Tuple[Optional[str], Optional[str]]] = None
        if target:
            for eid, tls_v, cipher in pairs:
                if eid == target:
                    exclude = (tls_v, cipher)
                    break

        keys = [k for k in counts.keys() if k != exclude]
        if not keys:
            keys = [exclude] if exclude else list(counts.keys())

        if prefer == "min":
            keys.sort(key=lambda k: (len(counts.get(k, [])), str(k[0] or ""), str(k[1] or "")))
        else:
            keys.sort(key=lambda k: (-len(counts.get(k, [])), str(k[0] or ""), str(k[1] or "")))

        chosen = keys[0] if keys else (None, None)
        return chosen[0], chosen[1]

    def _payload_with_pair(ctx: Dict[str, Any], *, prefer: str, extra: Dict[str, Any]) -> Dict[str, Any]:
        tls_v, cipher = _select_pair(ctx, prefer=prefer)
        payload = dict(extra or {})
        if tls_v is not None or cipher is not None:
            payload["tls_version"] = tls_v
            payload["cipher"] = cipher
        return payload

    def _sev(ctx: Dict[str, Any]) -> float:
        return float(ctx["metrics"].get("overall_severity", 0.0))

    def _crit(ctx: Dict[str, Any]) -> float:
        return float(ctx["metrics"].get("critical_severity_max", 0.0))

    def _blast(ctx: Dict[str, Any]) -> float:
        return float(ctx["metrics"].get("blast_radius_score", 0.0))

    def _reach(ctx: Dict[str, Any]) -> int:
        return int(ctx["metrics"].get("reachable_nodes", 0))

    def _pre_exists(ctx: Dict[str, Any]) -> bool:
        co = ctx.get("current_outputs")
        return bool(co and len(co.snapshot.endpoints) > 0)

    def _post_sev(ctx: Dict[str, Any]) -> bool:
        return _sev(ctx) > thresh

    def _post_crit(ctx: Dict[str, Any]) -> bool:
        return _crit(ctx) > 0.0

    def _post_blast(ctx: Dict[str, Any]) -> bool:
        base = ctx["baseline_outputs"]
        base_sev = 0.0
        if base and base.guardians:
            base_sev = float(_guardian_summary(base.guardians).get("overall_severity_01", 0.0))
        return _blast(ctx) > 0.0 and _sev(ctx) > base_sev

    def _post_reach(ctx: Dict[str, Any]) -> bool:
        prev_metrics = ctx.get("previous_metrics") or {}
        prev_reach = int(prev_metrics.get("reachable_nodes", 0))
        return _reach(ctx) > prev_reach

    return [
        ScenarioStep(
            name="Initial Access",
            max_repeat=2,
            _pre=_pre_exists,
            _inj=lambda _c: {"tls_version": "TLS1.2", "entropy_score": 0.75, "confidence": 0.2},
            _post=_post_sev,
        ),
        ScenarioStep(
            name="Credential Exposure",
            max_repeat=2,
            _pre=lambda c: _sev(c) > thresh,
            _inj=lambda c: _payload_with_pair(c, prefer="min", extra={"entropy_score": 0.85, "confidence": 0.25}),
            _post=_post_crit,
        ),
        ScenarioStep(
            name="Lateral Movement",
            max_repeat=2,
            _pre=lambda c: _blast(c) > 0.0,
            _inj=lambda c: _payload_with_pair(c, prefer="max", extra={"entropy_score": 0.90, "confidence": 0.3}),
            _post=_post_reach,
        ),
        ScenarioStep(
            name="Privilege Escalation",
            max_repeat=2,
            _pre=lambda c: _crit(c) > 0.0,
            _inj=lambda c: _payload_with_pair(c, prefer="max", extra={"entropy_score": 0.95, "confidence": 0.35}),
            _post=_post_blast,
        ),
    ]


def _hash_response(response: SimulationResponse) -> str:
    import hashlib
    import json

    payload = response.to_dict()
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _response_from_cached_payload(payload: Dict[str, Any]) -> SimulationResponse:
    required = [
        "simulation_id",
        "tenant_id",
        "baseline_cycle_id",
        "scenario_id",
        "scenario_params",
        "baseline_guardian",
        "simulated_guardian",
        "deltas",
        "blast_radius",
        "attack_paths",
        "critical_impact_summary",
        "critical_entity_deltas",
        "concentration_metrics",
        "mitigation_analysis",
        "multi_cycle_projection",
        "narrative",
        "scenario_progression",
    ]
    for key in required:
        if key not in payload:
            raise RuntimeError(f"Corrupt simulation artifact: missing {key}")
    try:
        return SimulationResponse(
            simulation_id=str(payload["simulation_id"]),
            tenant_id=str(payload["tenant_id"]),
            baseline_cycle_id=str(payload["baseline_cycle_id"]),
            scenario_id=str(payload["scenario_id"]),
            scenario_params=dict(payload.get("scenario_params", {})),
            baseline_guardian=dict(payload.get("baseline_guardian", {})),
            simulated_guardian=dict(payload.get("simulated_guardian", {})),
            mitigation_guardian=(
                dict(payload["mitigation_guardian"])
                if isinstance(payload.get("mitigation_guardian"), dict)
                else None
            ),
            deltas={str(k): dict(v) for k, v in dict(payload.get("deltas", {})).items()},
            blast_radius=dict(payload.get("blast_radius", {})),
            attack_paths=list(payload.get("attack_paths", [])),
            critical_impact_summary=dict(payload.get("critical_impact_summary", {})),
            critical_entity_deltas={
                str(k): dict(v)
                for k, v in dict(payload.get("critical_entity_deltas", {})).items()
            },
            concentration_metrics=dict(payload.get("concentration_metrics", {})),
            mitigation_analysis=dict(payload.get("mitigation_analysis", {})),
            multi_cycle_projection=dict(payload.get("multi_cycle_projection", {})),
            narrative=dict(payload.get("narrative", {})),
            scenario_progression=list(payload.get("scenario_progression", [])),
        )
    except Exception as exc:
        raise RuntimeError("Corrupt simulation artifact") from exc


def _list_production_files(*, production_root: str, tenant_id: str) -> set[str]:
    from pathlib import Path

    tenant_path = Path(production_root) / "tenant_data_storage" / "tenants" / tenant_id
    if not tenant_path.exists():
        return set()
    out: set[str] = set()
    for p in tenant_path.rglob("*"):
        if p.is_file():
            out.add(str(p.relative_to(tenant_path)))
    return out


def _snapshot_hash(snapshot: Dict[str, Any]) -> str:
    import hashlib
    import json

    endpoints = snapshot.get("endpoints", []) or []
    if not isinstance(endpoints, list):
        raise RuntimeError("Baseline snapshot endpoints invalid")

    canonical: List[Dict[str, Any]] = []
    for e in endpoints:
        if not isinstance(e, dict):
            continue
        canonical.append(
            {
                "hostname": e.get("hostname"),
                "port": e.get("port"),
                "tls_version": e.get("tls_version"),
                "certificate_sha256": e.get("certificate_sha256"),
                "certificate_expiry_unix_ms": e.get("certificate_expiry_unix_ms"),
                "ports_responding": sorted(set(e.get("ports_responding", []) or [])),
                "services_detected": sorted(set(e.get("services_detected", []) or [])),
                "discovered_by": sorted(set(e.get("discovered_by", []) or [])),
                "confidence": round(float(e.get("confidence", 0.0)), 4),
                "tls_jarm": e.get("tls_jarm"),
            }
        )

    canonical.sort(key=lambda item: (str(item.get("hostname", "")), int(item.get("port", 0) or 0)))
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _blast_to_dict(blast: BlastRadius) -> Dict[str, Any]:
    return {
        "impacted_nodes": int(blast.impacted_nodes),
        "depth": int(blast.depth),
        "spread_pct": float(blast.spread_pct),
        "amplification": float(blast.amplification),
        "confidence_drop": float(blast.confidence_drop),
        "score": float(blast.score),
    }


def _rank_paths_payload(
    *,
    trust_graph: Any,
    origin_node_id: str,
    max_depth: int,
    max_paths: int,
    max_expansions: int,
    top_k_edges: Optional[int],
    weight_min: float,
    critical_nodes: List[str],
) -> List[Dict[str, Any]]:
    if not origin_node_id:
        return []
    ranked = rank_paths(
        trust_graph=trust_graph,
        start_node_id=origin_node_id,
        max_depth=int(max_depth),
        max_paths=int(max_paths),
        max_expansions=int(max_expansions),
        top_k_edges=top_k_edges,
        weight_min=float(weight_min),
        critical_targets=list(critical_nodes),
    )
    return [{"nodes": p.nodes, "weight": p.weight} for p in ranked]


def _critical_severity_reduction(
    simulated: Dict[str, Any],
    mitigated: Dict[str, Any],
    critical_entities: List[Dict[str, Any]],
) -> Tuple[float, float]:
    ids = _critical_entity_ids(critical_entities)
    if not ids:
        return 0.0, 0.0
    reductions = []
    for eid in ids:
        s = simulated.get(eid)
        m = mitigated.get(eid)
        s_sev = float(getattr(s, "overall_severity_01", 0.0)) if s else 0.0
        m_sev = float(getattr(m, "overall_severity_01", 0.0)) if m else 0.0
        reductions.append(max(0.0, s_sev - m_sev))
    if not reductions:
        return 0.0, 0.0
    avg = sum(reductions) / float(len(reductions))
    mx = max(reductions) if reductions else 0.0
    return avg, mx


def _critical_weighted_severity_reduction(
    simulated: Dict[str, Any],
    mitigated: Dict[str, Any],
    critical_entities: List[Dict[str, Any]],
) -> float:
    ids = _critical_entity_ids(critical_entities)
    weights = _critical_weights(critical_entities)
    if not ids:
        return 0.0
    total_w = 0.0
    acc = 0.0
    for eid in ids:
        s = simulated.get(eid)
        m = mitigated.get(eid)
        s_sev = float(getattr(s, "overall_severity_01", 0.0)) if s else 0.0
        m_sev = float(getattr(m, "overall_severity_01", 0.0)) if m else 0.0
        w = float(weights.get(eid, 0.0))
        total_w += w
        acc += w * max(0.0, s_sev - m_sev)
    if total_w <= 0.0:
        return 0.0
    return acc / total_w


def _mitigation_analysis(
    *,
    request: SimulationRequest,
    max_mitigations: int,
    baseline_outputs: PipelineOutputs,
    simulated_outputs: PipelineOutputs,
    simulated_dicts: List[Dict[str, Any]],
    trust_graph_snapshot: Dict[str, Any],
    layer3_snapshot: Optional[Dict[str, Any]],
    severity_threshold: float,
    critical_entities: List[Dict[str, Any]],
    simulated_blast: BlastRadius,
    adapter: ObservationAdapter,
    mitigation_engine: MitigationEngine,
    pipeline: RuntimePipeline,
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    max_candidates = min(5, max(0, int(max_mitigations)))
    if max_candidates <= 0:
        return {
            "candidates": [],
            "candidates_evaluated": 0,
            "search_depth": 0,
            "best_action": None,
            "best_action_set": [],
            "metrics": {},
        }, None

    candidates_data = _extract_mitigation_candidates(request.mitigation)
    if not candidates_data:
        return {
            "candidates": [],
            "candidates_evaluated": 0,
            "search_depth": 0,
            "best_action": None,
            "best_action_set": [],
            "metrics": {},
        }, None

    # Deterministic sort by stable action key
    candidates_data = candidates_data[:max_candidates]
    candidates_data.sort(key=lambda d: _stable_action_key(d))
    simulated_summary = _guardian_summary(simulated_outputs.guardians)
    simulated_critical = _critical_impact_summary(
        simulated_outputs.guardians,
        critical_entities,
        threshold=severity_threshold,
    )

    def _action_from_data(data: Dict[str, Any]) -> MitigationAction:
        return MitigationAction(
            action_type=str(data.get("action_type", "unknown")),
            target=dict(data.get("target", {})),
            delta=dict(data.get("delta", {})),
            description=str(data.get("description", "")),
        )

    def _metrics_tuple(m: Dict[str, Any]) -> Tuple[float, float, float, float]:
        return (
            float(m.get("critical_severity_reduction_weighted", 0.0)),
            float(m.get("critical_impact_weighted_reduction", 0.0)),
            float(m.get("global_severity_reduction", 0.0)),
            float(m.get("confidence_improvement", 0.0)),
        )

    def _is_strictly_better(a: Tuple[float, float, float, float], b: Tuple[float, float, float, float]) -> bool:
        for i in range(len(a)):
            if a[i] > b[i]:
                return True
            if a[i] < b[i]:
                return False
        return False

    def _evaluate_action_set(actions: List[MitigationAction]) -> Dict[str, Any]:
        current_dicts = list(simulated_dicts)
        for act in actions:
            current_dicts = mitigation_engine.apply(current_dicts, act)

        current_records = [adapter.from_dict(d) for d in current_dicts]
        current_raw = [adapter.to_protocol_raw(r) for r in current_records]

        current_outputs = pipeline.run_from_observations(
            tenant_id=request.tenant_id,
            cycle_id=request.baseline_cycle_id,
            cycle_number=request.cycle_number,
            raw_observations=current_raw,
            trust_graph_snapshot=trust_graph_snapshot,
            layer3_state_snapshot=layer3_snapshot,
        )

        current_summary = _guardian_summary(current_outputs.guardians)
        current_critical = _critical_impact_summary(
            current_outputs.guardians,
            critical_entities,
            threshold=severity_threshold,
        )

        current_blast = compute_blast_radius(
            trust_graph=current_outputs.trust_graph,
            predictions=current_outputs.predictions,
            baseline_predictions=baseline_outputs.predictions,
            severity_threshold=severity_threshold,
        )

        critical_sev_reduction_avg, critical_sev_reduction_max = _critical_severity_reduction(
            simulated_outputs.guardians,
            current_outputs.guardians,
            critical_entities,
        )
        critical_sev_reduction_weighted = _critical_weighted_severity_reduction(
            simulated_outputs.guardians,
            current_outputs.guardians,
            critical_entities,
        )
        global_sev_reduction = float(simulated_summary.get("overall_severity_01", 0.0)) - float(
            current_summary.get("overall_severity_01", 0.0)
        )
        conf_improve = float(current_summary.get("overall_confidence_01", 0.0)) - float(
            simulated_summary.get("overall_confidence_01", 0.0)
        )
        critical_impact_reduction = float(simulated_critical.get("impacted_pct", 0.0)) - float(
            current_critical.get("impacted_pct", 0.0)
        )
        critical_impact_weighted_reduction = float(simulated_critical.get("impacted_weight_pct", 0.0)) - float(
            current_critical.get("impacted_weight_pct", 0.0)
        )
        blast_score_reduction = float(simulated_blast.score) - float(current_blast.score)
        blast_spread_reduction = float(simulated_blast.spread_pct) - float(current_blast.spread_pct)

        return {
            "metrics": {
                "critical_severity_reduction_avg": round(float(critical_sev_reduction_avg), 6),
                "critical_severity_reduction_max": round(float(critical_sev_reduction_max), 6),
                "critical_severity_reduction_weighted": round(float(critical_sev_reduction_weighted), 6),
                "global_severity_reduction": round(float(global_sev_reduction), 6),
                "confidence_improvement": round(float(conf_improve), 6),
                "critical_impact_reduction": round(float(critical_impact_reduction), 6),
                "critical_impact_weighted_reduction": round(float(critical_impact_weighted_reduction), 6),
                "blast_score_reduction": round(float(blast_score_reduction), 6),
                "blast_spread_reduction": round(float(blast_spread_reduction), 6),
            },
            "guardian_summary": dict(current_summary),
            "critical_summary": dict(current_critical),
            "blast_radius": _blast_to_dict(current_blast),
        }

    actions = [_action_from_data(d) for d in candidates_data]
    action_keys = [_stable_action_key(d) for d in candidates_data]

    results: List[Dict[str, Any]] = []
    mitigation_guardian: Optional[Dict[str, Any]] = None
    eval_count = 0
    max_evals = 10
    best_metrics_tuple: Tuple[float, float, float, float] = (0.0, 0.0, 0.0, 0.0)
    best_action_set: List[Dict[str, Any]] = []
    best_action_key = "\uffff"

    # Evaluate singles
    single_metrics_by_key: Dict[str, Tuple[float, float, float, float]] = {}
    for idx, action in enumerate(actions):
        if eval_count >= max_evals:
            break
        eval_count += 1
        payload = _evaluate_action_set([action])
        metrics = payload["metrics"]
        key = action_keys[idx]
        single_metrics_by_key[key] = _metrics_tuple(metrics)

        result = {
            "action_set": [
                {
                    "action_type": action.action_type,
                    "target": dict(action.target),
                    "delta": dict(action.delta),
                    "description": action.description,
                }
            ],
            "metrics": dict(metrics),
            "guardian_summary": dict(payload["guardian_summary"]),
            "critical_summary": dict(payload["critical_summary"]),
            "blast_radius": dict(payload["blast_radius"]),
        }
        results.append(result)

        mt = _metrics_tuple(metrics)
        if not best_action_set or _is_strictly_better(mt, best_metrics_tuple) or (
            mt == best_metrics_tuple and key < best_action_key
        ):
            best_metrics_tuple = mt
            best_action_set = list(result["action_set"])
            best_action_key = key
            if mitigation_guardian is None and _is_single_mitigation(request.mitigation):
                mitigation_guardian = dict(payload["guardian_summary"])

    # Evaluate pairs (depth <= 2)
    search_depth = 1
    if len(actions) >= 2 and eval_count < max_evals:
        search_depth = 2
        for i in range(len(actions)):
            for j in range(i + 1, len(actions)):
                if eval_count >= max_evals:
                    break
                key_a = action_keys[i]
                key_b = action_keys[j]
                ub = tuple(
                    (single_metrics_by_key.get(key_a, (0.0, 0.0, 0.0, 0.0))[k]
                     + single_metrics_by_key.get(key_b, (0.0, 0.0, 0.0, 0.0))[k])
                    for k in range(4)
                )
                # prune only if upper bound strictly worse than best
                if ub < best_metrics_tuple:
                    continue

                eval_count += 1
                payload = _evaluate_action_set([actions[i], actions[j]])
                metrics = payload["metrics"]
                mt = _metrics_tuple(metrics)

                action_set = [
                    {
                        "action_type": actions[i].action_type,
                        "target": dict(actions[i].target),
                        "delta": dict(actions[i].delta),
                        "description": actions[i].description,
                    },
                    {
                        "action_type": actions[j].action_type,
                        "target": dict(actions[j].target),
                        "delta": dict(actions[j].delta),
                        "description": actions[j].description,
                    },
                ]
                pair_key = f"{key_a}|{key_b}"

                results.append(
                    {
                        "action_set": action_set,
                        "metrics": dict(metrics),
                        "guardian_summary": dict(payload["guardian_summary"]),
                        "critical_summary": dict(payload["critical_summary"]),
                        "blast_radius": dict(payload["blast_radius"]),
                    }
                )

                if not best_action_set or _is_strictly_better(mt, best_metrics_tuple) or (
                    mt == best_metrics_tuple and pair_key < best_action_key
                ):
                    best_metrics_tuple = mt
                    best_action_set = list(action_set)
                    best_action_key = pair_key
            if eval_count >= max_evals:
                break

    # Deterministic sort of results
    results.sort(
        key=lambda r: (
            -float(r["metrics"]["critical_severity_reduction_weighted"]),
            -float(r["metrics"]["critical_impact_weighted_reduction"]),
            -float(r["metrics"]["global_severity_reduction"]),
            -float(r["metrics"]["confidence_improvement"]),
            _stable_action_key(r["action_set"][0]) if r.get("action_set") else "",
        )
    )

    best_action = None
    if best_action_set and len(best_action_set) == 1:
        best_action = dict(best_action_set[0])

    best_metrics = {}
    if results:
        best_metrics = dict(results[0]["metrics"])

    return {
        "candidates": results,
        "candidates_evaluated": int(eval_count),
        "search_depth": int(search_depth),
        "best_action": best_action,
        "best_action_set": list(best_action_set),
        "metrics": dict(best_metrics),
    }, mitigation_guardian
