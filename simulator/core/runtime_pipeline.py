"""
Runtime Reuse Pipeline
======================

Deterministic pipeline that reuses Layers 0–4 as-is.

No storage access.
No runtime mutations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from infrastructure.unified_discovery_v2.snapshot_builder import SnapshotBuilder
from layers.layer0_observation.acquisition.observation_bridge import ObservationBridge
from layers.layer1_trust_graph_dependency_modeling.graph import TrustGraph
from layers.layer1_trust_graph_dependency_modeling.dependency_builder import (
    build_trust_graph_delta,
    apply_graph_delta,
)
from layers.layer2_risk_and_weakness_analysis.layer2_engine import Layer2Engine
from layers.layer3_prediction_and_learning.layer3_engine import Layer3Engine
from layers.layer3_prediction_and_learning.learning_state_v2 import LearningState
from layers.layer4_decision_logic_guardian.guardian_core import GuardianCore
from layers.layer4_decision_logic_guardian.thresholds import GuardianThresholds

from layers.layer2_risk_and_weakness_analysis.weakness_contracts import WeaknessBundle
from layers.layer3_prediction_and_learning.prediction_contracts import PredictionBundle
from layers.layer4_decision_logic_guardian.contracts.guardian_query_response import GuardianQueryResponse
from infrastructure.unified_discovery_v2.models import DiscoverySnapshot

from simulator.core.physics_extractor import extract_physics_signals
from simulator.core.graph_slice_builder import build_graph_slice


@dataclass(frozen=True, slots=True)
class PipelineOutputs:
    snapshot: DiscoverySnapshot
    trust_graph: TrustGraph
    weaknesses: Dict[str, WeaknessBundle]
    predictions: Dict[str, PredictionBundle]
    guardians: Dict[str, GuardianQueryResponse]


class RuntimePipeline:
    """
    Deterministic pipeline for simulation runs.

    This pipeline reuses SnapshotBuilder, Layer2, Layer3, and Layer4
    without modifying any runtime code.
    """

    def __init__(self) -> None:
        self._snapshot_builder = SnapshotBuilder()
        self._bridge = ObservationBridge()
        self._layer2 = Layer2Engine()
        self._layer3 = Layer3Engine()
        self._guardian = GuardianCore(thresholds=GuardianThresholds())

    def run_from_observations(
        self,
        *,
        tenant_id: str,
        cycle_id: str,
        cycle_number: int,
        raw_observations: Sequence[Any],
        trust_graph_snapshot: Optional[Dict[str, Any]] = None,
        layer3_state_snapshot: Optional[Dict[str, Any]] = None,
        layer3_state_map: Optional[Dict[str, LearningState]] = None,
        physics_signals_by_entity: Optional[Dict[str, Dict[str, Any]]] = None,
        baseline_by_entity: Optional[Dict[str, Dict[str, Any]]] = None,
        return_state: bool = False,
    ) -> Union[PipelineOutputs, Tuple[PipelineOutputs, Dict[str, LearningState]]]:
        if not tenant_id:
            raise ValueError("tenant_id cannot be empty")
        if not cycle_id:
            raise ValueError("cycle_id cannot be empty")

        # --------------------------------------------------
        # SnapshotBuilder (Layer 0 boundary)
        # --------------------------------------------------
        snapshot, _diff, _stats = self._snapshot_builder.build_snapshot(
            cycle_id=cycle_id,
            cycle_number=int(cycle_number),
            raw_observations=list(raw_observations),
            previous_snapshot=None,
        )

        # --------------------------------------------------
        # Fingerprint extraction (Layer 0 physics)
        # --------------------------------------------------
        fingerprints_by_entity: Dict[str, List[Any]] = {}
        grouped = self._group_observations_by_entity(raw_observations)
        for entity_id, series in grouped.items():
            fps = self._bridge.process_series(list(series))
            if fps:
                fingerprints_by_entity.setdefault(entity_id, []).extend(fps)

        # --------------------------------------------------
        # TrustGraph replay (Layer 1 pipeline)
        # --------------------------------------------------
        trust_graph = TrustGraph()
        if trust_graph_snapshot is not None:
            trust_graph = TrustGraph.from_snapshot_dict(trust_graph_snapshot)
            trust_graph.validate_integrity()

        for entity_id in sorted(fingerprints_by_entity.keys()):
            fps = fingerprints_by_entity.get(entity_id, [])
            if not fps:
                continue
            delta = build_trust_graph_delta(
                fps,
                ingestion_ts_ms=snapshot.timestamp_unix_ms,
            )
            apply_graph_delta(trust_graph, delta)

        trust_graph.prune_evidence(max_per_endpoint=trust_graph.MAX_EVIDENCE_PER_ENDPOINT)
        trust_graph.validate_integrity()

        # --------------------------------------------------
        # Layer 2 -> Layer 3 -> Layer 4 (per endpoint)
        # --------------------------------------------------
        weaknesses: Dict[str, WeaknessBundle] = {}
        predictions: Dict[str, PredictionBundle] = {}
        guardians: Dict[str, GuardianQueryResponse] = {}

        # --------------------------------------------------
        # Layer3 state replay (read-only snapshot)
        # --------------------------------------------------
        if layer3_state_map is not None:
            state_map = dict(layer3_state_map)
        elif layer3_state_snapshot is not None:
            state_map = LearningState.from_snapshot(layer3_state_snapshot, tenant_id=tenant_id)
        else:
            state_map = {}

        ps_map = physics_signals_by_entity or {}
        bl_map = baseline_by_entity or {}

        state_out: Dict[str, LearningState] = {}

        for endpoint in snapshot.endpoints:
            entity_id = endpoint.endpoint_id()
            fps = fingerprints_by_entity.get(entity_id, [])

            if entity_id in ps_map:
                physics = dict(ps_map.get(entity_id, {}))
            else:
                physics = extract_physics_signals(fps)
            baseline = dict(bl_map.get(entity_id, {}))

            graph_slice = build_graph_slice(entity_id=entity_id, trust_graph=trust_graph)

            weakness_bundle = self._layer2.evaluate(
                entity_id=entity_id,
                session_id=cycle_id,
                ts_ms=snapshot.timestamp_unix_ms,
                fingerprints=fps,
                physics_signals=physics,
                baseline=baseline,
                graph_slice=graph_slice,
            )

            if return_state:
                pred_bundle, new_state = self._layer3.predict(
                    weakness_bundle=weakness_bundle.to_dict(),
                    state=state_map.get(entity_id),
                    return_state=True,
                )
                state_out[entity_id] = new_state
            else:
                pred_bundle = self._layer3.predict(
                    weakness_bundle=weakness_bundle.to_dict(),
                    state=state_map.get(entity_id),
                    return_state=False,
                )

            guardian_response = self._guardian.evaluate(
                tenant_id=tenant_id,
                prediction_bundle=pred_bundle.to_dict(),
                policy_mode="disabled",
            )

            weaknesses[entity_id] = weakness_bundle
            predictions[entity_id] = pred_bundle
            guardians[entity_id] = guardian_response

        outputs = PipelineOutputs(
            snapshot=snapshot,
            trust_graph=trust_graph,
            weaknesses=weaknesses,
            predictions=predictions,
            guardians=guardians,
        )
        if return_state:
            return outputs, state_out
        return outputs

    def _group_observations_by_entity(self, observations: Sequence[Any]) -> Dict[str, List[Any]]:
        grouped: Dict[str, List[Any]] = {}
        for obs in observations:
            entity_id = getattr(obs, "entity_id", None) or getattr(obs, "endpoint", None)
            if not entity_id:
                continue
            grouped.setdefault(str(entity_id), []).append(obs)
        return grouped
