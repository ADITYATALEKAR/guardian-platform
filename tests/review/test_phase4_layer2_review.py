from __future__ import annotations

from pathlib import Path
from typing import List

from layers.layer0_observation.fingerprints.fingerprint_types import Fingerprint
from layers.layer1_trust_graph_dependency_modeling.edges import Edge, EdgeType
from layers.layer1_trust_graph_dependency_modeling.nodes import EvidenceNode, NodeType
from layers.layer2_risk_and_weakness_analysis.graph_slice import GraphSlice
from layers.layer2_risk_and_weakness_analysis.layer2_engine import Layer2Engine
from layers.layer3_prediction_and_learning.layer3_engine import Layer3Engine


def _fingerprints() -> List[Fingerprint]:
    return [
        Fingerprint(
            fingerprint_id="fp_handshake",
            entity_id="api.example.com:443",
            kind="handshake_fp_v1",
            version=1,
            created_ms=1000,
            hash="h_handshake",
            vector=[0.1, 0.2],
            quality=0.9,
            source_fields={},
        ),
        Fingerprint(
            fingerprint_id="fp_coh",
            entity_id="api.example.com:443",
            kind="coherence_fp_v1",
            version=1,
            created_ms=1010,
            hash="h_coh",
            vector=[0.2, 0.2],
            quality=0.7,
            source_fields={},
        ),
        Fingerprint(
            fingerprint_id="fp_drift",
            entity_id="api.example.com:443",
            kind="drift_fp_v1",
            version=1,
            created_ms=1020,
            hash="h_drift",
            vector=[0.3, 0.2],
            quality=0.8,
            source_fields={},
        ),
        Fingerprint(
            fingerprint_id="fp_entropy",
            entity_id="api.example.com:443",
            kind="entropy_histogram_fp_v1",
            version=1,
            created_ms=1030,
            hash="h_entropy",
            vector=[0.4, 0.2],
            quality=0.6,
            source_fields={},
        ),
        Fingerprint(
            fingerprint_id="fp_fallback",
            entity_id="api.example.com:443",
            kind="fallback_path_fp_v1",
            version=1,
            created_ms=1040,
            hash="h_fallback",
            vector=[0.5, 0.2],
            quality=0.6,
            source_fields={},
        ),
        Fingerprint(
            fingerprint_id="fp_transition",
            entity_id="api.example.com:443",
            kind="transition_fp_v1",
            version=1,
            created_ms=1050,
            hash="h_transition",
            vector=[0.6, 0.2],
            quality=0.6,
            source_fields={},
        ),
    ]


def _physics_signals() -> dict:
    return {
        "coherence_score": 0.2,
        "drift_rate": 0.95,
        "momentum": 0.9,
        "entropy_value": 0.1,
        "entropy_decay_rate": 0.8,
        "fallback_rate": 0.8,
        "transition_prev": 0.0,
        "transition_curr": 1.0,
    }


def _baseline() -> dict:
    return {
        "baseline_coherence": 0.9,
        "coherence_std": 0.1,
        "baseline_drift_mean": 0.2,
        "baseline_drift_std": 0.1,
        "baseline_entropy_mean": 0.8,
        "baseline_entropy_std": 0.1,
        "entropy_floor": 0.2,
        "baseline_fallback_rate": 0.1,
    }


def _graph_slice() -> GraphSlice:
    root_a = EvidenceNode(
        node_id="evidence::root_a",
        node_type=NodeType.EVIDENCE,
        created_at_ms=1000,
        metadata={},
        fingerprint_id="root_a",
        kind="handshake_fp_v1",
        hash="ha",
        vector=(0.1, 0.2),
        quality=0.9,
        created_ms=1000,
        source_fields={},
    )
    root_b = EvidenceNode(
        node_id="evidence::root_b",
        node_type=NodeType.EVIDENCE,
        created_at_ms=1010,
        metadata={},
        fingerprint_id="root_b",
        kind="drift_fp_v1",
        hash="hb",
        vector=(0.1, 0.21),
        quality=0.8,
        created_ms=1010,
        source_fields={},
    )
    neighbor = EvidenceNode(
        node_id="evidence::neighbor",
        node_type=NodeType.EVIDENCE,
        created_at_ms=1020,
        metadata={},
        fingerprint_id="neighbor",
        kind="transition_fp_v1",
        hash="hc",
        vector=(0.1, 0.22),
        quality=0.7,
        created_ms=1020,
        source_fields={},
    )
    edges = (
        Edge(
            edge_id="edge:temporal:root_a->neighbor",
            from_node_id=root_a.node_id,
            to_node_id=neighbor.node_id,
            edge_type=EdgeType.TEMPORAL_SEQUENCE,
            weight=0.9,
            count=1,
        ),
        Edge(
            edge_id="edge:similarity:root_b->neighbor",
            from_node_id=root_b.node_id,
            to_node_id=neighbor.node_id,
            edge_type=EdgeType.VECTOR_SIMILARITY,
            weight=0.8,
            count=1,
        ),
    )
    return GraphSlice(
        evidence_nodes=(root_a, root_b, neighbor),
        edges=edges,
        root_evidence_ids=(root_a.node_id, root_b.node_id),
        identity_neighbor_count=2,
        material_neighbor_count=1,
    )


def test_phase4_layer2_static_boundary_no_forbidden_imports() -> None:
    root = Path("layers/layer2_risk_and_weakness_analysis")
    py_files = sorted(root.glob("*.py"))
    assert py_files

    forbidden = [
        "layers.layer4_",
        "simulator.",
        "infrastructure.storage_manager",
        "infrastructure.operator_plane",
    ]
    for path in py_files:
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in text, f"forbidden coupling '{token}' found in {path}"


def test_phase4_layer2_deterministic_output_for_fixed_inputs() -> None:
    engine = Layer2Engine()
    fps = _fingerprints()
    bundle_a = engine.evaluate(
        entity_id="api.example.com:443",
        session_id="cycle_1",
        ts_ms=123456,
        fingerprints=fps,
        physics_signals=_physics_signals(),
        baseline=_baseline(),
        graph_slice=_graph_slice(),
    )
    bundle_b = engine.evaluate(
        entity_id="api.example.com:443",
        session_id="cycle_1",
        ts_ms=123456,
        fingerprints=list(reversed(fps)),
        physics_signals=_physics_signals(),
        baseline=_baseline(),
        graph_slice=_graph_slice(),
    )

    assert bundle_a.to_dict() == bundle_b.to_dict()
    assert len(bundle_a.signals) <= bundle_a.MAX_SIGNALS
    for signal in bundle_a.signals:
        assert 0.0 <= signal.severity_01 <= 1.0
        assert 0.0 <= signal.confidence_01 <= 1.0
        assert len(signal.evidence_refs) <= signal.MAX_EVIDENCE_REFS
        assert len(signal.metrics) <= signal.MAX_METRICS


def test_phase4_layer2_missing_graph_slice_and_layer3_contract_compatibility() -> None:
    engine = Layer2Engine()
    bundle = engine.evaluate(
        entity_id="api.example.com:443",
        session_id="cycle_2",
        ts_ms=999,
        fingerprints=_fingerprints(),
        physics_signals=_physics_signals(),
        baseline=_baseline(),
        graph_slice=None,
    )
    payload = bundle.to_dict()
    layer3 = Layer3Engine()
    prediction = layer3.predict(weakness_bundle=payload)
    pred_payload = prediction.to_dict()

    assert isinstance(pred_payload, dict)
    assert "signals" in pred_payload


def test_phase4_layer2_failure_injection_nonnumeric_inputs_do_not_crash() -> None:
    engine = Layer2Engine()
    bundle = engine.evaluate(
        entity_id="",
        session_id="",
        ts_ms=-42,
        fingerprints=[{"kind": None, "hash": None, "fingerprint_id": None}],
        physics_signals={
            "coherence_score": "nan",
            "drift_rate": "bad",
            "momentum": None,
            "entropy_value": float("inf"),
            "entropy_decay_rate": float("-inf"),
            "fallback_rate": {"oops": 1},
            "transition_prev": [],
            "transition_curr": {},
        },
        baseline={"baseline_coherence": "x", "entropy_floor": "y"},
        graph_slice=None,
    )

    payload = bundle.to_dict()
    assert payload["entity_id"] == "unknown"
    assert payload["session_id"] == "unknown"
    assert payload["ts_ms"] == 0
    assert len(payload["signals"]) <= bundle.MAX_SIGNALS
