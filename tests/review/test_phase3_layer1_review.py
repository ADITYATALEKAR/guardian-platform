from __future__ import annotations

import json
from pathlib import Path
from typing import List

import pytest

from layers.layer0_observation.fingerprints.fingerprint_types import Fingerprint
from layers.layer1_trust_graph_dependency_modeling.dependency_builder import (
    apply_graph_delta,
    build_trust_graph_delta,
)
from layers.layer1_trust_graph_dependency_modeling.edges import Edge, EdgeType
from layers.layer1_trust_graph_dependency_modeling.graph import TrustGraph
from layers.layer1_trust_graph_dependency_modeling.nodes import (
    EndpointNode,
    EvidenceNode,
    NodeType,
)


def _make_fingerprints() -> List[Fingerprint]:
    return [
        Fingerprint(
            fingerprint_id="fp_1",
            entity_id="api.example.com:443",
            kind="handshake_fp_v1",
            version=1,
            created_ms=1000,
            hash="h1",
            vector=[0.1, 0.2, 0.3],
            quality=0.8,
            source_fields={"coherence_score": 0.9},
        ),
        Fingerprint(
            fingerprint_id="fp_2",
            entity_id="api.example.com:443",
            kind="tls_cert_fp_v1",
            version=1,
            created_ms=1010,
            hash="h2",
            vector=[0.1, 0.2, 0.31],
            quality=0.7,
            source_fields={},
        ),
        Fingerprint(
            fingerprint_id="fp_3",
            entity_id="api.example.com:443",
            kind="issuer_fp_v1",
            version=1,
            created_ms=1020,
            hash="h3",
            vector=[0.4, 0.2, 0.1],
            quality=0.6,
            source_fields={},
        ),
    ]


def _build_graph(fingerprints: List[Fingerprint]) -> TrustGraph:
    graph = TrustGraph()
    delta = build_trust_graph_delta(fingerprints, ingestion_ts_ms=2000)
    apply_graph_delta(graph, delta)
    graph.validate_integrity()
    return graph


def test_phase3_layer1_static_boundary_no_forbidden_imports() -> None:
    root = Path("layers/layer1_trust_graph_dependency_modeling")
    py_files = sorted(root.glob("*.py"))
    assert py_files, "layer1 files not found"

    forbidden = [
        "layers.layer2_",
        "layers.layer3_",
        "layers.layer4_",
        "simulator.",
        "infrastructure.storage_manager",
        "infrastructure.operator_plane",
    ]
    for path in py_files:
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in text, f"forbidden coupling '{token}' found in {path}"


def test_phase3_layer1_replay_determinism_under_input_permutation() -> None:
    fps = _make_fingerprints()
    g1 = _build_graph(fps)
    g2 = _build_graph(list(reversed(fps)))

    sig1 = g1.signature()
    sig2 = g2.signature()
    assert sig1 == sig2

    snap1 = json.dumps(g1.to_snapshot_dict(created_at_ms=2000), sort_keys=True, separators=(",", ":"))
    snap2 = json.dumps(g2.to_snapshot_dict(created_at_ms=2000), sort_keys=True, separators=(",", ":"))
    assert snap1 == snap2


def test_phase3_layer1_snapshot_roundtrip_and_corruption_fail_loud() -> None:
    graph = _build_graph(_make_fingerprints())
    snapshot = graph.to_snapshot_dict(created_at_ms=3000)
    restored = TrustGraph.from_snapshot_dict(snapshot)
    restored.validate_integrity()
    assert restored.signature() == graph.signature()

    corrupt = json.loads(json.dumps(snapshot))
    assert corrupt["edges"], "expected at least one edge"
    corrupt["edges"][0]["edge_type"] = "invalid_edge_type"
    with pytest.raises(ValueError):
        TrustGraph.from_snapshot_dict(corrupt)


def test_phase3_layer1_prune_evidence_is_bounded_and_deterministic() -> None:
    graph = TrustGraph()
    endpoint_id = "endpoint:api.example.com:443"
    graph.add_node(
        EndpointNode(
            node_id=endpoint_id,
            node_type=NodeType.ENDPOINT,
            created_at_ms=1,
            metadata={"entity_id": "api.example.com:443"},
        )
    )

    for i in range(10):
        evidence_id = f"evidence::fp_{i}"
        graph.add_node(
            EvidenceNode(
                node_id=evidence_id,
                node_type=NodeType.EVIDENCE,
                created_at_ms=1000 + i,
                metadata={},
                fingerprint_id=f"fp_{i}",
                kind="handshake_fp_v1",
                hash=f"h{i}",
                vector=(0.1, 0.2, 0.3),
                quality=0.5,
                created_ms=1000 + i,
                source_fields={},
            )
        )
        graph.add_edge(
            Edge(
                edge_id=f"edge:produces:{endpoint_id}->{evidence_id}",
                from_node_id=endpoint_id,
                to_node_id=evidence_id,
                edge_type=EdgeType.PRODUCES,
                first_seen_ms=1000 + i,
                last_seen_ms=1000 + i,
                count=1,
                weight=0.5,
                metadata={"relation": "endpoint_produces_evidence"},
            )
        )

    graph.prune_evidence(max_per_endpoint=3)
    graph.validate_integrity()

    remaining_ids = sorted(
        node.node_id
        for node in graph.nodes.values()
        if getattr(node, "node_type", None) == NodeType.EVIDENCE
    )
    assert remaining_ids == [
        "evidence::fp_7",
        "evidence::fp_8",
        "evidence::fp_9",
    ]
