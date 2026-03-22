from __future__ import annotations

from typing import Any, Dict, Sequence, List

from layers.layer1_trust_graph_dependency_modeling.edges import EdgeType
from layers.layer1_trust_graph_dependency_modeling.graph import TrustGraph
from layers.layer1_trust_graph_dependency_modeling.nodes import EvidenceNode
from layers.layer2_risk_and_weakness_analysis.graph_slice import GraphSlice


def extract_physics_signals(fps: Sequence[Any]) -> Dict[str, float]:
    def _clamp01(x: float) -> float:
        if x < 0.0:
            return 0.0
        if x > 1.0:
            return 1.0
        return float(x)

    signals: Dict[str, float] = {
        "drift_rate": 0.0,
        "entropy_value": 0.0,
        "entropy_decay_rate": 0.0,
        "fallback_rate": 0.0,
        "coherence_score": 0.0,
        "momentum": 0.0,
        "transition_score": 0.0,
        "transition_prev": 0.0,
        "transition_curr": 0.0,
        "correlation_score": 0.0,
    }

    entropy_sample_count: float | None = None
    oscillation_energy: float | None = None

    for fp in fps:
        kind = _get(fp, "kind", "").lower()
        source_fields = _get(fp, "source_fields", {})
        if not isinstance(source_fields, dict):
            continue

        if kind.startswith("drift") and "drift_rate" in source_fields:
            signals["drift_rate"] = float(source_fields["drift_rate"])
        elif kind.startswith("entropy") and "sample_count" in source_fields:
            entropy_sample_count = float(source_fields["sample_count"])
        elif kind.startswith("oscillation") and "oscillation_energy" in source_fields:
            oscillation_energy = float(source_fields["oscillation_energy"])
        elif kind.startswith("fallback"):
            if "fallback_ratio" in source_fields:
                signals["fallback_rate"] = float(source_fields["fallback_ratio"])
            elif "periodicity_strength01" in source_fields:
                signals["fallback_rate"] = float(source_fields["periodicity_strength01"])
        elif kind.startswith("coherence") and "coherence_score" in source_fields:
            signals["coherence_score"] = float(source_fields["coherence_score"])
        elif kind.startswith("momentum"):
            if "momentum_value" in source_fields:
                signals["momentum"] = float(source_fields["momentum_value"])
            elif "momentum" in source_fields:
                signals["momentum"] = float(source_fields["momentum"])
        elif kind.startswith("transition"):
            transition_metrics = source_fields.get("metrics", {})
            if not isinstance(transition_metrics, dict):
                transition_metrics = {}
            if "transition_rate" in source_fields:
                signals["transition_score"] = float(source_fields["transition_rate"])
            elif "transition_rate" in transition_metrics:
                signals["transition_score"] = float(transition_metrics["transition_rate"])
            if "mean_abs_delta" in transition_metrics:
                signals["transition_prev"] = float(transition_metrics["mean_abs_delta"])
            if "transition_rate" in transition_metrics:
                signals["transition_curr"] = float(transition_metrics["transition_rate"])
        elif kind.startswith("coupling") and "coupling_strength" in source_fields:
            signals["correlation_score"] = float(source_fields["coupling_strength"])

    if entropy_sample_count is not None:
        signals["entropy_value"] = _clamp01(entropy_sample_count / 50.0)
    if oscillation_energy is not None:
        signals["entropy_decay_rate"] = float(oscillation_energy)
    return signals


def build_layer2_graph_slice(*, entity_id: str, trust_graph: TrustGraph) -> GraphSlice | None:
    endpoint_id = f"endpoint:{entity_id}"
    if endpoint_id not in trust_graph.nodes:
        return None

    root_evidence_ids: List[str] = []
    for e in trust_graph.get_outgoing_edges(endpoint_id):
        if e.edge_type != EdgeType.PRODUCES:
            continue
        node = trust_graph.nodes.get(e.to_node_id)
        if isinstance(node, EvidenceNode):
            root_evidence_ids.append(node.node_id)

    if not root_evidence_ids:
        return None
    root_evidence_ids = sorted(set(root_evidence_ids))

    evidence_nodes: Dict[str, EvidenceNode] = {}
    for eid in root_evidence_ids:
        n = trust_graph.nodes.get(eid)
        if isinstance(n, EvidenceNode):
            evidence_nodes[eid] = n

    allowed_edge_types = {
        EdgeType.IDENTITY_LINK,
        EdgeType.MATERIAL_DEPENDENCY,
        EdgeType.TEMPORAL_SEQUENCE,
        EdgeType.VECTOR_SIMILARITY,
    }

    edges: Dict[str, Any] = {}
    neighbor_candidates: Dict[str, EvidenceNode] = {}
    identity_neighbors: set[str] = set()
    material_neighbors: set[str] = set()

    for root_id in root_evidence_ids:
        outgoing = trust_graph.get_outgoing_edges(root_id)
        incoming = trust_graph.get_incoming_edges(root_id)
        for e in outgoing + incoming:
            if e.edge_type not in allowed_edge_types:
                continue
            other_id = e.to_node_id if e.from_node_id == root_id else e.from_node_id
            other_node = trust_graph.nodes.get(other_id)
            if e.edge_type == EdgeType.IDENTITY_LINK:
                if not isinstance(other_node, EvidenceNode):
                    identity_neighbors.add(str(other_id))
                    continue
            if e.edge_type == EdgeType.MATERIAL_DEPENDENCY:
                if not isinstance(other_node, EvidenceNode):
                    material_neighbors.add(str(other_id))
                    continue
            if not isinstance(other_node, EvidenceNode):
                continue
            edges[e.edge_id] = e
            if other_id not in evidence_nodes:
                neighbor_candidates[other_id] = other_node

    neighbors: List[EvidenceNode] = list(neighbor_candidates.values())
    neighbors.sort(
        key=lambda n: (
            int(getattr(n, "created_ms", 0) or 0),
            str(getattr(n, "fingerprint_id", "")),
        )
    )
    if len(neighbors) > GraphSlice.MAX_NEIGHBOR_EVIDENCE:
        neighbors = neighbors[-GraphSlice.MAX_NEIGHBOR_EVIDENCE :]

    for n in neighbors:
        evidence_nodes[n.node_id] = n

    allowed_evidence_ids = set(evidence_nodes.keys())
    pruned_edges: Dict[str, Any] = {}
    for edge_id, e in edges.items():
        if e.from_node_id in allowed_evidence_ids and e.to_node_id in allowed_evidence_ids:
            pruned_edges[edge_id] = e

    nodes_sorted = sorted(evidence_nodes.values(), key=lambda n: n.node_id)
    edges_sorted = sorted(pruned_edges.values(), key=lambda e: e.edge_id)
    root_sorted = tuple(sorted(root_evidence_ids))

    return GraphSlice(
        evidence_nodes=tuple(nodes_sorted),
        edges=tuple(edges_sorted),
        root_evidence_ids=root_sorted,
        identity_neighbor_count=len(identity_neighbors),
        material_neighbor_count=len(material_neighbors),
    )


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)
