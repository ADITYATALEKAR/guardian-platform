from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple

from layers.layer1_trust_graph_dependency_modeling.edges import EdgeType

from .graph_slice import GraphSlice


def _safe_float(x: object, default: float = 0.0) -> float:
    try:
        v = float(x)
        if v != v or v in (float("inf"), float("-inf")):
            return default
        return v
    except Exception:
        return default


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return float(x)


def _mean(vals: Iterable[float]) -> float:
    items = list(vals)
    if not items:
        return 0.0
    return sum(items) / max(1, len(items))


def _stddev(vals: Sequence[float]) -> float:
    if not vals:
        return 0.0
    mu = _mean(vals)
    acc = 0.0
    for v in vals:
        dv = float(v) - mu
        acc += dv * dv
    return (acc / max(1, len(vals))) ** 0.5


@dataclass(frozen=True, slots=True)
class GraphStructuralSignals:
    identity_reuse_density: float
    similarity_cluster_score: float
    material_dependency_fanout: float
    temporal_escalation_score: float
    cross_endpoint_correlation_score: float
    vector_stability_score: float
    evidence_quality_weight: float

    def to_dict(self) -> Dict[str, float]:
        return {
            "identity_reuse_density": float(self.identity_reuse_density),
            "similarity_cluster_score": float(self.similarity_cluster_score),
            "material_dependency_fanout": float(self.material_dependency_fanout),
            "temporal_escalation_score": float(self.temporal_escalation_score),
            "cross_endpoint_correlation_score": float(self.cross_endpoint_correlation_score),
            "vector_stability_score": float(self.vector_stability_score),
            "evidence_quality_weight": float(self.evidence_quality_weight),
        }


class GraphSignalExtractor:
    """
    Deterministic structural signal extraction from a GraphSlice.
    """

    # Normalization caps for edge-based densities
    IDENTITY_EDGE_CAP_PER_EVIDENCE = 1
    MATERIAL_EDGE_CAP_PER_EVIDENCE = 1

    def extract(self, slice_: GraphSlice) -> GraphStructuralSignals:
        root_ids = set(slice_.root_evidence_ids or ())
        if not root_ids:
            return GraphStructuralSignals(
                identity_reuse_density=0.0,
                similarity_cluster_score=0.0,
                material_dependency_fanout=0.0,
                temporal_escalation_score=0.0,
                cross_endpoint_correlation_score=0.0,
                vector_stability_score=0.0,
                evidence_quality_weight=0.0,
            )

        # Evidence quality weight (root evidence only)
        root_quality: List[float] = []
        for n in slice_.evidence_nodes:
            if n.node_id in root_ids:
                root_quality.append(_clamp01(_safe_float(n.quality, 0.0)))
        evidence_quality_weight = _clamp01(_mean(root_quality))

        # Vector similarity weights (edges touching roots)
        similarity_weights: List[float] = []

        # Temporal sequence weights (edges touching roots)
        temporal_weights: List[float] = []

        for e in slice_.edges:
            if e.edge_type == EdgeType.VECTOR_SIMILARITY:
                if e.from_node_id in root_ids or e.to_node_id in root_ids:
                    similarity_weights.append(_clamp01(_safe_float(e.weight, 0.0)))

            elif e.edge_type == EdgeType.TEMPORAL_SEQUENCE:
                if e.from_node_id in root_ids or e.to_node_id in root_ids:
                    temporal_weights.append(_clamp01(_safe_float(e.weight, 0.0)))

        # Normalize identity reuse density
        denom_id = max(1, len(root_ids) * self.IDENTITY_EDGE_CAP_PER_EVIDENCE)
        identity_reuse_density = _clamp01(
            float(slice_.identity_neighbor_count) / float(denom_id)
        )

        # Normalize material dependency fanout
        denom_mat = max(1, len(root_ids) * self.MATERIAL_EDGE_CAP_PER_EVIDENCE)
        material_dependency_fanout = _clamp01(
            float(slice_.material_neighbor_count) / float(denom_mat)
        )

        # Similarity cluster score: mean similarity weight
        similarity_cluster_score = _clamp01(_mean(similarity_weights))

        # Temporal escalation score: mean temporal weight (proxy for rapid sequence)
        temporal_escalation_score = _clamp01(_mean(temporal_weights))

        # Vector stability score: 1 - normalized stddev of similarity weights
        if similarity_weights:
            std = _stddev(similarity_weights)
            vector_stability_score = _clamp01(1.0 - min(1.0, std / 0.5))
        else:
            vector_stability_score = 0.0

        # Cross-endpoint correlation proxy (bounded structural mix)
        cross_endpoint_correlation_score = _clamp01(
            0.5 * identity_reuse_density + 0.5 * material_dependency_fanout
        )

        return GraphStructuralSignals(
            identity_reuse_density=identity_reuse_density,
            similarity_cluster_score=similarity_cluster_score,
            material_dependency_fanout=material_dependency_fanout,
            temporal_escalation_score=temporal_escalation_score,
            cross_endpoint_correlation_score=cross_endpoint_correlation_score,
            vector_stability_score=vector_stability_score,
            evidence_quality_weight=evidence_quality_weight,
        )
