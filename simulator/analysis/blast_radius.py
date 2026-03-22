"""
Blast Radius Analysis
=====================

Deterministic blast radius computation using TrustGraph and Prediction outputs.
"""

from dataclasses import dataclass
from typing import Dict, Any, Iterable, Set

from layers.layer1_trust_graph_dependency_modeling.graph import TrustGraph
from layers.layer3_prediction_and_learning.prediction_contracts import PredictionBundle


@dataclass(frozen=True, slots=True)
class BlastRadius:
    impacted_nodes: int
    depth: int
    spread_pct: float
    amplification: float
    confidence_drop: float
    score: float


def compute_blast_radius(
    *,
    trust_graph: TrustGraph,
    predictions: Dict[str, PredictionBundle],
    baseline_predictions: Dict[str, PredictionBundle],
    severity_threshold: float = 0.55,
) -> BlastRadius:
    impacted: Set[str] = set()

    for entity_id, bundle in predictions.items():
        for s in bundle.signals:
            if float(s.severity_01) >= severity_threshold:
                impacted.add(entity_id)
                break

    total_nodes = max(1, len(trust_graph.nodes))
    impacted_count = len(impacted)
    spread_pct = impacted_count / float(total_nodes)

    # Depth estimation: max shortest path from any impacted origin
    depth = _max_depth_from_impacted(trust_graph, impacted)

    # Amplification: max severity / origin severity (bounded)
    amplification = _compute_amplification(predictions, impacted)

    # Confidence drop between baseline and simulated
    confidence_drop = _compute_confidence_drop(predictions, baseline_predictions)

    score = _compute_score(depth, spread_pct, amplification, confidence_drop)

    return BlastRadius(
        impacted_nodes=impacted_count,
        depth=depth,
        spread_pct=round(spread_pct, 6),
        amplification=round(amplification, 6),
        confidence_drop=round(confidence_drop, 6),
        score=round(score, 6),
    )


def _max_depth_from_impacted(graph: TrustGraph, impacted: Set[str]) -> int:
    if not impacted:
        return 0

    max_depth = 0
    for node in sorted(impacted):
        depths = _bfs_depths(graph, node)
        if depths:
            max_depth = max(max_depth, max(depths.values()))
    return int(max_depth)


def _bfs_depths(graph: TrustGraph, origin: str) -> Dict[str, int]:
    depths: Dict[str, int] = {origin: 0}
    queue = [origin]

    while queue:
        current = queue.pop(0)
        for neighbor in graph.get_outgoing(current):
            if neighbor not in depths:
                depths[neighbor] = depths[current] + 1
                queue.append(neighbor)
    return depths


def _compute_amplification(
    predictions: Dict[str, PredictionBundle],
    impacted: Set[str],
) -> float:
    max_sev = 0.0
    origin_sev = 0.0

    for entity_id, bundle in predictions.items():
        for s in bundle.signals:
            sev = float(s.severity_01)
            if sev > max_sev:
                max_sev = sev
            if entity_id in impacted:
                origin_sev = max(origin_sev, sev)

    if origin_sev <= 0.0:
        return 0.0

    amp = max_sev / origin_sev
    if amp > 1.0:
        amp = 1.0
    if amp < 0.0:
        amp = 0.0
    return amp


def _compute_confidence_drop(
    simulated: Dict[str, PredictionBundle],
    baseline: Dict[str, PredictionBundle],
) -> float:
    sim_conf = _mean_confidence(simulated)
    base_conf = _mean_confidence(baseline)
    drop = base_conf - sim_conf
    if drop < 0.0:
        drop = 0.0
    if drop > 1.0:
        drop = 1.0
    return drop


def _mean_confidence(predictions: Dict[str, PredictionBundle]) -> float:
    values = []
    for bundle in predictions.values():
        for s in bundle.signals:
            values.append(float(s.confidence_01))
    if not values:
        return 0.0
    return sum(values) / float(len(values))


def _compute_score(depth: int, spread_pct: float, amplification: float, confidence_drop: float) -> float:
    # bounded weighted composite
    d = min(1.0, depth / 10.0)
    s = min(1.0, spread_pct)
    a = min(1.0, amplification)
    c = min(1.0, confidence_drop)

    score = (0.30 * d) + (0.30 * s) + (0.20 * a) + (0.20 * c)
    if score < 0.0:
        score = 0.0
    if score > 1.0:
        score = 1.0
    return score
