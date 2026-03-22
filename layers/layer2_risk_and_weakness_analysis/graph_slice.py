from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Tuple

from layers.layer1_trust_graph_dependency_modeling.edges import Edge
from layers.layer1_trust_graph_dependency_modeling.nodes import EvidenceNode


@dataclass(frozen=True, slots=True)
class GraphSlice:
    """
    Immutable, 1-hop graph slice for a single endpoint.

    - evidence_nodes: EvidenceNode objects only
    - edges: allowed edge types touching root evidence nodes
    - root_evidence_ids: Evidence node IDs produced by the endpoint
    """

    evidence_nodes: Tuple[EvidenceNode, ...]
    edges: Tuple[Edge, ...]
    root_evidence_ids: Tuple[str, ...]
    identity_neighbor_count: int = 0
    material_neighbor_count: int = 0

    # Hard cap for neighbor evidence nodes (not including roots)
    MAX_NEIGHBOR_EVIDENCE: ClassVar[int] = 256
