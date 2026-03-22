"""
GraphSlice Builder
==================

Deterministic 1-hop GraphSlice construction for Layer 2 structural augmentation.
"""

from __future__ import annotations

from infrastructure.unified_discovery_v2.weakness_inputs import (
    build_layer2_graph_slice as _build_shared_graph_slice,
)

from layers.layer1_trust_graph_dependency_modeling.graph import TrustGraph
from layers.layer2_risk_and_weakness_analysis.graph_slice import GraphSlice


def build_graph_slice(*, entity_id: str, trust_graph: TrustGraph) -> GraphSlice | None:
    return _build_shared_graph_slice(entity_id=entity_id, trust_graph=trust_graph)
