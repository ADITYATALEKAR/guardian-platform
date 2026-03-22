"""
🎯 Purpose of traversal.py

This module provides safe, bounded traversal of the trust graph.

It answers structural questions only:
• What depends on what?
• How far does connectivity extend?
• What nodes are reachable?

It does NOT interpret meaning, risk, or importance.
"""

from collections import deque
from typing import Set, List, Literal

from layers.layer1_trust_graph_dependency_modeling.graph import TrustGraph


Direction = Literal["outgoing", "incoming", "both"]


def get_direct_neighbors(
    graph: TrustGraph,
    node_id: str,
    direction: Direction = "outgoing"
) -> Set[str]:
    neighbors: Set[str] = set()

    if direction in ("outgoing", "both"):
        neighbors |= graph.outgoing.get(node_id, set())

    if direction in ("incoming", "both"):
        neighbors |= graph.incoming.get(node_id, set())

    return neighbors


def traverse(
    graph: TrustGraph,
    start_node_id: str,
    max_depth: int = 1,
    direction: Direction = "outgoing"
) -> Set[str]:
    """
    Breadth-first traversal with depth limit.
    Returns all reachable node IDs (excluding the start node).
    """

    visited: Set[str] = {start_node_id}
    discovered: Set[str] = set()

    queue = deque([(start_node_id, 0)])

    while queue:
        current_node_id, depth = queue.popleft()

        if depth >= max_depth:
            continue

        neighbors = get_direct_neighbors(graph, current_node_id, direction)

        for neighbor_id in neighbors:
            if neighbor_id not in visited:
                visited.add(neighbor_id)
                discovered.add(neighbor_id)
                queue.append((neighbor_id, depth + 1))

    return discovered
