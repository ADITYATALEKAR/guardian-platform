# layers/layer1_trust_graph_dependency_modeling/path_enumeration.py
"""
path_enumeration.py

Bank-grade path enumeration:
- deterministic output ordering
- bounded exploration (max_depth, max_paths)
- structural only
"""

from __future__ import annotations

from collections import deque
from typing import List, Set

from .graph import TrustGraph


def enumerate_paths(
    graph: TrustGraph,
    *,
    start_node_id: str,
    target_node_id: str | None = None,
    max_depth: int = 4,
    max_paths: int = 50,
) -> List[List[str]]:
    """
    Enumerate simple paths (no repeated nodes) from start_node_id.

    Returns:
        List of paths where each path is a list of node_ids.

    Determinism:
        - neighbors visited in sorted order
        - queue expansion deterministic
        - final paths sorted deterministically
    """
    if max_depth < 0:
        return []
    if max_paths <= 0:
        return []

    start = str(start_node_id)
    if start not in graph.nodes:
        return []

    target = str(target_node_id) if target_node_id is not None else None

    results: List[List[str]] = []
    q = deque()
    q.append([start])

    while q and len(results) < max_paths:
        path = q.popleft()
        last = path[-1]

        depth = len(path) - 1
        if depth > max_depth:
            continue

        if target is not None and last == target:
            results.append(path)
            continue

        if depth == max_depth:
            # max depth reached, stop expanding
            if target is None:
                results.append(path)
            continue

        neighbors = sorted(graph.get_outgoing(last))
        for nb in neighbors:
            nb = str(nb)
            if nb in path:
                continue  # avoid loops
            q.append(path + [nb])

    # deterministic ordering of results
    results.sort(key=lambda p: (len(p), tuple(p)))
    return results[:max_paths]
