"""
Attack Path Ranking
===================

Deterministic ranking of paths using TrustGraph edges only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Iterable, Set, Deque, Tuple
from collections import deque

from layers.layer1_trust_graph_dependency_modeling.graph import TrustGraph


@dataclass(frozen=True, slots=True)
class RankedPath:
    nodes: List[str]
    weight: float


def rank_paths(
    *,
    trust_graph: TrustGraph,
    start_node_id: str,
    max_depth: int,
    max_paths: int,
    max_expansions: int,
    top_k_edges: Optional[int] = None,
    weight_min: float = 0.0,
    critical_targets: Optional[Iterable[str]] = None,
) -> List[RankedPath]:
    _assert_no_nondeterminism()
    critical_set: Set[str] = set()
    if critical_targets is not None:
        critical_set = {str(t) for t in critical_targets if str(t)}

    paths = _bounded_paths(
        trust_graph=trust_graph,
        start_node_id=start_node_id,
        max_depth=max_depth,
        max_paths=max_paths,
        max_expansions=max_expansions,
        top_k_edges=top_k_edges,
        weight_min=weight_min,
    )

    ranked: List[RankedPath] = []
    for p in paths:
        ranked.append(RankedPath(nodes=p, weight=_path_weight(trust_graph, p)))

    def _is_critical(path: RankedPath) -> int:
        if not critical_set:
            return 0
        if not path.nodes:
            return 0
        return 1 if path.nodes[-1] in critical_set else 0

    ranked.sort(key=lambda r: (-_is_critical(r), -r.weight, len(r.nodes), r.nodes))
    return ranked[:max_paths]


def _bounded_paths(
    *,
    trust_graph: TrustGraph,
    start_node_id: str,
    max_depth: int,
    max_paths: int,
    max_expansions: int,
    top_k_edges: Optional[int],
    weight_min: float,
) -> List[List[str]]:
    """
    Deterministic bounded BFS with pruning.

    Worst-case expansions:
      min(B^D, max_expansions)

    Since max_expansions is fixed, runtime and memory are bounded by O(max_expansions).
    """
    if max_depth < 0 or max_paths <= 0 or max_expansions <= 0:
        return []

    start = str(start_node_id)
    if start not in trust_graph.nodes:
        return []

    results: List[List[str]] = []
    q: Deque[Tuple[List[str], float]] = deque()
    q.append(([start], 1.0))
    expansions = 0

    while q and len(results) < max_paths:
        if expansions >= max_expansions:
            break

        path, cum_w = q.popleft()
        expansions += 1

        depth = len(path) - 1
        if depth > max_depth:
            continue

        if depth == max_depth:
            results.append(path)
            continue

        last = path[-1]
        edges = trust_graph.get_outgoing_edges(last)
        edges.sort(key=lambda e: (-_edge_weight_value(e), str(e.to_node_id), str(e.edge_type), str(e.edge_id)))

        if top_k_edges is not None:
            edges = edges[: max(0, int(top_k_edges))]

        for e in edges:
            nxt = str(e.to_node_id)
            if nxt in path:
                continue

            ew = _edge_weight_value(e)
            next_w = cum_w * ew
            if next_w < float(weight_min):
                continue

            if len(q) >= max_expansions:
                # hard frontier cap: stop exploration entirely
                q.clear()
                break

            q.append((path + [nxt], next_w))

        if not q and len(results) >= max_paths:
            break

    results.sort(key=lambda p: (len(p), tuple(p)))
    return results[:max_paths]


def _path_weight(graph: TrustGraph, path: List[str]) -> float:
    if len(path) < 2:
        return 0.0
    w = 1.0
    for i in range(len(path) - 1):
        w *= _edge_weight(graph, path[i], path[i + 1])
    if w < 0.0:
        w = 0.0
    if w > 1.0:
        w = 1.0
    return w


def _edge_weight(graph: TrustGraph, src: str, dst: str) -> float:
    edges = graph.get_outgoing_edges(src)
    for e in edges:
        if e.to_node_id == dst:
            return _edge_weight_value(e)
    return 0.0


def _edge_weight_value(edge: object) -> float:
    try:
        ew = float(getattr(edge, "weight", 0.0) or 0.0)
    except Exception:
        ew = 0.0
    if ew < 0.0:
        ew = 0.0
    if ew > 1.0:
        ew = 1.0
    return ew


def _assert_no_nondeterminism() -> None:
    if "time" in globals() or "random" in globals():
        raise RuntimeError("Nondeterministic modules are forbidden in attack_paths")
