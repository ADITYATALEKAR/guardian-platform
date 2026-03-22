"""
Concentration Risk Analysis
===========================

Deterministic structural concentration metrics using TrustGraph only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Any, List, Tuple, Set
from collections import deque

from layers.layer1_trust_graph_dependency_modeling.graph import TrustGraph
from layers.layer1_trust_graph_dependency_modeling.nodes import NodeType, TrustMaterialNode, BaseNode


MAX_SPOF_CANDIDATES = 20
MAX_ISSUER_NODES_PER_ENDPOINT = 8
ISSUER_SEARCH_DEPTH = 3


def compute_concentration_metrics(trust_graph: TrustGraph) -> Dict[str, Any]:
    endpoints = _endpoint_nodes(trust_graph)
    adjacency = _adjacency(trust_graph)

    ca = _ca_concentration(trust_graph, endpoints, adjacency)
    centrality = _dependency_centrality(trust_graph, adjacency)
    spof = _single_point_of_failure(trust_graph, endpoints, adjacency)

    return {
        "ca_concentration": ca,
        "dependency_centrality": centrality,
        "single_point_of_failure": spof,
    }


def _endpoint_nodes(graph: TrustGraph) -> List[str]:
    out: List[str] = []
    for node_id in sorted(graph.nodes.keys()):
        node = graph.nodes.get(node_id)
        if _is_endpoint(node):
            out.append(node_id)
    return out


def _is_endpoint(node: BaseNode | None) -> bool:
    if node is None:
        return False
    try:
        return node.node_type == NodeType.ENDPOINT
    except Exception:
        return False


def _adjacency(graph: TrustGraph) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for node_id in sorted(graph.nodes.keys()):
        out[node_id] = graph.get_outgoing(node_id)
    return out


def _ca_concentration(
    graph: TrustGraph,
    endpoints: List[str],
    adjacency: Dict[str, List[str]],
) -> Dict[str, Any]:
    issuer_counts: Dict[str, int] = {}

    for endpoint_id in endpoints:
        issuers = _find_issuer_nodes(graph, adjacency, endpoint_id)
        issuer_key = issuers[0] if issuers else "unknown"
        issuer_counts[issuer_key] = issuer_counts.get(issuer_key, 0) + 1

    total = len(endpoints)
    if total <= 0:
        return {
            "total_endpoints": 0,
            "unique_issuers": 0,
            "top_issuer": None,
            "top_issuer_pct": 0.0,
            "hhi": 0.0,
            "issuer_counts": [],
        }

    items = sorted(issuer_counts.items(), key=lambda kv: (-kv[1], str(kv[0])))
    top_issuer, top_count = items[0]
    top_pct = float(top_count) / float(total)

    hhi = 0.0
    for _issuer, count in items:
        share = float(count) / float(total)
        hhi += share * share

    top_list = [
        {"issuer": issuer, "count": int(count), "pct": round(float(count) / float(total), 6)}
        for issuer, count in items[:5]
    ]

    return {
        "total_endpoints": int(total),
        "unique_issuers": int(len(items)),
        "top_issuer": str(top_issuer),
        "top_issuer_pct": round(top_pct, 6),
        "hhi": round(hhi, 6),
        "issuer_counts": top_list,
    }


def _find_issuer_nodes(
    graph: TrustGraph,
    adjacency: Dict[str, List[str]],
    start_node: str,
) -> List[str]:
    if start_node not in adjacency:
        return []

    visited: Set[str] = set()
    q: deque[Tuple[str, int]] = deque()
    q.append((start_node, 0))
    visited.add(start_node)

    issuers: List[str] = []
    while q:
        node_id, depth = q.popleft()
        if depth > ISSUER_SEARCH_DEPTH:
            continue

        node = graph.nodes.get(node_id)
        if isinstance(node, TrustMaterialNode):
            kind = str(getattr(node, "kind", "")).lower()
            if "issuer" in kind:
                issuers.append(_issuer_key(node))
                if len(issuers) >= MAX_ISSUER_NODES_PER_ENDPOINT:
                    break

        if depth == ISSUER_SEARCH_DEPTH:
            continue
        for nxt in adjacency.get(node_id, []):
            if nxt in visited:
                continue
            visited.add(nxt)
            q.append((nxt, depth + 1))

    issuers = sorted(set(issuers))
    return issuers


def _issuer_key(node: TrustMaterialNode) -> str:
    kind = str(getattr(node, "kind", "") or "")
    h = str(getattr(node, "hash", "") or "")
    if not kind and not h:
        return "unknown"
    return f"{kind}:{h}"


def _dependency_centrality(
    graph: TrustGraph,
    adjacency: Dict[str, List[str]],
) -> Dict[str, Any]:
    in_degrees: Dict[str, int] = {}
    out_degrees: Dict[str, int] = {}

    for node_id in sorted(graph.nodes.keys()):
        out_deg = len(adjacency.get(node_id, []))
        in_deg = len(graph.get_incoming(node_id))
        out_degrees[node_id] = out_deg
        in_degrees[node_id] = in_deg

    total_in = sum(in_degrees.values())
    total_out = sum(out_degrees.values())
    max_in = max(in_degrees.values()) if in_degrees else 0
    max_out = max(out_degrees.values()) if out_degrees else 0

    top_nodes = sorted(
        graph.nodes.keys(),
        key=lambda n: (-int(in_degrees.get(n, 0) + out_degrees.get(n, 0)), str(n)),
    )
    top_k = 5
    top_list = []
    for nid in top_nodes[:top_k]:
        top_list.append(
            {
                "node_id": str(nid),
                "in_degree": int(in_degrees.get(nid, 0)),
                "out_degree": int(out_degrees.get(nid, 0)),
                "total_degree": int(in_degrees.get(nid, 0) + out_degrees.get(nid, 0)),
            }
        )

    top1 = top_nodes[0] if top_nodes else None
    reachable_pct = 0.0
    if top1:
        reachable = _reachable_from_sources(adjacency, [top1], removed=None)
        reachable_pct = float(len(reachable)) / float(max(1, len(graph.nodes)))

    return {
        "node_count": int(len(graph.nodes)),
        "edge_count": int(len(graph.edges)),
        "top_in_degree_ratio": round(float(max_in) / float(total_in), 6) if total_in > 0 else 0.0,
        "top_out_degree_ratio": round(float(max_out) / float(total_out), 6) if total_out > 0 else 0.0,
        "reachable_pct_from_top1": round(reachable_pct, 6),
        "top_nodes": top_list,
    }


def _single_point_of_failure(
    graph: TrustGraph,
    endpoints: List[str],
    adjacency: Dict[str, List[str]],
) -> Dict[str, Any]:
    baseline_reachable = _reachable_from_sources(adjacency, endpoints, removed=None)
    baseline_count = len(baseline_reachable)

    candidates = _top_spof_candidates(graph, endpoints, adjacency)
    results = []
    for node_id in candidates:
        reachable = _reachable_from_sources(adjacency, endpoints, removed=node_id)
        drop = float(baseline_count - len(reachable)) / float(baseline_count) if baseline_count > 0 else 0.0
        results.append({"node_id": str(node_id), "drop_pct": round(drop, 6)})

    results.sort(key=lambda r: (-float(r["drop_pct"]), str(r["node_id"])))
    top_drop = results[0]["drop_pct"] if results else 0.0

    return {
        "baseline_reachable_count": int(baseline_count),
        "candidate_count": int(len(candidates)),
        "top_drop_pct": float(top_drop),
        "candidates": results,
    }


def _top_spof_candidates(
    graph: TrustGraph,
    endpoints: List[str],
    adjacency: Dict[str, List[str]],
) -> List[str]:
    degrees: List[Tuple[int, str]] = []
    for node_id in endpoints:
        out_deg = len(adjacency.get(node_id, []))
        in_deg = len(graph.get_incoming(node_id))
        degrees.append((in_deg + out_deg, node_id))
    degrees.sort(key=lambda t: (-int(t[0]), str(t[1])))
    return [node_id for _deg, node_id in degrees[:MAX_SPOF_CANDIDATES]]


def _reachable_from_sources(
    adjacency: Dict[str, List[str]],
    sources: List[str],
    *,
    removed: str | None,
) -> Set[str]:
    visited: Set[str] = set()
    q: deque[str] = deque()

    for s in sources:
        if s == removed:
            continue
        if s not in adjacency:
            continue
        if s in visited:
            continue
        visited.add(s)
        q.append(s)

    while q:
        node = q.popleft()
        for nxt in adjacency.get(node, []):
            if nxt == removed:
                continue
            if nxt in visited:
                continue
            visited.add(nxt)
            q.append(nxt)

    return visited
