# layers/layer1_trust_graph_dependency_modeling/dependency_builder.py
"""
dependency_builder.py

Layer 1: Trust Graph Dependency Modeling

Bank-grade constraints:
- deterministic replay (order invariance)
- bounded anchors + metadata
- no attacker/risk semantics
- no self-loop edges
- delta-merge convergence:
    ingest(b1); ingest(b2) == ingest(b1+b2)

Core modeling:
- Endpoint node per entity_id
- Session node per entity per window bucket (60s)
- Endpoint -> Session edge
- Session -> Evidence anchor edges
- Session -> Identity / TrustMaterial edges (strict structural)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from layers.layer0_observation.fingerprints.fingerprint_types import Fingerprint

from .edges import Edge, EdgeType
from .graph import TrustGraph
from .nodes import (
    BaseNode,
    EvidenceNode,
    EndpointNode,
    IdentityNode,
    TrustMaterialNode,
    NodeType,
)

# Layer 1 now creates explicit EvidenceNode objects per fingerprint.


# ---------------------------------------------------------------------
# Public delta contract
# ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GraphDelta:
    nodes: Dict[str, BaseNode]
    edges: Dict[str, Edge]


# ---------------------------------------------------------------------
# Safe + bounded helpers
# ---------------------------------------------------------------------


def _safe_str(x: object) -> str:
    try:
        if x is None:
            return ""
        return str(x).strip()
    except Exception:
        return ""


def _safe_int(x: object) -> Optional[int]:
    try:
        if x is None:
            return None
        return int(x)
    except Exception:
        return None


def _safe_float(x: object, default: float = 0.0) -> float:
    try:
        if x is None:
            return float(default)
        v = float(x)
        if v != v:
            return float(default)
        return v
    except Exception:
        return float(default)


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return float(x)


def _bounded_metadata(meta: object, *, max_items: int = 16) -> Dict[str, str]:
    if not isinstance(meta, dict) or not meta:
        return {}
    out: Dict[str, str] = {}
    for k in sorted(meta.keys())[:max_items]:
        ks = _safe_str(k)
        if not ks:
            continue
        vs = meta.get(k)
        out[ks] = "" if vs is None else _safe_str(vs)
    return out


def _coerce_fingerprint(obj: object) -> Optional[Fingerprint]:
    """
    Accept Fingerprint objects or dict payloads and return a Fingerprint.
    """
    if isinstance(obj, Fingerprint):
        return obj
    if not isinstance(obj, dict):
        return None

    return Fingerprint(
        fingerprint_id=_safe_str(obj.get("fingerprint_id", "")),
        entity_id=_safe_str(obj.get("entity_id", "")),
        kind=_safe_str(obj.get("kind", "")),
        version=int(obj.get("version", 1) or 1),
        created_ms=int(_safe_int(obj.get("created_ms")) or 0),
        hash=_safe_str(obj.get("hash", "")),
        vector=list(obj.get("vector") or []),
        quality=_safe_float(obj.get("quality", 0.0), 0.0),
        source_fields=dict(obj.get("source_fields") or {}),
    )


# ---------------------------------------------------------------------
# Stable deterministic ids
# ---------------------------------------------------------------------


def _edge_id(edge_type: EdgeType, from_id: str, to_id: str) -> str:
    return f"edge:{edge_type.value}:{from_id}->{to_id}"


def _node_id_endpoint(entity_id: str) -> str:
    return f"endpoint:{entity_id}"


def _node_id_identity(kind: str, h: str) -> str:
    return f"identity:{kind}:{h}"


def _node_id_trust_material(kind: str, h: str) -> str:
    return f"trust:{kind}:{h}"


def _node_id_evidence(fingerprint_id: str) -> str:
    return f"evidence::{fingerprint_id}"


# ---------------------------------------------------------------------
# Fingerprint extraction
# ---------------------------------------------------------------------


def _fp_sort_key(fp: Fingerprint) -> Tuple[str, str, str]:
    kind = _safe_str(getattr(fp, "kind", ""))
    h = _safe_str(getattr(fp, "hash", ""))
    fid = _safe_str(getattr(fp, "fingerprint_id", ""))
    return (kind, h, fid)


def _extract_event_ts(fp: Fingerprint) -> int:
    ts = _safe_int(getattr(fp, "created_ms", None))
    return int(ts) if ts is not None and ts > 0 else 0


def _is_identity_kind(kind: str) -> bool:
    # strict identity anchors only
    return kind.startswith("handshake_fp")


def _is_trust_material_kind(kind: str) -> bool:
    return "cert" in kind or "issuer" in kind


# ---------------------------------------------------------------------
# Deterministic similarity / sequence constants
# ---------------------------------------------------------------------

VECTOR_SIMILARITY_THRESHOLD = 0.92
MAX_SIM_COMPARISONS = 2000
VECTOR_BUCKET_DIMS = 4
VECTOR_BUCKET_PRECISION = 2
MAX_EVIDENCE_PER_ENDPOINT = 2000
TEMPORAL_TAU_MS = 60_000


def _safe_vector(vec: object) -> Tuple[float, ...]:
    if not isinstance(vec, (list, tuple)):
        return ()
    out: List[float] = []
    for v in vec:
        out.append(_safe_float(v, 0.0))
    return tuple(out)


def _cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    if not a or not b:
        return 0.0
    n = min(len(a), len(b))
    if n <= 0:
        return 0.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    for i in range(n):
        av = float(a[i])
        bv = float(b[i])
        dot += av * bv
        na += av * av
        nb += bv * bv
    denom = (na ** 0.5) * (nb ** 0.5)
    if denom <= 1e-12:
        return 0.0
    return dot / denom


def _vector_bucket_key(vec: Sequence[float]) -> Tuple[float, ...]:
    if not vec:
        return ()
    k = min(VECTOR_BUCKET_DIMS, len(vec))
    return tuple(round(float(vec[i]), VECTOR_BUCKET_PRECISION) for i in range(k))


# ---------------------------------------------------------------------
# Windowing for merge convergence
# ---------------------------------------------------------------------


def _created_at_ms_for_nodes(event_ts_ms: int, ingestion_ts_ms: Optional[int]) -> int:
    # node-level created_at_ms must be stable
    if ingestion_ts_ms is not None and ingestion_ts_ms > 0:
        return int(ingestion_ts_ms)
    if event_ts_ms > 0:
        return int(event_ts_ms)
    return 0


def _edge_seen_ts(event_ts_ms: int, ingestion_ts_ms: Optional[int]) -> Optional[int]:
    """
    Edge lifecycle timestamps:
    - prefer ingestion_ts_ms
    - fallback event_ts_ms
    - else None (do not poison)
    """
    if ingestion_ts_ms is not None and ingestion_ts_ms > 0:
        return int(ingestion_ts_ms)
    if event_ts_ms > 0:
        return int(event_ts_ms)
    return None


def _mk_edge(
    *,
    edge_type: EdgeType,
    from_node_id: str,
    to_node_id: str,
    seen_ts_ms: Optional[int],
    metadata: Optional[Dict[str, str]] = None,
    evidence_refs: Optional[Tuple[Dict[str, str], ...]] = None,
) -> Edge:
    """
    Single canonical edge constructor.
    Ensures count>=1 and timestamps safe.
    """
    return Edge(
        edge_id=_edge_id(edge_type, from_node_id, to_node_id),
        from_node_id=from_node_id,
        to_node_id=to_node_id,
        edge_type=edge_type,
        first_seen_ms=seen_ts_ms,
        last_seen_ms=seen_ts_ms,
        count=1,
        evidence_refs=tuple(evidence_refs or ()),
        metadata=_bounded_metadata(metadata or {}),
    )


# ---------------------------------------------------------------------
# Delta builder
# ---------------------------------------------------------------------


def build_trust_graph_delta(
    fingerprints: Sequence[Fingerprint],
    *,
    ingestion_ts_ms: Optional[int],
) -> GraphDelta:
    fps_raw = list(fingerprints or [])
    fps: List[Fingerprint] = []
    for obj in fps_raw:
        fp = _coerce_fingerprint(obj)
        if fp is not None:
            fps.append(fp)
    fps.sort(key=_fp_sort_key)

    nodes: Dict[str, BaseNode] = {}
    edges: Dict[str, Edge] = {}

    # group by entity (deterministic)
    entity_to_fps: Dict[str, List[Fingerprint]] = {}
    for fp in fps:
        eid = _safe_str(getattr(fp, "entity_id", ""))
        if not eid:
            continue
        entity_to_fps.setdefault(eid, []).append(fp)

    for entity_id in sorted(entity_to_fps.keys()):
        entity_fps = entity_to_fps[entity_id]
        if not entity_fps:
            continue
        entity_fps.sort(key=_fp_sort_key)

        endpoint_id = _node_id_endpoint(entity_id)
        first_ts = _extract_event_ts(entity_fps[0])

        if endpoint_id not in nodes:
            nodes[endpoint_id] = EndpointNode(
                node_id=endpoint_id,
                node_type=NodeType.ENDPOINT,
                created_at_ms=_created_at_ms_for_nodes(first_ts, ingestion_ts_ms),
                metadata=_bounded_metadata({"entity_id": entity_id}),
                hostname=None,
                ip_address=None,
                port=None,
            )

        evidence_nodes: List[EvidenceNode] = []

        for fp in entity_fps:
            fid = _safe_str(getattr(fp, "fingerprint_id", ""))
            kind = _safe_str(getattr(fp, "kind", ""))
            h = _safe_str(getattr(fp, "hash", ""))
            ts = _extract_event_ts(fp)

            if not fid:
                continue

            evidence_id = _node_id_evidence(fid)
            if evidence_id not in nodes:
                vec = _safe_vector(getattr(fp, "vector", None))
                quality = _clamp01(_safe_float(getattr(fp, "quality", 0.0), 0.0))
                sf = getattr(fp, "source_fields", None)
                sf_dict = dict(sf) if isinstance(sf, dict) else {}
                nodes[evidence_id] = EvidenceNode(
                    node_id=evidence_id,
                    node_type=NodeType.EVIDENCE,
                    created_at_ms=_created_at_ms_for_nodes(ts, ingestion_ts_ms),
                    metadata=_bounded_metadata({"kind": kind, "hash": h}),
                    fingerprint_id=fid,
                    kind=kind,
                    hash=h,
                    vector=tuple(vec),
                    quality=float(quality),
                    created_ms=int(ts),
                    source_fields=sf_dict,
                )
            evidence_nodes.append(nodes[evidence_id])  # type: ignore[arg-type]

            # produces: endpoint -> evidence
            e_pe = Edge(
                edge_id=_edge_id(EdgeType.PRODUCES, endpoint_id, evidence_id),
                from_node_id=endpoint_id,
                to_node_id=evidence_id,
                edge_type=EdgeType.PRODUCES,
                first_seen_ms=_edge_seen_ts(ts, ingestion_ts_ms),
                last_seen_ms=_edge_seen_ts(ts, ingestion_ts_ms),
                count=1,
                weight=_clamp01(_safe_float(getattr(fp, "quality", 0.0), 0.0)),
                metadata=_bounded_metadata({"relation": "endpoint_produces_evidence"}),
            )
            edges[e_pe.edge_id] = e_pe

            # identity link
            if _is_identity_kind(kind):
                id_node_id = _node_id_identity(kind, h)
                if id_node_id not in nodes:
                    nodes[id_node_id] = IdentityNode(
                        node_id=id_node_id,
                        node_type=NodeType.IDENTITY,
                        created_at_ms=_created_at_ms_for_nodes(ts, ingestion_ts_ms),
                        metadata=_bounded_metadata({"kind": kind, "hash": h}),
                        kind=kind,
                        hash=h,
                    )
                coherence = 1.0
                sf = getattr(fp, "source_fields", None)
                if isinstance(sf, dict) and "coherence_score" in sf:
                    coherence = _clamp01(_safe_float(sf.get("coherence_score", 1.0), 1.0))
                w = _clamp01(_safe_float(getattr(fp, "quality", 0.0), 0.0) * coherence)
                e_ei = Edge(
                    edge_id=_edge_id(EdgeType.IDENTITY_LINK, evidence_id, id_node_id),
                    from_node_id=evidence_id,
                    to_node_id=id_node_id,
                    edge_type=EdgeType.IDENTITY_LINK,
                    first_seen_ms=_edge_seen_ts(ts, ingestion_ts_ms),
                    last_seen_ms=_edge_seen_ts(ts, ingestion_ts_ms),
                    count=1,
                    weight=w,
                    metadata=_bounded_metadata({"relation": "evidence_identity"}),
                )
                edges[e_ei.edge_id] = e_ei
                e_ie = Edge(
                    edge_id=_edge_id(EdgeType.IDENTITY_LINK, id_node_id, evidence_id),
                    from_node_id=id_node_id,
                    to_node_id=evidence_id,
                    edge_type=EdgeType.IDENTITY_LINK,
                    first_seen_ms=_edge_seen_ts(ts, ingestion_ts_ms),
                    last_seen_ms=_edge_seen_ts(ts, ingestion_ts_ms),
                    count=1,
                    weight=w,
                    metadata=_bounded_metadata({"relation": "identity_evidence"}),
                )
                edges[e_ie.edge_id] = e_ie

            # trust material dependency
            if _is_trust_material_kind(kind):
                tm_node_id = _node_id_trust_material(kind, h)
                if tm_node_id not in nodes:
                    nodes[tm_node_id] = TrustMaterialNode(
                        node_id=tm_node_id,
                        node_type=NodeType.TRUST_MATERIAL,
                        created_at_ms=_created_at_ms_for_nodes(ts, ingestion_ts_ms),
                        metadata=_bounded_metadata({"kind": kind, "hash": h}),
                        kind=kind,
                        hash=h,
                    )
                e_em = Edge(
                    edge_id=_edge_id(EdgeType.MATERIAL_DEPENDENCY, evidence_id, tm_node_id),
                    from_node_id=evidence_id,
                    to_node_id=tm_node_id,
                    edge_type=EdgeType.MATERIAL_DEPENDENCY,
                    first_seen_ms=_edge_seen_ts(ts, ingestion_ts_ms),
                    last_seen_ms=_edge_seen_ts(ts, ingestion_ts_ms),
                    count=1,
                    weight=_clamp01(_safe_float(getattr(fp, "quality", 0.0), 0.0)),
                    metadata=_bounded_metadata({"relation": "evidence_trust_material"}),
                )
                edges[e_em.edge_id] = e_em

        # Enforce per-endpoint cap (deterministic: drop oldest)
        evidence_nodes.sort(
            key=lambda n: (int(getattr(n, "created_ms", 0) or 0), _safe_str(getattr(n, "fingerprint_id", "")))
        )
        if len(evidence_nodes) > MAX_EVIDENCE_PER_ENDPOINT:
            evidence_nodes = evidence_nodes[-MAX_EVIDENCE_PER_ENDPOINT:]

        # temporal sequence (per endpoint, deterministic)
        evidence_nodes.sort(
            key=lambda n: (int(getattr(n, "created_ms", 0) or 0), _safe_str(getattr(n, "fingerprint_id", "")))
        )
        for i in range(1, len(evidence_nodes)):
            a = evidence_nodes[i - 1]
            b = evidence_nodes[i]
            delta_ms = max(0, int(getattr(b, "created_ms", 0) or 0) - int(getattr(a, "created_ms", 0) or 0))
            w = 1.0 / (1.0 + (float(delta_ms) / float(TEMPORAL_TAU_MS)))
            e_tt = Edge(
                edge_id=_edge_id(EdgeType.TEMPORAL_SEQUENCE, a.node_id, b.node_id),
                from_node_id=a.node_id,
                to_node_id=b.node_id,
                edge_type=EdgeType.TEMPORAL_SEQUENCE,
                first_seen_ms=_edge_seen_ts(int(getattr(b, "created_ms", 0) or 0), ingestion_ts_ms),
                last_seen_ms=_edge_seen_ts(int(getattr(b, "created_ms", 0) or 0), ingestion_ts_ms),
                count=1,
                weight=round(float(w), 6),
                metadata=_bounded_metadata({"relation": "temporal_sequence"}),
            )
            edges[e_tt.edge_id] = e_tt

        # vector similarity (bucketed + capped, deterministic)
        comparisons = 0
        buckets: Dict[Tuple[float, ...], List[EvidenceNode]] = {}
        for n in evidence_nodes:
            v = _safe_vector(getattr(n, "vector", None))
            if not v:
                continue
            key = _vector_bucket_key(v)
            buckets.setdefault(key, []).append(n)

        for key in sorted(buckets.keys()):
            nodes_in_bucket = buckets[key]
            nodes_in_bucket.sort(
                key=lambda n: (int(getattr(n, "created_ms", 0) or 0), _safe_str(getattr(n, "fingerprint_id", "")))
            )
            for i in range(len(nodes_in_bucket)):
                for j in range(i + 1, len(nodes_in_bucket)):
                    if comparisons >= MAX_SIM_COMPARISONS:
                        break
                    a = nodes_in_bucket[i]
                    b = nodes_in_bucket[j]
                    va = _safe_vector(getattr(a, "vector", None))
                    vb = _safe_vector(getattr(b, "vector", None))
                    if not va or not vb:
                        continue
                    sim = _cosine_similarity(va, vb)
                    comparisons += 1
                    if sim >= VECTOR_SIMILARITY_THRESHOLD:
                        w = round(float(sim), 6)
                        e_ab = Edge(
                            edge_id=_edge_id(EdgeType.VECTOR_SIMILARITY, a.node_id, b.node_id),
                            from_node_id=a.node_id,
                            to_node_id=b.node_id,
                            edge_type=EdgeType.VECTOR_SIMILARITY,
                            first_seen_ms=None,
                            last_seen_ms=None,
                            count=1,
                            weight=w,
                            metadata=_bounded_metadata({"relation": "vector_similarity"}),
                        )
                        edges[e_ab.edge_id] = e_ab
                        e_ba = Edge(
                            edge_id=_edge_id(EdgeType.VECTOR_SIMILARITY, b.node_id, a.node_id),
                            from_node_id=b.node_id,
                            to_node_id=a.node_id,
                            edge_type=EdgeType.VECTOR_SIMILARITY,
                            first_seen_ms=None,
                            last_seen_ms=None,
                            count=1,
                            weight=w,
                            metadata=_bounded_metadata({"relation": "vector_similarity"}),
                        )
                        edges[e_ba.edge_id] = e_ba
                if comparisons >= MAX_SIM_COMPARISONS:
                    break
            if comparisons >= MAX_SIM_COMPARISONS:
                break

    return GraphDelta(nodes=nodes, edges=edges)


# ---------------------------------------------------------------------
# Delta apply (merge-safe)
# ---------------------------------------------------------------------


def apply_graph_delta(graph: TrustGraph, delta: GraphDelta) -> None:
    for n in delta.nodes.values():
        if n.node_id not in graph.nodes:
            graph.add_node(n)

    for e in delta.edges.values():
        existing = graph.edges.get(e.edge_id)
        if existing is None:
            graph.add_edge(e)
        else:
            graph.edges[e.edge_id] = existing.merged_with(e)


def ingest_fingerprints(
    graph: TrustGraph,
    fingerprints: Sequence[Fingerprint],
    *,
    ingestion_ts_ms: Optional[int],
) -> None:
    delta = build_trust_graph_delta(fingerprints, ingestion_ts_ms=ingestion_ts_ms)
    apply_graph_delta(graph, delta)
