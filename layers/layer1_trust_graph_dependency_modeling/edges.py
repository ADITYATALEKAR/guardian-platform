# layers/layer1_trust_graph_dependency_modeling/edges.py
"""
edges.py

Layer 1 edge contract.

Design goals (bank-grade):
- deterministic replay
- bounded metadata
- supports delta merge convergence
- backward compatible with builder code that may still pass created_at_ms
- provides src/dst aliases expected by tests
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Tuple


class EdgeType(str, Enum):
    CONNECTS_TO = "connects_to"
    DEPENDS_ON = "depends_on"
    PRODUCES = "produces"
    IDENTITY_LINK = "identity_link"
    MATERIAL_DEPENDENCY = "material_dependency"
    TEMPORAL_SEQUENCE = "temporal_sequence"
    VECTOR_SIMILARITY = "vector_similarity"
    USES_IDENTITY = "uses_identity"
    USES_TRUST_MATERIAL = "uses_trust_material"
    EMITS_EVIDENCE = "emits_evidence"
    ISSUED_BY = "issued_by"


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
        v = int(x)
        return v
    except Exception:
        return None


def _bounded_metadata(meta: object, *, max_items: int = 16) -> Dict[str, str]:
    """
    Bank-grade bounded metadata:
    - strings only
    - bounded count
    - deterministic ordering
    """
    if not isinstance(meta, dict) or not meta:
        return {}

    out: Dict[str, str] = {}
    for k in sorted(meta.keys())[:max_items]:
        ks = _safe_str(k)
        if not ks:
            continue
        v = meta.get(k)
        out[ks] = "" if v is None else _safe_str(v)
    return out


def _merge_metadata(a: Dict[str, str], b: Dict[str, str]) -> Dict[str, str]:
    # deterministic: left-biased but updated by right (stable)
    m = dict(a)
    m.update(b)
    return _bounded_metadata(m, max_items=16)


def _min_opt(a: Optional[int], b: Optional[int]) -> Optional[int]:
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


def _max_opt(a: Optional[int], b: Optional[int]) -> Optional[int]:
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


@dataclass(frozen=True, slots=True)
class Edge:
    """
    Directed relationship between two nodes.

    IMPORTANT:
    - edge_id must be deterministic (constructed by builder/linker)
    - src/dst properties exist for test compatibility
    """

    edge_id: str
    from_node_id: str
    to_node_id: str
    edge_type: EdgeType

    # Compatibility field (legacy)
    created_at_ms: Optional[int] = None

    # Bank-grade lifecycle fields
    first_seen_ms: Optional[int] = None
    last_seen_ms: Optional[int] = None
    count: int = 1
    weight: float = 1.0

    # bounded evidence anchors (optional)
    evidence_refs: Tuple[Dict[str, str], ...] = field(default_factory=tuple)

    # bounded metadata
    metadata: Dict[str, str] = field(default_factory=dict)

    # -------------------------
    # Test/legacy aliases
    # -------------------------
    @property
    def src(self) -> str:
        return self.from_node_id

    @property
    def dst(self) -> str:
        return self.to_node_id

    # -------------------------
    # Deterministic merge
    # -------------------------
    def merged_with(self, other: "Edge") -> "Edge":
        """
        Merge two edges with the same edge_id deterministically.

        - count increments
        - first_seen is min
        - last_seen is max
        - created_at_ms is stable min(if available)
        - metadata merged and bounded
        """
        if self.edge_id != other.edge_id:
            raise ValueError("Cannot merge edges with different edge_id")

        # created_at_ms: keep earliest known
        ca = _safe_int(self.created_at_ms)
        cb = _safe_int(other.created_at_ms)
        created = _min_opt(ca, cb)

        fs = _min_opt(_safe_int(self.first_seen_ms), _safe_int(other.first_seen_ms))
        ls = _max_opt(_safe_int(self.last_seen_ms), _safe_int(other.last_seen_ms))

        # If lifecycle missing, fall back to created_at_ms
        if fs is None:
            fs = created
        if ls is None:
            ls = created

        c = int(self.count) + int(other.count)
        if c < 1:
            c = 1

        meta = _merge_metadata(self.metadata, other.metadata)
        w = max(float(self.weight), float(other.weight))

        # Evidence refs: bounded + deterministic de-dup
        merged_refs = list(self.evidence_refs) + list(other.evidence_refs)
        dedup: Dict[Tuple[str, str, str], Dict[str, str]] = {}
        for r in merged_refs:
            if not isinstance(r, dict):
                continue
            rr = _bounded_metadata(r, max_items=8)
            key = (rr.get("kind", ""), rr.get("hash", ""), rr.get("fingerprint_id", ""))
            dedup[key] = rr
        refs = tuple(dedup[k] for k in sorted(dedup.keys()))[:8]

        return Edge(
            edge_id=self.edge_id,
            from_node_id=self.from_node_id,
            to_node_id=self.to_node_id,
            edge_type=self.edge_type,
            created_at_ms=created,
            first_seen_ms=fs,
            last_seen_ms=ls,
            count=c,
            weight=w,
            evidence_refs=refs,
            metadata=meta,
        )
