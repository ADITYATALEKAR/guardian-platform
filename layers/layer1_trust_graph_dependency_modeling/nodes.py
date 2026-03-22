# layers/layer1_trust_graph_dependency_modeling/nodes.py
"""
nodes.py

Layer1 TrustGraph nodes.

Bank-grade constraints:
- deterministic replay
- bounded metadata
- minimal semantics (no risk/attacker labels)
- dataclasses are immutable (frozen) for safety
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict



class NodeType(str, Enum):
    ENDPOINT = "endpoint"
    SESSION = "session"
    EVIDENCE = "evidence"
    IDENTITY = "identity"
    TRUST_MATERIAL = "trust_material"


def _bounded_metadata(meta: Any, *, max_items: int = 16) -> Dict[str, str]:
    """
    Bank-grade bounded metadata:
    - deterministic ordering
    - bounded key count
    - string values only
    """
    if not isinstance(meta, dict) or not meta:
        return {}

    out: Dict[str, str] = {}
    for k in sorted(meta.keys())[:max_items]:
        try:
            ks = str(k)
            vs = meta.get(k)
            out[ks] = "" if vs is None else str(vs)
        except Exception:
            continue
    return out


# ---------------------------------------------------------------------
# Base node contract
# ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BaseNode:
    node_id: str
    node_type: NodeType
    created_at_ms: int
    metadata: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------
# Session grouping key
# ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SessionKey:
    """
    Deterministic session/window descriptor.
    """
    entity_id: str
    session_id: str
    window_start_ms: int
    window_end_ms: int


# ---------------------------------------------------------------------
# Core nodes used in tests + builder
# ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EndpointNode(BaseNode):
    hostname: str | None = None
    ip_address: str | None = None
    port: int | None = None


@dataclass(frozen=True, slots=True)
class SessionNode(BaseNode):
    """
    Represents an (entity, window) grouping anchor.
    """
    session_key: str = ""
    entity_id: str = ""
    window_start_ms: int = 0
    window_end_ms: int = 0


@dataclass(frozen=True, slots=True)
class EvidenceNode(BaseNode):
    """
    Evidence anchor node: full fingerprint instance (signal-preserving).
    """
    fingerprint_id: str = ""
    kind: str = ""
    hash: str = ""
    vector: tuple[float, ...] = ()
    quality: float = 0.0
    created_ms: int = 0
    source_fields: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class IdentityNode(BaseNode):
    """
    Identity anchor node: strict equality only.
    Typically driven by handshake_fp hashes.
    """
    kind: str = ""
    hash: str = ""


@dataclass(frozen=True, slots=True)
class TrustMaterialNode(BaseNode):
    """
    Trust-material anchor node: cert / issuer / trust-chain material.
    """
    kind: str = ""
    hash: str = ""


ServiceNode = BaseNode
