from dataclasses import dataclass, field
from typing import Dict, List, Set, Any, Iterable, Tuple

from .edges import Edge, EdgeType
from .nodes import (
    BaseNode,
    EndpointNode,
    EvidenceNode,
    IdentityNode,
    TrustMaterialNode,
    NodeType,
)


@dataclass(slots=True)
class TrustGraph:
    """
    Deterministic directed trust graph.

    Guarantees:
    - Deterministic adjacency
    - O(1) neighbor access
    - O(1) edge retrieval
    - Stable replay signature
    - Simulator-ready edge access
    """

    # Core storage
    nodes: Dict[str, BaseNode] = field(default_factory=dict)
    edges: Dict[str, Edge] = field(default_factory=dict)

    MAX_EVIDENCE_PER_ENDPOINT = 2000

    # Node adjacency (node_id -> neighbor node_ids)
    outgoing: Dict[str, Set[str]] = field(default_factory=dict)
    incoming: Dict[str, Set[str]] = field(default_factory=dict)

    # NEW: Edge adjacency (node_id -> edge_ids)
    outgoing_edges: Dict[str, Set[str]] = field(default_factory=dict)
    incoming_edges: Dict[str, Set[str]] = field(default_factory=dict)

    # ------------------------------------------------------------
    # NODE MANAGEMENT
    # ------------------------------------------------------------

    def add_node(self, node: BaseNode) -> None:
        self.nodes[node.node_id] = node

        self.outgoing.setdefault(node.node_id, set())
        self.incoming.setdefault(node.node_id, set())

        self.outgoing_edges.setdefault(node.node_id, set())
        self.incoming_edges.setdefault(node.node_id, set())

    # ------------------------------------------------------------
    # EDGE MANAGEMENT
    # ------------------------------------------------------------

    def add_edge(self, edge: Edge) -> None:
        self.edges[edge.edge_id] = edge

        # ensure node maps exist
        self.outgoing.setdefault(edge.from_node_id, set())
        self.incoming.setdefault(edge.to_node_id, set())

        self.outgoing_edges.setdefault(edge.from_node_id, set())
        self.incoming_edges.setdefault(edge.to_node_id, set())

        # maintain node adjacency
        self.outgoing[edge.from_node_id].add(edge.to_node_id)
        self.incoming[edge.to_node_id].add(edge.from_node_id)

        # maintain edge adjacency
        self.outgoing_edges[edge.from_node_id].add(edge.edge_id)
        self.incoming_edges[edge.to_node_id].add(edge.edge_id)

    # ------------------------------------------------------------
    # READ API (DETERMINISTIC)
    # ------------------------------------------------------------

    def get_outgoing(self, node_id: str) -> List[str]:
        """
        Deterministic sorted neighbor node IDs.
        """
        return sorted(self.outgoing.get(node_id, []))

    def get_incoming(self, node_id: str) -> List[str]:
        """
        Deterministic sorted incoming neighbor node IDs.
        """
        return sorted(self.incoming.get(node_id, []))

    def get_outgoing_edges(self, node_id: str) -> List[Edge]:
        """
        Deterministic sorted outgoing Edge objects.
        O(1) access via adjacency.
        """
        edge_ids = self.outgoing_edges.get(node_id, set())
        return sorted(
            (self.edges[eid] for eid in edge_ids),
            key=lambda e: (e.to_node_id, e.edge_type),
        )

    def get_incoming_edges(self, node_id: str) -> List[Edge]:
        """
        Deterministic sorted incoming Edge objects.
        """
        edge_ids = self.incoming_edges.get(node_id, set())
        return sorted(
            (self.edges[eid] for eid in edge_ids),
            key=lambda e: (e.from_node_id, e.edge_type),
        )

    # ------------------------------------------------------------
    # STABLE SIGNATURE (REPLAY GUARANTEE)
    # ------------------------------------------------------------

    def signature(self) -> str:
        """
        Stable graph signature for replay / snapshot diffing.
        """
        n = "|".join(sorted(self.nodes.keys()))
        e = "|".join(sorted(self.edges.keys()))
        return f"nodes:{n}__edges:{e}"

    # ------------------------------------------------------------
    # INTEGRITY / PRUNING
    # ------------------------------------------------------------

    def validate_integrity(self) -> None:
        """
        Hard validation of graph consistency.
        """
        # node_id uniqueness is guaranteed by dict keys
        for eid, edge in self.edges.items():
            if eid != edge.edge_id:
                raise ValueError("Edge ID mismatch in graph")
            if edge.from_node_id not in self.nodes or edge.to_node_id not in self.nodes:
                raise ValueError("Edge references missing node")
            if not isinstance(edge.edge_type, EdgeType):
                raise ValueError("Edge type invalid")

    def prune_evidence(self, *, max_per_endpoint: int) -> None:
        """
        Deterministically prune evidence nodes per endpoint.
        """
        if max_per_endpoint <= 0:
            return

        # Build endpoint -> evidence list via PRODUCES edges
        endpoint_to_evidence: Dict[str, List[EvidenceNode]] = {}
        for edge in self.edges.values():
            if edge.edge_type != EdgeType.PRODUCES:
                continue
            if edge.from_node_id not in self.nodes or edge.to_node_id not in self.nodes:
                continue
            ev = self.nodes[edge.to_node_id]
            if isinstance(ev, EvidenceNode):
                endpoint_to_evidence.setdefault(edge.from_node_id, []).append(ev)

        # Determine evidence nodes to remove
        to_remove: Set[str] = set()
        for endpoint_id in sorted(endpoint_to_evidence.keys()):
            evs = endpoint_to_evidence[endpoint_id]
            evs.sort(
                key=lambda n: (int(getattr(n, "created_ms", 0) or 0), str(getattr(n, "fingerprint_id", "")))
            )
            if len(evs) > max_per_endpoint:
                for ev in evs[: len(evs) - max_per_endpoint]:
                    to_remove.add(ev.node_id)

        if not to_remove:
            return

        # Remove edges touching pruned evidence
        for edge_id in list(self.edges.keys()):
            e = self.edges[edge_id]
            if e.from_node_id in to_remove or e.to_node_id in to_remove:
                del self.edges[edge_id]

        # Remove evidence nodes
        for node_id in to_remove:
            if node_id in self.nodes:
                del self.nodes[node_id]
            self.outgoing.pop(node_id, None)
            self.incoming.pop(node_id, None)
            self.outgoing_edges.pop(node_id, None)
            self.incoming_edges.pop(node_id, None)

        # Clean adjacency sets
        for nid, outs in list(self.outgoing.items()):
            self.outgoing[nid] = {x for x in outs if x not in to_remove}
        for nid, ins in list(self.incoming.items()):
            self.incoming[nid] = {x for x in ins if x not in to_remove}
        for nid, outs in list(self.outgoing_edges.items()):
            self.outgoing_edges[nid] = {x for x in outs if x in self.edges}
        for nid, ins in list(self.incoming_edges.items()):
            self.incoming_edges[nid] = {x for x in ins if x in self.edges}

    # ------------------------------------------------------------
    # PERSISTENCE (DETERMINISTIC SNAPSHOT)
    # ------------------------------------------------------------

    def to_snapshot_dict(self, *, created_at_ms: int) -> Dict[str, Any]:
        """
        Deterministic, lossless snapshot for persistence.
        """
        nodes_out: List[Dict[str, Any]] = []
        for node_id in sorted(self.nodes.keys()):
            n = self.nodes[node_id]
            base = {
                "node_id": n.node_id,
                "node_type": n.node_type.value if isinstance(n.node_type, NodeType) else str(n.node_type),
                "created_at_ms": n.created_at_ms,
                "metadata": dict(n.metadata or {}),
            }
            if isinstance(n, EvidenceNode):
                base.update(
                    {
                        "fingerprint_id": n.fingerprint_id,
                        "kind": n.kind,
                        "hash": n.hash,
                        "vector": list(n.vector or ()),
                        "quality": n.quality,
                        "created_ms": n.created_ms,
                        "source_fields": dict(n.source_fields or {}),
                    }
                )
            elif isinstance(n, IdentityNode):
                base.update(
                    {
                        "kind": n.kind,
                        "hash": n.hash,
                    }
                )
            elif isinstance(n, TrustMaterialNode):
                base.update(
                    {
                        "kind": n.kind,
                        "hash": n.hash,
                    }
                )
            elif isinstance(n, EndpointNode):
                base.update(
                    {
                        "hostname": n.hostname,
                        "ip_address": n.ip_address,
                        "port": n.port,
                    }
                )
            nodes_out.append(base)

        edges_out: List[Dict[str, Any]] = []
        for edge_id in sorted(self.edges.keys()):
            e = self.edges[edge_id]
            edges_out.append(
                {
                    "edge_id": e.edge_id,
                    "from_node_id": e.from_node_id,
                    "to_node_id": e.to_node_id,
                    "edge_type": e.edge_type.value if isinstance(e.edge_type, EdgeType) else str(e.edge_type),
                    "weight": e.weight,
                    "first_seen_ms": e.first_seen_ms,
                    "last_seen_ms": e.last_seen_ms,
                    "count": e.count,
                    "metadata": dict(e.metadata or {}),
                }
            )

        return {
            "version": 1,
            "created_at_ms": int(created_at_ms),
            "nodes": nodes_out,
            "edges": edges_out,
        }

    @staticmethod
    def from_snapshot_dict(snapshot: Dict[str, Any]) -> "TrustGraph":
        """
        Deterministic reconstruction from snapshot dict.
        """
        version = snapshot.get("version")
        if version != 1:
            raise ValueError("TrustGraph snapshot version mismatch")
        if not isinstance(snapshot.get("nodes"), list) or not isinstance(snapshot.get("edges"), list):
            raise ValueError("TrustGraph snapshot structure invalid")

        g = TrustGraph()
        nodes_in = snapshot.get("nodes") or []
        edges_in = snapshot.get("edges") or []
        seen_node_ids: Set[str] = set()
        seen_edge_ids: Set[str] = set()

        for nd in nodes_in:
            if not isinstance(nd, dict):
                raise ValueError("Invalid node entry in snapshot")
            node_type = str(nd.get("node_type", ""))
            node_id = str(nd.get("node_id", ""))
            if not node_id:
                raise ValueError("Node missing node_id")
            if node_id in seen_node_ids:
                raise ValueError("Duplicate node_id in snapshot")
            seen_node_ids.add(node_id)
            if node_type not in NodeType._value2member_map_:
                raise ValueError("Invalid node_type in snapshot")
            created_at_ms = int(nd.get("created_at_ms") or 0)
            metadata = dict(nd.get("metadata") or {})

            if node_type == NodeType.EVIDENCE.value:
                for key in ("fingerprint_id", "kind", "hash", "vector", "quality", "created_ms", "source_fields"):
                    if key not in nd:
                        raise ValueError("EvidenceNode missing required fields")
                n = EvidenceNode(
                    node_id=node_id,
                    node_type=NodeType.EVIDENCE,
                    created_at_ms=created_at_ms,
                    metadata=metadata,
                    fingerprint_id=str(nd.get("fingerprint_id", "")),
                    kind=str(nd.get("kind", "")),
                    hash=str(nd.get("hash", "")),
                    vector=tuple(nd.get("vector") or ()),
                    quality=float(nd.get("quality") or 0.0),
                    created_ms=int(nd.get("created_ms") or 0),
                    source_fields=dict(nd.get("source_fields") or {}),
                )
            elif node_type == NodeType.IDENTITY.value:
                for key in ("kind", "hash"):
                    if key not in nd:
                        raise ValueError("IdentityNode missing required fields")
                n = IdentityNode(
                    node_id=node_id,
                    node_type=NodeType.IDENTITY,
                    created_at_ms=created_at_ms,
                    metadata=metadata,
                    kind=str(nd.get("kind", "")),
                    hash=str(nd.get("hash", "")),
                )
            elif node_type == NodeType.TRUST_MATERIAL.value:
                for key in ("kind", "hash"):
                    if key not in nd:
                        raise ValueError("TrustMaterialNode missing required fields")
                n = TrustMaterialNode(
                    node_id=node_id,
                    node_type=NodeType.TRUST_MATERIAL,
                    created_at_ms=created_at_ms,
                    metadata=metadata,
                    kind=str(nd.get("kind", "")),
                    hash=str(nd.get("hash", "")),
                )
            elif node_type == NodeType.ENDPOINT.value:
                n = EndpointNode(
                    node_id=node_id,
                    node_type=NodeType.ENDPOINT,
                    created_at_ms=created_at_ms,
                    metadata=metadata,
                    hostname=nd.get("hostname"),
                    ip_address=nd.get("ip_address"),
                    port=nd.get("port"),
                )
            else:
                n = BaseNode(
                    node_id=node_id,
                    node_type=NodeType(node_type) if node_type in NodeType._value2member_map_ else NodeType.ENDPOINT,
                    created_at_ms=created_at_ms,
                    metadata=metadata,
                )

            g.add_node(n)

        for ed in edges_in:
            if not isinstance(ed, dict):
                raise ValueError("Invalid edge entry in snapshot")
            for key in ("edge_id", "from_node_id", "to_node_id", "edge_type"):
                if key not in ed:
                    raise ValueError("Edge missing required fields")
            edge_type = str(ed.get("edge_type", ""))
            edge_id = str(ed.get("edge_id", ""))
            if not edge_id:
                raise ValueError("Edge missing edge_id")
            if edge_id in seen_edge_ids:
                raise ValueError("Duplicate edge_id in snapshot")
            seen_edge_ids.add(edge_id)
            if edge_type not in EdgeType._value2member_map_:
                raise ValueError("Invalid edge_type in snapshot")
            e = Edge(
                edge_id=edge_id,
                from_node_id=str(ed.get("from_node_id", "")),
                to_node_id=str(ed.get("to_node_id", "")),
                edge_type=EdgeType(edge_type) if edge_type in EdgeType._value2member_map_ else EdgeType.DEPENDS_ON,
                first_seen_ms=ed.get("first_seen_ms"),
                last_seen_ms=ed.get("last_seen_ms"),
                count=int(ed.get("count") or 1),
                weight=float(ed.get("weight") or 0.0),
                metadata=dict(ed.get("metadata") or {}),
            )
            g.add_edge(e)

        # ensure edges reference existing nodes
        for e in g.edges.values():
            if e.from_node_id not in g.nodes or e.to_node_id not in g.nodes:
                raise ValueError("Edge references missing node")

        g.validate_integrity()

        return g
