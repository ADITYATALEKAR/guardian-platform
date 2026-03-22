"""
Structural Linkage Validation Test
==================================

Deterministic validation that handshake pair reuse creates new TrustGraph connectivity.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Set, Tuple

from simulator.core.simulation_service import _snapshot_hash, _build_compromised_endpoint_steps
from simulator.core.observation_adapter import ObservationAdapter
from simulator.core.runtime_pipeline import RuntimePipeline
from simulator.scenarios.scenario_injector import ScenarioInjector
from simulator.scenarios.scenario_catalog import AttackScenario
from simulator.scenarios.state_machine import _build_context
from simulator.analysis.attack_paths import rank_paths
from layers.layer1_trust_graph_dependency_modeling.edges import EdgeType
from layers.layer1_trust_graph_dependency_modeling.graph import TrustGraph


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, sort_keys=True, indent=2)


def _reachable(graph: TrustGraph, start: str) -> Set[str]:
    if start not in graph.nodes:
        return set()
    visited = {start}
    queue = [start]
    while queue:
        node = queue.pop(0)
        for nxt in graph.get_outgoing(node):
            if nxt in visited:
                continue
            visited.add(nxt)
            queue.append(nxt)
    return visited


def _components(graph: TrustGraph) -> List[int]:
    # undirected components for structural connectivity view
    adj: Dict[str, Set[str]] = {}
    for node_id in graph.nodes.keys():
        adj[node_id] = set(graph.get_outgoing(node_id)) | set(graph.get_incoming(node_id))
    visited: Set[str] = set()
    sizes: List[int] = []
    for node_id in sorted(graph.nodes.keys()):
        if node_id in visited:
            continue
        comp = set([node_id])
        queue = [node_id]
        visited.add(node_id)
        while queue:
            n = queue.pop(0)
            for nxt in adj.get(n, set()):
                if nxt in visited:
                    continue
                visited.add(nxt)
                comp.add(nxt)
                queue.append(nxt)
        sizes.append(len(comp))
    sizes.sort(reverse=True)
    return sizes


def _shared_identity_nodes(graph: TrustGraph) -> List[Tuple[str, List[str]]]:
    # map evidence -> endpoint via PRODUCES
    evidence_to_endpoint: Dict[str, str] = {}
    for edge in graph.edges.values():
        if edge.edge_type != EdgeType.PRODUCES:
            continue
        evidence_to_endpoint[str(edge.to_node_id)] = str(edge.from_node_id)

    identity_to_evidence: Dict[str, Set[str]] = {}
    for edge in graph.edges.values():
        if edge.edge_type != EdgeType.IDENTITY_LINK:
            continue
        src = str(edge.from_node_id)
        dst = str(edge.to_node_id)
        if src.startswith("evidence::") and dst.startswith("identity:"):
            identity_to_evidence.setdefault(dst, set()).add(src)
        elif src.startswith("identity:") and dst.startswith("evidence::"):
            identity_to_evidence.setdefault(src, set()).add(dst)

    shared: List[Tuple[str, List[str]]] = []
    for identity_id in sorted(identity_to_evidence.keys()):
        endpoints = set()
        for ev in identity_to_evidence.get(identity_id, set()):
            if ev in evidence_to_endpoint:
                endpoints.add(evidence_to_endpoint[ev])
        if len(endpoints) >= 2:
            shared.append((identity_id, sorted(endpoints)))
    return shared


def _path_count_to(graph: TrustGraph, start: str, target: str) -> int:
    paths = rank_paths(
        trust_graph=graph,
        start_node_id=start,
        max_depth=6,
        max_paths=50,
        max_expansions=10_000,
        top_k_edges=None,
        weight_min=0.0,
        critical_targets=None,
    )
    return sum(1 for p in paths if p.nodes and p.nodes[-1] == target)


def run() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        prod_root = Path(tmp) / "prod"
        tenant_id = "tenant_struct"
        cycle_id = "cycle_000001"

        tenant_path = prod_root / "tenant_data_storage" / "tenants" / tenant_id

        snapshot = {
            "schema_version": "1.2",
            "cycle_id": cycle_id,
            "cycle_number": 1,
            "timestamp_unix_ms": 1,
            "endpoint_count": 3,
            "endpoints": [
                {
                    "hostname": "app.example.com",
                    "port": 443,
                    "tls_version": "TLS1.2",
                    "certificate_sha256": "a1",
                    "certificate_expiry_unix_ms": 0,
                    "ip": "10.0.0.1",
                    "cipher": "TLS_AES_128_GCM_SHA256",
                    "cert_issuer": "issuerA",
                    "entropy_score": 0.1,
                    "ports_responding": [],
                    "services_detected": [],
                    "discovered_by": ["snapshot"],
                    "confidence": 0.9,
                    "tls_jarm": None,
                },
                {
                    "hostname": "app.example.com",
                    "port": 8443,
                    "tls_version": "TLS1.3",
                    "certificate_sha256": "b1",
                    "certificate_expiry_unix_ms": 0,
                    "ip": "10.0.0.2",
                    "cipher": "TLS_AES_256_GCM_SHA384",
                    "cert_issuer": "issuerB",
                    "entropy_score": 0.1,
                    "ports_responding": [],
                    "services_detected": [],
                    "discovered_by": ["snapshot"],
                    "confidence": 0.9,
                    "tls_jarm": None,
                },
                {
                    "hostname": "app.example.com",
                    "port": 9443,
                    "tls_version": "TLS1.3",
                    "certificate_sha256": "c1",
                    "certificate_expiry_unix_ms": 0,
                    "ip": "10.0.0.3",
                    "cipher": "TLS_CHACHA20_POLY1305_SHA256",
                    "cert_issuer": "issuerC",
                    "entropy_score": 0.1,
                    "ports_responding": [],
                    "services_detected": [],
                    "discovered_by": ["snapshot"],
                    "confidence": 0.9,
                    "tls_jarm": None,
                },
            ],
        }
        snapshot["snapshot_hash_sha256"] = _snapshot_hash(snapshot)

        _write_json(tenant_path / "snapshots" / f"{cycle_id}.json", snapshot)
        _write_json(
            tenant_path / "trust_graph" / "latest.json",
            {"version": 1, "created_at_ms": 1, "nodes": [], "edges": []},
        )

        adapter = ObservationAdapter()
        injector = ScenarioInjector()
        pipeline = RuntimePipeline()

        baseline_records = adapter.observations_from_snapshot(snapshot)
        baseline_dicts = [adapter.to_dict(r) for r in baseline_records]
        baseline_raw = [adapter.to_protocol_raw(r) for r in baseline_records]

        baseline_outputs = pipeline.run_from_observations(
            tenant_id=tenant_id,
            cycle_id=cycle_id,
            cycle_number=1,
            raw_observations=baseline_raw,
            trust_graph_snapshot={"version": 1, "created_at_ms": 1, "nodes": [], "edges": []},
            layer3_state_snapshot=None,
        )

        origin_entity = "app.example.com:443"
        origin_node = f"endpoint:{origin_entity}"
        target_node = "endpoint:app.example.com:8443"

        before_graph = baseline_outputs.trust_graph
        before_reach = _reachable(before_graph, origin_node)
        before_paths_to_b = _path_count_to(before_graph, origin_node, target_node)
        before_components = _components(before_graph)
        before_shared = _shared_identity_nodes(before_graph)

        steps = _build_compromised_endpoint_steps(severity_threshold=0.55)
        scenario = AttackScenario(
            id="compromised_endpoint",
            injection_type="compromised_endpoint",
            target_selector={"entity_id": origin_entity},
            injection_payload={},
            description="test",
        )

        # Step 1 injection
        ctx1 = _build_context(
            baseline_outputs=baseline_outputs,
            current_outputs=baseline_outputs,
            previous_outputs=None,
            severity_threshold=0.55,
            critical_entities=[],
            origin_entity=origin_entity,
        )
        payload1 = steps[0].injection_payload(ctx1)
        dicts1 = injector.inject(
            baseline_dicts,
            AttackScenario(
                id=scenario.id,
                injection_type=scenario.injection_type,
                target_selector=dict(scenario.target_selector),
                injection_payload=payload1,
                description=scenario.description,
            ),
        )
        records1 = [adapter.from_dict(d) for d in dicts1]
        raw1 = [adapter.to_protocol_raw(r) for r in records1]
        outputs1 = pipeline.run_from_observations(
            tenant_id=tenant_id,
            cycle_id=cycle_id,
            cycle_number=1,
            raw_observations=raw1,
            trust_graph_snapshot={"version": 1, "created_at_ms": 1, "nodes": [], "edges": []},
            layer3_state_snapshot=None,
        )

        # Step 2 injection (credential exposure)
        ctx2 = _build_context(
            baseline_outputs=baseline_outputs,
            current_outputs=outputs1,
            previous_outputs=baseline_outputs,
            severity_threshold=0.55,
            critical_entities=[],
            origin_entity=origin_entity,
        )
        payload2 = steps[1].injection_payload(ctx2)
        dicts2 = injector.inject(
            dicts1,
            AttackScenario(
                id=scenario.id,
                injection_type=scenario.injection_type,
                target_selector=dict(scenario.target_selector),
                injection_payload=payload2,
                description=scenario.description,
            ),
        )
        records2 = [adapter.from_dict(d) for d in dicts2]
        raw2 = [adapter.to_protocol_raw(r) for r in records2]
        outputs2 = pipeline.run_from_observations(
            tenant_id=tenant_id,
            cycle_id=cycle_id,
            cycle_number=1,
            raw_observations=raw2,
            trust_graph_snapshot={"version": 1, "created_at_ms": 1, "nodes": [], "edges": []},
            layer3_state_snapshot=None,
        )

        after_graph = outputs2.trust_graph
        after_reach = _reachable(after_graph, origin_node)
        after_paths_to_b = _path_count_to(after_graph, origin_node, target_node)
        after_components = _components(after_graph)
        after_shared = _shared_identity_nodes(after_graph)

        print("=== Structural Linkage Validation ===")
        print(f"Nodes before: {len(before_graph.nodes)} | after: {len(after_graph.nodes)}")
        print(f"Edges before: {len(before_graph.edges)} | after: {len(after_graph.edges)}")
        print(f"Reachable from A before: {len(before_reach)} | after: {len(after_reach)}")
        print(f"Paths A -> B before: {before_paths_to_b} | after: {after_paths_to_b}")
        print(f"Components before: {before_components}")
        print(f"Components after:  {after_components}")
        print(f"Shared identity nodes before: {len(before_shared)}")
        print(f"Shared identity nodes after: {len(after_shared)}")

        if after_shared:
            print("Shared identity nodes (after):")
            for nid, eps in after_shared:
                print(f"  {nid} -> endpoints={eps}")

        if len(after_reach) <= len(before_reach):
            print("WARNING: reachable set did not increase")
        if after_paths_to_b <= before_paths_to_b:
            print("WARNING: no new endpoint-to-endpoint path detected")
        if not after_shared:
            print("WARNING: no identity node linked to 2+ endpoints")


if __name__ == "__main__":
    run()
