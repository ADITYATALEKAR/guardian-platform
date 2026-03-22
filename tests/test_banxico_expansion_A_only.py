import json
import os
from pathlib import Path
from typing import Any, List
import pytest

from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.discovery.expansion_wrapper import ExpansionConfig
from infrastructure.discovery.expansion_category_a import (
    ExpansionCategoryA,
    EdgeType,
    PassiveDiscoveryGraph,
    extract_candidates,
    REQUESTS_AVAILABLE,
)
from infrastructure.runtime.tenant_lifecycle_manager import TenantLifecycleManager
from infrastructure.storage_manager.identity_manager import IdentityManager
from infrastructure.storage_manager.storage_manager import StorageManager
from infrastructure.unified_discovery_v2.snapshot_builder import SnapshotBuilder
from infrastructure.unified_discovery_v2.temporal_state_engine import TemporalStateEngine
from infrastructure.unified_discovery_v2.unified_cycle_orchestrator import (
    UnifiedCycleOrchestrator,
)

pytestmark = [pytest.mark.network]


class CategoryAOnlyWrapper:
    def __init__(self, max_endpoints: int):
        self._max_endpoints = int(max_endpoints)
        self._category_a = ExpansionCategoryA()
        self.last_graph: PassiveDiscoveryGraph | None = None

    def expand(self, root_domain: str, config: ExpansionConfig):
        graph = self._category_a.get_full_graph(root_domain)
        self.last_graph = graph
        candidates = extract_candidates(graph)
        candidates = candidates[: self._max_endpoints]
        return type(
            "ExpansionResult",
            (),
            {
                "root_domain": root_domain,
                "endpoint_candidates": {c.host for c in candidates},
                "node_count": len(graph.all_nodes()),
                "edge_count": len(graph.all_edges()),
                "ceilings_hit": len(candidates) >= self._max_endpoints,
                "diagnostics": {"mode": "A_ONLY"},
            },
        )


class AOnlyDiscoveryEngine(DiscoveryEngine):
    def run_discovery(self, *args: Any, **kwargs: Any):
        expansion_mode = kwargs.get("expansion_mode")
        if expansion_mode != "A_ONLY":
            raise RuntimeError("Expansion mode not forced to A_ONLY")
        return super().run_discovery(*args, **kwargs)


def test_banxico_expansion_a_only(tmp_path: Path) -> None:
    prod_root = tmp_path / "tenant_storage"
    sim_root = tmp_path / "simulation_storage"

    storage = StorageManager(str(prod_root))
    identity = IdentityManager(storage)
    lifecycle = TenantLifecycleManager(storage, identity, str(sim_root))

    seed = "www.banxico.org.mx:443"
    tenant_id = lifecycle.register_tenant(
        name="Banco de Mexico",
        password="StrongTestPassword123!",
        main_url="https://www.banxico.org.mx/indexen.html",
        seed_endpoints=[seed],
    )

    wrapper = CategoryAOnlyWrapper(max_endpoints=100)
    discovery_engine = AOnlyDiscoveryEngine(
        storage=storage,
        max_workers=50,
        max_endpoints=100,
        expansion_wrapper=wrapper,
    )

    snapshot_builder = SnapshotBuilder()
    temporal_engine = TemporalStateEngine()

    orchestrator = UnifiedCycleOrchestrator(
        storage=storage,
        discovery_engine=discovery_engine,
        snapshot_builder=snapshot_builder,
        temporal_engine=temporal_engine,
        simulation_root=str(sim_root),
    )

    orchestrator.run_cycle(tenant_id)

    snapshot_dict = storage.load_latest_snapshot(tenant_id)
    endpoint_count = snapshot_dict.get("endpoint_count", 0) if snapshot_dict else 0

    if endpoint_count <= 2:
        raise AssertionError("Only 1-2 endpoints discovered; A-only expansion too shallow")
    if endpoint_count > 100:
        raise AssertionError("Endpoint cap exceeded")

    graph = wrapper.last_graph
    if graph is None:
        raise AssertionError("Category A did not produce a graph")

    san_edges = graph.get_edges_by_type(EdgeType.SAN)
    ct_edges = graph.get_edges_by_type(EdgeType.HISTORICAL_CERT)

    if not san_edges and not ct_edges:
        raise AssertionError("No SAN or CT derived expansion found")

    dns_edges = (
        graph.get_edges_by_type(EdgeType.A_RECORD)
        + graph.get_edges_by_type(EdgeType.AAAA_RECORD)
        + graph.get_edges_by_type(EdgeType.CNAME)
        + graph.get_edges_by_type(EdgeType.MX)
        + graph.get_edges_by_type(EdgeType.NS)
        + graph.get_edges_by_type(EdgeType.TXT_REFERENCE)
        + graph.get_edges_by_type(EdgeType.SPF_INCLUDE)
        + graph.get_edges_by_type(EdgeType.PTR)
    )
    if not dns_edges:
        raise AssertionError("No DNS expansion edges detected")

    if REQUESTS_AVAILABLE:
        assert len(ct_edges) > 0

    candidates = extract_candidates(graph)
    discovered = [c.host for c in candidates][:10]

    print("Total endpoints discovered:", endpoint_count)
    print("Graph nodes:", len(graph.all_nodes()))
    print("Graph edges:", len(graph.all_edges()))
    print("First 10 discovered endpoints:", discovered)
    print(
        json.dumps(
            {
                "mode": "A_ONLY",
                "total_endpoints": endpoint_count,
                "graph_nodes": len(graph.all_nodes()),
                "graph_edges": len(graph.all_edges()),
            },
            indent=2,
            sort_keys=True,
        )
    )
