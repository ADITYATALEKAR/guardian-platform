import json
from pathlib import Path
import pytest

from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.discovery.expansion_wrapper import ExpansionConfig
from infrastructure.discovery.expansion_category_a import (
    ExpansionCategoryA,
    EdgeType,
    NodeType,
    PassiveDiscoveryGraph,
    extract_candidates,
)
from infrastructure.runtime.tenant_lifecycle_manager import TenantLifecycleManager
from infrastructure.storage_manager.identity_manager import IdentityManager
from infrastructure.storage_manager.storage_manager import StorageManager
from infrastructure.unified_discovery_v2.rate_controller import RateController

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


def test_banxico_category_a_diagnostic(tmp_path: Path) -> None:
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
    discovery_engine = DiscoveryEngine(
        storage=storage,
        max_workers=50,
        max_endpoints=100,
        expansion_wrapper=wrapper,
    )

    raw_observations = discovery_engine.run_discovery(
        tenant_id=tenant_id,
        rate_controller=RateController(),
        cycle_id="cycle_diag_000001",
        seed_endpoints=[seed],
        expansion_mode="A_ONLY",
    )

    graph = wrapper.last_graph
    domain_nodes = 0
    candidates = []
    if graph is not None:
        domain_nodes = len(graph.get_nodes_by_type(NodeType.DOMAIN))
        candidates = extract_candidates(graph)

    successful = sum(1 for r in raw_observations if getattr(r, "success", False))
    failed = len(raw_observations) - successful

    output = {
        "category_a_domain_nodes": domain_nodes,
        "category_a_total_candidates": len(candidates),
        "successful_observations": successful,
        "failed_observations": failed,
    }

    print(json.dumps(output, indent=2, sort_keys=True))
