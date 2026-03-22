import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple
import pytest

from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.discovery.expansion_wrapper import ExpansionConfig
from infrastructure.discovery.expansion_category_a import (
    NodeType,
    PassiveDiscoveryGraph,
)
from infrastructure.discovery.expansion_category_bcde import (
    BCDEExpansionContext,
    ExpansionCategoryBCDE,
    extract_bcde_candidates,
)
from infrastructure.runtime.tenant_lifecycle_manager import TenantLifecycleManager
from infrastructure.storage_manager.identity_manager import IdentityManager
from infrastructure.storage_manager.storage_manager import StorageManager
from infrastructure.unified_discovery_v2.rate_controller import RateController

pytestmark = [pytest.mark.network]


class BCDEOnlyWrapper:
    """
    Test-only wrapper that skips Category A entirely.
    Builds a minimal graph from the seed domain and runs BCDE modules only.
    """

    def __init__(self, max_total_endpoints: int):
        self._max_total_endpoints = int(max_total_endpoints)
        self._category_bcde = ExpansionCategoryBCDE()
        self.last_graph: PassiveDiscoveryGraph | None = None
        self.last_context: BCDEExpansionContext | None = None

    def expand(self, root_domain: str, config: ExpansionConfig):
        # Minimal seed graph: just the root domain node.
        graph = PassiveDiscoveryGraph()
        graph.add_node(
            root_domain,
            NodeType.DOMAIN,
            method="seed",
            confidence=1.0,
            metadata={"seed": True},
        )

        context = BCDEExpansionContext(
            root_domain=root_domain,
            max_total_nodes=config.max_total_nodes,
            max_total_edges=config.max_total_edges,
            max_total_endpoints=self._max_total_endpoints,
        )
        self.last_context = context

        graph_full = self._category_bcde.expand(graph, context)
        self.last_graph = graph_full

        candidates = extract_bcde_candidates(graph_full, root_domain)
        endpoint_candidates = {c.host for c in candidates}

        return type(
            "ExpansionResult",
            (object,),
            {
                "root_domain": root_domain,
                "endpoint_candidates": endpoint_candidates,
                "node_count": len(graph_full.all_nodes()),
                "edge_count": len(graph_full.all_edges()),
                "ceilings_hit": len(graph_full.get_nodes_by_type(NodeType.ENDPOINT)) >= self._max_total_endpoints,
                "diagnostics": {"mode": "BCDE_ONLY"},
            },
        )


class BCDEOnlyDiscoveryEngine(DiscoveryEngine):
    def run_discovery(self, *args: Any, **kwargs: Any):
        expansion_mode = kwargs.get("expansion_mode")
        if expansion_mode != "BCDE_ONLY":
            raise RuntimeError("Expansion mode not forced to BCDE_ONLY")
        # Use A_BCDE internally so DiscoveryEngine passes its validation.
        kwargs["expansion_mode"] = "A_BCDE"
        return super().run_discovery(*args, **kwargs)


def _parse_endpoint_host_port(endpoint_id: str) -> Tuple[str, int]:
    # endpoint_id examples: "https://host:443", "http://host:80"
    host_port = endpoint_id
    for prefix in ("https://", "http://"):
        if host_port.startswith(prefix):
            host_port = host_port[len(prefix):]
            break
    if ":" in host_port:
        host, port_str = host_port.rsplit(":", 1)
        try:
            return host, int(port_str)
        except ValueError:
            return host, 0
    return host_port, 0


def test_banxico_expansion_bcde_only(tmp_path: Path) -> None:
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

    wrapper = BCDEOnlyWrapper(max_total_endpoints=100)
    discovery_engine = BCDEOnlyDiscoveryEngine(
        storage=storage,
        max_workers=20,
        max_endpoints=100,
        expansion_wrapper=wrapper,
    )

    raw_observations = discovery_engine.run_discovery(
        tenant_id=tenant_id,
        rate_controller=RateController(),
        cycle_id="cycle_bcde_000001",
        seed_endpoints=[seed],
        expansion_mode="BCDE_ONLY",
    )

    graph = wrapper.last_graph
    context = wrapper.last_context
    if graph is None or context is None:
        raise AssertionError("BCDE expansion did not produce a graph/context")

    bcde_domain_nodes = len(graph.get_nodes_by_type(NodeType.DOMAIN))
    candidates = extract_bcde_candidates(graph, context.root_domain)
    bcde_total_candidates = len(candidates)

    successful = sum(1 for r in raw_observations if getattr(r, "success", False))
    failed = len(raw_observations) - successful

    endpoint_nodes = graph.get_nodes_by_type(NodeType.ENDPOINT)
    graph_nodes = len(graph.all_nodes())
    graph_edges = len(graph.all_edges())

    discovered_domains = sorted(node.id for node in graph.get_nodes_by_type(NodeType.DOMAIN))
    print("First 15 discovered domains:", discovered_domains[:15])

    # Required assertions
    if bcde_domain_nodes <= 5:
        raise AssertionError("BCDE expansion produced insufficient breadth")
    if bcde_domain_nodes <= 22:
        raise AssertionError("BCDE did not exceed A-only baseline (22 domains)")
    if bcde_domain_nodes <= 1:
        raise AssertionError("BCDE produced no new domain candidates")

    if len(endpoint_nodes) > context.max_total_endpoints:
        raise AssertionError("Global endpoint cap exceeded")

    # Per-host port cap check using endpoint metadata or endpoint_id parsing.
    ports_by_host: Dict[str, Set[int]] = defaultdict(set)
    for node in endpoint_nodes:
        meta = node.metadata or {}
        host = meta.get("host")
        port = meta.get("port")
        if host is None or port is None:
            host, port = _parse_endpoint_host_port(node.id)
        if host:
            ports_by_host[host].add(int(port))

    for host, ports in ports_by_host.items():
        if len(ports) > context.max_ports_per_host:
            raise AssertionError(
                f"Host {host} exceeded max_ports_per_host "
                f"({len(ports)} > {context.max_ports_per_host})"
            )

    # Structural metrics output
    output = {
        "bcde_domain_nodes": bcde_domain_nodes,
        "bcde_total_candidates": bcde_total_candidates,
        "successful_observations": successful,
        "failed_observations": failed,
        "graph_nodes": graph_nodes,
        "graph_edges": graph_edges,
    }

    print(json.dumps(output, indent=2, sort_keys=True))
