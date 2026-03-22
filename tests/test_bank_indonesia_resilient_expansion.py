import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional
import pytest

from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.discovery.expansion_wrapper import ExpansionConfig
from infrastructure.discovery.expansion_category_a import (
    ExpansionCategoryA,
    NodeType,
    PassiveDiscoveryGraph,
    extract_candidates,
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

pytestmark = [pytest.mark.network, pytest.mark.slow]


class CategoryAOnlyWrapper:
    def __init__(self):
        self._category_a = ExpansionCategoryA()
        self.last_graph: Optional[PassiveDiscoveryGraph] = None

    def expand(self, root_domain: str, config: ExpansionConfig):
        graph = self._category_a.get_full_graph(root_domain)
        self.last_graph = graph
        candidates = extract_candidates(graph)
        endpoint_candidates = {c.host for c in candidates}
        return type(
            "ExpansionResult",
            (object,),
            {
                "root_domain": root_domain,
                "endpoint_candidates": endpoint_candidates,
                "node_count": len(graph.all_nodes()),
                "edge_count": len(graph.all_edges()),
                "ceilings_hit": False,
                "diagnostics": {"mode": "A_ONLY"},
            },
        )


class BCDEOnlyWrapper:
    def __init__(self, max_total_endpoints: int):
        self._max_total_endpoints = int(max_total_endpoints)
        self._category_bcde = ExpansionCategoryBCDE()
        self.last_graph: Optional[PassiveDiscoveryGraph] = None
        self.last_context: Optional[BCDEExpansionContext] = None

    def expand(self, root_domain: str, config: ExpansionConfig):
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
                "ceilings_hit": len(graph_full.get_nodes_by_type(NodeType.ENDPOINT))
                >= self._max_total_endpoints,
                "diagnostics": {"mode": "BCDE_ONLY"},
            },
        )


class BCDEOnlyDiscoveryEngine(DiscoveryEngine):
    def run_discovery(self, *args: Any, **kwargs: Any):
        expansion_mode = kwargs.get("expansion_mode")
        if expansion_mode != "BCDE_ONLY":
            raise RuntimeError("Expansion mode not forced to BCDE_ONLY")
        kwargs["expansion_mode"] = "A_BCDE"
        return super().run_discovery(*args, **kwargs)


def _run_with_heartbeat(fn, label: str, start: float, interval_sec: int = 10):
    stop_event = threading.Event()

    def _heartbeat():
        while not stop_event.is_set():
            elapsed = int(time.monotonic() - start)
            print(f"[{label}] heartbeat elapsed={elapsed}s", flush=True)
            stop_event.wait(interval_sec)

    thread = threading.Thread(target=_heartbeat, daemon=True)
    thread.start()
    try:
        return fn()
    finally:
        stop_event.set()
        thread.join(timeout=1)


def _run_phase(
    phase_name: str,
    discovery_engine: DiscoveryEngine,
    tenant_id: str,
    seed: str,
    expansion_mode: str,
    wrapper: Any,
    duration_sec: int,
    start_total: float,
    results: Dict[str, Dict[str, int]],
    errors: list,
) -> None:
    phase_start = time.monotonic()
    last_print = phase_start
    previous_domains: Optional[int] = None

    while True:
        if time.monotonic() - start_total > 150:
            errors.append("total runtime exceeded 150 seconds")
            break

        print(f"[{phase_name}] starting discovery pass", flush=True)

        def _do_discovery():
            return discovery_engine.run_discovery(
                tenant_id=tenant_id,
                rate_controller=RateController(),
                cycle_id=f"cycle_{phase_name.lower()}_000001",
                seed_endpoints=[seed],
                expansion_mode=expansion_mode,
            )

        try:
            raw = _run_with_heartbeat(_do_discovery, phase_name, phase_start)
        except Exception as e:
            errors.append(f"{phase_name} discovery error: {repr(e)}")
            break

        graph = wrapper.last_graph
        if graph is None:
            errors.append(f"{phase_name} produced no graph")
            break

        domain_nodes = len(graph.get_nodes_by_type(NodeType.DOMAIN))
        successful = sum(1 for r in raw if getattr(r, "success", False))
        failed = len(raw) - successful

        results[phase_name] = {
            "domain_nodes": domain_nodes,
            "successful": successful,
            "failed": failed,
        }

        now = time.monotonic()
        if now - last_print >= 10:
            elapsed = int(now - phase_start)
            print(
                f"[{phase_name}] elapsed={elapsed}s domains={domain_nodes} "
                f"success={successful} failed={failed}",
                flush=True,
            )
            last_print = now

        if previous_domains is not None and domain_nodes <= previous_domains:
            break
        previous_domains = domain_nodes

        if now - phase_start >= duration_sec:
            break


def test_bank_indonesia_resilient_expansion(tmp_path: Path) -> None:
    start_total = time.monotonic()
    results: Dict[str, Dict[str, int]] = {"phase_A": {}, "phase_BCDE": {}}
    errors: list = []

    prod_root = tmp_path / "tenant_storage"
    sim_root = tmp_path / "simulation_storage"

    storage = StorageManager(str(prod_root))
    identity = IdentityManager(storage)
    lifecycle = TenantLifecycleManager(storage, identity, str(sim_root))

    seed = "www.bi.go.id:443"
    tenant_id = lifecycle.register_tenant(
        name="Bank Indonesia",
        password="StrongTestPassword123!",
        main_url="https://www.bi.go.id/",
        seed_endpoints=[seed],
    )

    try:
        a_wrapper = CategoryAOnlyWrapper()
        a_engine = DiscoveryEngine(
            storage=storage,
            max_workers=20,
            max_endpoints=100000,
            expansion_wrapper=a_wrapper,
        )
        _run_phase(
            "phase_A",
            a_engine,
            tenant_id,
            seed,
            "A_ONLY",
            a_wrapper,
            duration_sec=60,
            start_total=start_total,
            results=results,
            errors=errors,
        )
    except Exception as e:
        errors.append(f"phase_A error: {repr(e)}")

    try:
        bcde_wrapper = BCDEOnlyWrapper(max_total_endpoints=100000)
        bcde_engine = BCDEOnlyDiscoveryEngine(
            storage=storage,
            max_workers=20,
            max_endpoints=100000,
            expansion_wrapper=bcde_wrapper,
        )
        _run_phase(
            "phase_BCDE",
            bcde_engine,
            tenant_id,
            seed,
            "BCDE_ONLY",
            bcde_wrapper,
            duration_sec=60,
            start_total=start_total,
            results=results,
            errors=errors,
        )
    except Exception as e:
        errors.append(f"phase_BCDE error: {repr(e)}")
    finally:
        runtime_seconds = int(time.monotonic() - start_total)
        output = {
            "target": "www.bi.go.id",
            "runtime_seconds": runtime_seconds,
            "phase_A": results.get("phase_A", {}),
            "phase_BCDE": results.get("phase_BCDE", {}),
            "errors": errors,
        }
        print(json.dumps(output, indent=2, sort_keys=True))
