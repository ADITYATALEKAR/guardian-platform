import json
import socket
import ssl
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
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
    """
    Test-only wrapper that skips Category A entirely.
    Builds a minimal graph from the seed domain and runs BCDE only.
    """

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
        # Pass A_BCDE to satisfy DiscoveryEngine validation, but wrapper skips A.
        kwargs["expansion_mode"] = "A_BCDE"
        return super().run_discovery(*args, **kwargs)


def _run_phase(
    phase_name: str,
    discovery_engine: DiscoveryEngine,
    tenant_id: str,
    seed: str,
    expansion_mode: str,
    wrapper: Any,
    duration_sec: int,
) -> Dict[str, int]:
    start = time.monotonic()
    last_print = start
    previous_domains: Optional[int] = None
    metrics: Dict[str, int] = {
        "domain_nodes": 0,
        "total_candidates": 0,
        "successful": 0,
        "failed": 0,
    }

    def _run_with_heartbeat(fn, label: str, interval_sec: int = 10):
        stop_event = threading.Event()

        def _heartbeat():
            while not stop_event.is_set():
                elapsed = int(time.monotonic() - start)
                print(f"[{label}] heartbeat time_elapsed={elapsed}s", flush=True)
                stop_event.wait(interval_sec)

        thread = threading.Thread(target=_heartbeat, daemon=True)
        thread.start()
        try:
            return fn()
        finally:
            stop_event.set()
            thread.join(timeout=1)

    while True:
        print(f"[{phase_name}] starting discovery pass", flush=True)

        def _do_discovery():
            return discovery_engine.run_discovery(
                tenant_id=tenant_id,
                rate_controller=RateController(),
                cycle_id=f"cycle_{phase_name.lower()}_000001",
                seed_endpoints=[seed],
                expansion_mode=expansion_mode,
            )

        raw = _run_with_heartbeat(_do_discovery, phase_name)

        graph = wrapper.last_graph
        if graph is None:
            raise AssertionError(f"{phase_name} did not produce a graph")

        domain_nodes = len(graph.get_nodes_by_type(NodeType.DOMAIN))

        if phase_name == "A_ONLY":
            candidates = extract_candidates(graph)
        else:
            candidates = extract_bcde_candidates(graph, graph.get_nodes_by_type(NodeType.DOMAIN)[0].id)

        successful = sum(1 for r in raw if getattr(r, "success", False))
        failed = len(raw) - successful

        metrics = {
            "domain_nodes": domain_nodes,
            "total_candidates": len(candidates),
            "successful": successful,
            "failed": failed,
        }

        now = time.monotonic()
        elapsed = int(now - start)
        if now - last_print >= 10:
            print(
                f"[{phase_name}] time_elapsed={elapsed}s domains={domain_nodes} "
                f"success={successful} failed={failed}"
            )
            last_print = now

        if previous_domains is not None and domain_nodes <= previous_domains:
            break
        previous_domains = domain_nodes

        if now - start >= duration_sec:
            break

    return metrics


def test_banconal_dual_phase_expansion(tmp_path: Path) -> None:
    start_total = time.monotonic()

    prod_root = tmp_path / "tenant_storage"
    sim_root = tmp_path / "simulation_storage"

    target_host = "www.banconal.com.pa"
    target_port = 443

    # Pre-flight network diagnostics (test-only).
    diagnostics = {
        "dns": {"ok": False, "addresses": [], "error": None},
        "tcp_443": {"ok": False, "error": None},
        "tls_handshake": {"ok": False, "error": None, "cert_subject": None},
        "http_head": {"ok": False, "status": None, "error": None},
    }
    try:
        infos = socket.getaddrinfo(target_host, target_port, type=socket.SOCK_STREAM)
        addresses = sorted({info[4][0] for info in infos})
        diagnostics["dns"]["ok"] = True
        diagnostics["dns"]["addresses"] = addresses
    except Exception as e:
        diagnostics["dns"]["error"] = repr(e)

    try:
        with socket.create_connection((target_host, target_port), timeout=5):
            diagnostics["tcp_443"]["ok"] = True
    except Exception as e:
        diagnostics["tcp_443"]["error"] = repr(e)

    try:
        context = ssl.create_default_context()
        with socket.create_connection((target_host, target_port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=target_host) as tls_sock:
                cert = tls_sock.getpeercert()
                diagnostics["tls_handshake"]["ok"] = True
                diagnostics["tls_handshake"]["cert_subject"] = cert.get("subject")
    except Exception as e:
        diagnostics["tls_handshake"]["error"] = repr(e)

    try:
        context = ssl.create_default_context()
        with socket.create_connection((target_host, target_port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=target_host) as tls_sock:
                request = (
                    f"HEAD / HTTP/1.1\r\nHost: {target_host}\r\n"
                    "User-Agent: banconal-dual-phase-test\r\n"
                    "Connection: close\r\n\r\n"
                )
                tls_sock.sendall(request.encode("ascii", errors="ignore"))
                data = tls_sock.recv(1024).decode("utf-8", errors="replace")
                status_line = data.splitlines()[0] if data else ""
                diagnostics["http_head"]["ok"] = True
                diagnostics["http_head"]["status"] = status_line
    except Exception as e:
        diagnostics["http_head"]["error"] = repr(e)

    print(json.dumps({"preflight_diagnostics": diagnostics}, indent=2, sort_keys=True), flush=True)

    storage = StorageManager(str(prod_root))
    identity = IdentityManager(storage)
    lifecycle = TenantLifecycleManager(storage, identity, str(sim_root))

    seed = f"{target_host}:{target_port}"
    tenant_id = lifecycle.register_tenant(
        name="Banco Nacional de Panama",
        password="StrongTestPassword123!",
        main_url="https://www.banconal.com.pa/",
        seed_endpoints=[seed],
    )

    # Phase 1 — A_ONLY
    a_wrapper = CategoryAOnlyWrapper()
    a_engine = DiscoveryEngine(
        storage=storage,
        max_workers=20,
        max_endpoints=100000,
        expansion_wrapper=a_wrapper,
    )
    assert a_engine.max_workers <= 20

    a_metrics = _run_phase(
        "A_ONLY",
        a_engine,
        tenant_id,
        seed,
        "A_ONLY",
        a_wrapper,
        duration_sec=60,
    )

    # Phase 2 — BCDE_ONLY
    bcde_wrapper = BCDEOnlyWrapper(max_total_endpoints=100000)
    bcde_engine = BCDEOnlyDiscoveryEngine(
        storage=storage,
        max_workers=20,
        max_endpoints=100000,
        expansion_wrapper=bcde_wrapper,
    )
    assert bcde_engine.max_workers <= 20

    bcde_metrics = _run_phase(
        "BCDE_ONLY",
        bcde_engine,
        tenant_id,
        seed,
        "BCDE_ONLY",
        bcde_wrapper,
        duration_sec=60,
    )

    if a_metrics["domain_nodes"] < 1:
        raise AssertionError("Expansion A discovered no domain candidates")

    if bcde_metrics["domain_nodes"] < a_metrics["domain_nodes"]:
        raise AssertionError("BCDE did not expand beyond A baseline")

    total_elapsed = time.monotonic() - start_total
    if total_elapsed > 600:
        raise AssertionError("Test exceeded 10 minute limit")

    output = {
        "target": "www.banconal.com.pa",
        "phase_A": {
            "domain_nodes": a_metrics["domain_nodes"],
            "total_candidates": a_metrics["total_candidates"],
            "successful": a_metrics["successful"],
            "failed": a_metrics["failed"],
        },
        "phase_BCDE": {
            "domain_nodes": bcde_metrics["domain_nodes"],
            "total_candidates": bcde_metrics["total_candidates"],
            "successful": bcde_metrics["successful"],
            "failed": bcde_metrics["failed"],
        },
        "delta_growth_from_A_to_BCDE": {
            "new_domains": bcde_metrics["domain_nodes"] - a_metrics["domain_nodes"],
            "new_successful": bcde_metrics["successful"] - a_metrics["successful"],
        },
    }

    print(json.dumps(output, indent=2, sort_keys=True))
