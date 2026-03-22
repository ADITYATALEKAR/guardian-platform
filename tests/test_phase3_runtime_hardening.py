from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List

import pytest

import layers.layer0_observation.acquisition.protocol_observer as protocol_observer
from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.discovery.expansion_category_a import (
    CertificateTransparencyModule,
    ExpansionCategoryA,
    NodeType as CategoryANodeType,
    PassiveDiscoveryGraph as CategoryAGraph,
)
from infrastructure.discovery.expansion_category_bcde import (
    BCDEExpansionContext,
    ExpansionCategoryBCDE,
    HTTPCrawlModule,
    NodeType,
    PassiveDiscoveryGraph,
)
from infrastructure.discovery.expansion_wrapper import (
    ExpansionConfig,
    ExpansionResult,
    ExpansionWrapper,
)
from infrastructure.storage_manager.storage_manager import StorageManager
from infrastructure.unified_discovery_v2.snapshot_builder import SnapshotBuilder
from layers.layer0_observation.acquisition.protocol_observer import (
    DNSObservation,
    RawObservation as ProtocolRawObservation,
    TLSObservation,
)

pytestmark = [pytest.mark.performance]


@dataclass
class _FakeSeries:
    observations: List[object]
    elapsed_ms: int = 5


@dataclass
class _FakeObs:
    endpoint: str
    success: bool
    tls: Any
    endpoint_str: str = ""

    def __post_init__(self) -> None:
        if not self.endpoint_str:
            self.endpoint_str = self.endpoint


@dataclass
class _FakeTLS:
    cert_san: List[str]


class _StubExpansionWrapper:
    def __init__(self) -> None:
        self.calls: List[str] = []

    def expand(self, root_domain: str, config, stage_callback=None) -> ExpansionResult:
        self.calls.append(root_domain)
        return ExpansionResult(
            root_domain=root_domain,
            endpoint_candidates=set(),
            node_count=0,
            edge_count=0,
            ceilings_hit=False,
            diagnostics={},
        )


def _new_storage(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    return storage


def test_phase3_discovery_engine_dual_scope_worker_cap_and_reporting(monkeypatch, tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    wrapper = _StubExpansionWrapper()
    engine = DiscoveryEngine(
        storage=storage,
        max_workers=500,
        max_endpoints=20,
        samples_per_endpoint=1,
        expansion_wrapper=wrapper,
        max_san_recursion=999,
        max_dns_recursion=999,
        max_spf_recursion=999,
        bcde_time_budget_seconds=9999,
    )

    def _fake_observe(endpoint: str, samples: int, **kwargs) -> _FakeSeries:
        obs = _FakeObs(
            endpoint=endpoint,
            success=True,
            tls=_FakeTLS(cert_san=[]),
        )
        return _FakeSeries(observations=[obs], elapsed_ms=7)

    monkeypatch.setattr(protocol_observer, "observe_endpoint_series", _fake_observe)

    results = engine.run_discovery(
        tenant_id="tenant_a",
        rate_controller=None,
        cycle_id="cycle_000001",
        seed_endpoints=["www.example.com:443"],
        expansion_mode="A_ONLY",
    )

    assert len(results) == 1
    assert sorted(set(wrapper.calls)) == ["example.com", "www.example.com"]
    assert engine.max_workers == 75
    assert engine.max_san_recursion == 10
    assert engine.max_dns_recursion == 10
    assert engine.max_spf_recursion == 15
    assert engine.bcde_time_budget_seconds == 1800

    metrics = engine.get_last_reporting_metrics()
    assert metrics["total_discovered_domains"] >= 1
    assert metrics["total_successful_observations"] == 1
    assert metrics["total_failed_observations"] == 0


def test_phase3_ct_query_widening_patterns(monkeypatch) -> None:
    queries: List[str] = []

    def _fake_safe_http_get(url: str, params=None, timeout: int = 0, **kwargs):
        if isinstance(params, dict):
            queries.append(str(params.get("q", "")))
        return []

    monkeypatch.setattr(
        "infrastructure.discovery.expansion_category_a.safe_http_get",
        _fake_safe_http_get,
    )

    module = CertificateTransparencyModule()
    rows = module._fetch_all_entries("www.bank.com")
    assert rows == []
    assert queries == [
        "%.www.bank.com",
        "www.bank.com",
        "%.bank.com",
        "bank.com",
    ]


def test_phase3_bcde_budget_cancel_and_crawl_gate() -> None:
    graph = PassiveDiscoveryGraph()
    graph.add_node("example.com", NodeType.DOMAIN, method="root", confidence=1.0)

    context = BCDEExpansionContext(
        root_domain="example.com",
        time_budget_seconds=60,
        deadline_unix_ms=int(time.time() * 1000) - 1,
    )
    engine = ExpansionCategoryBCDE()
    result_graph = engine.expand(graph, context)

    assert result_graph is graph
    assert context.cancel_requested is True
    assert len(result_graph.all_nodes()) == 1

    crawl = HTTPCrawlModule()
    gate_context = BCDEExpansionContext(root_domain="example.com")
    gate_context.open_ports_cache["api.example.com"] = [22]
    assert crawl._has_http_response("api.example.com", gate_context) is False
    gate_context.open_ports_cache["api.example.com"] = [443]
    assert crawl._has_http_response("api.example.com", gate_context) is True


def test_phase3_snapshot_reporting_metrics_split() -> None:
    obs_success = ProtocolRawObservation(
        endpoint="a.example.com:443",
        entity_id="a.example.com:443",
        observation_id="obs_1",
        timestamp_ms=1_000,
        dns=DNSObservation(resolved_ip="1.1.1.1"),
        tls=TLSObservation(handshake_time_ms=12.0, tls_version="TLSv1.3"),
        success=True,
    )
    obs_failed = ProtocolRawObservation(
        endpoint="b.example.com:443",
        entity_id="b.example.com:443",
        observation_id="obs_2",
        timestamp_ms=1_100,
        dns=DNSObservation(resolved_ip=None),
        tls=TLSObservation(handshake_time_ms=None, tls_version=None),
        success=False,
        error="timeout",
    )

    builder = SnapshotBuilder()
    _snapshot, _diff, stats = builder.build_snapshot(
        cycle_id="cycle_000001",
        cycle_number=1,
        raw_observations=[obs_success, obs_failed],
        reporting_metrics={
            "total_discovered_domains": 12,
            "total_successful_observations": 7,
            "total_failed_observations": 5,
        },
    )

    assert stats.successful_observations == 1
    assert stats.failed_observations == 1
    assert stats.total_discovered_domains == 12
    assert stats.total_successful_observations == 7
    assert stats.total_failed_observations == 5


def test_category_a_global_ceiling_enforced_post_module(caplog: pytest.LogCaptureFixture) -> None:
    class _ModuleOne:
        def execute(self, graph: CategoryAGraph, context) -> None:
            graph.add_node("one.example.com", CategoryANodeType.DOMAIN, method="m1")

    class _ModuleTwo:
        def __init__(self) -> None:
            self.called = False

        def execute(self, graph: CategoryAGraph, context) -> None:
            self.called = True
            graph.add_node("two.example.com", CategoryANodeType.DOMAIN, method="m2")

    category_a = ExpansionCategoryA()
    second = _ModuleTwo()
    category_a._modules = [_ModuleOne(), second]

    with caplog.at_level("WARNING"):
        graph = category_a.get_full_graph(
            "example.com",
            context_overrides={
                "max_total_nodes": 2,
                "max_total_edges": 10,
                "max_total_endpoints": 10,
            },
        )

    assert len(graph.all_nodes()) == 2
    assert second.called is False
    assert "Category A global ceiling hit" in caplog.text


def test_expansion_wrapper_passes_global_ceilings_to_category_a() -> None:
    class _CaptureCategoryA:
        def __init__(self) -> None:
            self.context_overrides = None

        def get_full_graph(self, root_domain: str, context_overrides=None):  # noqa: ANN001
            self.context_overrides = dict(context_overrides or {})
            graph = CategoryAGraph()
            graph.add_node(root_domain, CategoryANodeType.DOMAIN, method="root")
            return graph

    capture = _CaptureCategoryA()
    wrapper = ExpansionWrapper(category_a=capture)

    config = ExpansionConfig(
        aggressive=False,
        max_total_nodes=123,
        max_total_edges=456,
        max_total_endpoints=789,
    )
    wrapper.expand("example.com", config)

    assert capture.context_overrides is not None
    assert capture.context_overrides["max_total_nodes"] == 123
    assert capture.context_overrides["max_total_edges"] == 456
    assert capture.context_overrides["max_total_endpoints"] == 789
