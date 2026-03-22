from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import List

import layers.layer0_observation.acquisition.protocol_observer as protocol_observer

from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.discovery.expansion_category_a import (
    CertificateTransparencyModule,
    ExpansionCategoryA,
    ExpansionContext,
    NodeType,
    PassiveDiscoveryGraph,
)
from infrastructure.discovery.expansion_wrapper import ExpansionConfig, ExpansionResult
from infrastructure.discovery.scope_utils import extract_registrable_base
from infrastructure.storage_manager.storage_manager import StorageManager
from infrastructure.unified_discovery_v2.models import RawObservation
from infrastructure.unified_discovery_v2.snapshot_builder import SnapshotBuilder
from infrastructure.unified_discovery_v2.temporal_state_engine import TemporalStateEngine
from layers.layer0_observation.acquisition.observation_bridge import ObservationBridge
from layers.layer0_observation.acquisition.protocol_observer import (
    DNSObservation,
    HTTPObservation,
    RawObservation as ProtocolRawObservation,
    TCPObservation,
    TLSObservation,
)


@dataclass
class _FakeSeries:
    observations: List[ProtocolRawObservation]
    elapsed_ms: int = 5


class _TimingExpansionWrapper:
    def __init__(self) -> None:
        self.calls: List[ExpansionConfig] = []

    def expand(self, root_domain: str, config: ExpansionConfig, stage_callback=None, progress_callback=None) -> ExpansionResult:
        call_index = len(self.calls)
        self.calls.append(config)
        timings = [
            {
                "a_exploration_s": 420.0,
                "bcde_exploration_s": 0.0,
                "a_exploitation_s": 120.0,
                "bcde_exploitation_s": 0.0,
            },
            {
                "a_exploration_s": 60.0,
                "bcde_exploration_s": 0.0,
                "a_exploitation_s": 60.0,
                "bcde_exploitation_s": 0.0,
            },
        ]
        return ExpansionResult(
            root_domain=root_domain,
            endpoint_candidates=set(),
            node_count=1,
            edge_count=0,
            ceilings_hit=False,
            diagnostics={"timing": timings[min(call_index, len(timings) - 1)]},
        )


def _new_storage(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    storage.save_seed_endpoints("tenant_a", ["www.example.com:443"])
    return storage


def _protocol_observation(endpoint: str) -> ProtocolRawObservation:
    return ProtocolRawObservation(
        endpoint=endpoint,
        entity_id=endpoint,
        observation_id=f"obs_{endpoint.replace(':', '_')}",
        timestamp_ms=1_710_000_000_123,
        dns=DNSObservation(resolved_ip="1.1.1.1", resolution_time_ms=5.0),
        tcp=TCPObservation(connected=True, connect_time_ms=4.0),
        tls=TLSObservation(
            handshake_time_ms=10.0,
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            cert_subject="commonName=www.example.com",
            cert_issuer="commonName=Demo CA",
            cert_not_before="Jan  1 00:00:00 2026 GMT",
            cert_not_after="Jan  1 00:00:00 2027 GMT",
            cert_san=["www.example.com"],
            cert_public_key_algorithm="RSA",
            cert_public_key_size_bits=2048,
            cert_must_staple=False,
            cert_ocsp_urls=[],
            alpn_protocol="h2",
            sni_mismatch=False,
            ocsp_stapled=False,
        ),
        http=HTTPObservation(
            status_code=200,
            response_time_ms=12.0,
            headers={"server": "demo"},
        ),
        success=True,
    )


def test_phase10_scope_extraction_handles_ccTld_second_levels() -> None:
    assert extract_registrable_base("www.banxico.org.mx") == "banxico.org.mx"
    assert extract_registrable_base("www.boj.or.jp") == "boj.or.jp"
    assert extract_registrable_base("org.mx") is None
    assert extract_registrable_base("or.jp") is None
    assert extract_registrable_base("www.example.com") == "example.com"


def test_phase10_discovery_engine_budgets_are_global_across_scopes(
    monkeypatch,
    tmp_path: Path,
) -> None:
    storage = _new_storage(tmp_path)
    wrapper = _TimingExpansionWrapper()
    engine = DiscoveryEngine(
        storage=storage,
        max_workers=1,
        max_endpoints=1,
        expansion_wrapper=wrapper,
        enable_phase5_findings=False,
    )

    monkeypatch.setattr(
        protocol_observer,
        "observe_endpoint_series",
        lambda endpoint, samples, **kwargs: _FakeSeries(observations=[_protocol_observation(endpoint)]),
    )
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    engine.run_discovery(
        tenant_id="tenant_a",
        rate_controller=None,
        cycle_id="cycle_000001",
        cycle_deadline_unix_ms=int(time.time() * 1000) + (1_800 * 1000),
    )

    assert len(wrapper.calls) == 1
    assert wrapper.calls[0].category_a_time_budget_seconds == 300
    assert wrapper.calls[0].bcde_time_budget_seconds == 300
    assert wrapper.calls[0].exploration_budget_seconds == 300
    assert 599 <= wrapper.calls[0].exploitation_budget_seconds <= 600


def test_phase10_ct_module_skips_http_queries_once_deadline_is_exhausted(monkeypatch) -> None:
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
    context = ExpansionContext(
        root_domain="www.bank.com",
        deadline_unix_ms=int(time.time() * 1000) - 1,
    )

    rows = module._fetch_all_entries("www.bank.com", context=context)

    assert rows == []
    assert queries == []


def test_phase10_snapshot_builder_carries_forward_one_cycle_missing_endpoint() -> None:
    builder = SnapshotBuilder()
    previous_snapshot = {
        "schema_version": "1.2",
        "cycle_id": "cycle_000001",
        "cycle_number": 1,
        "timestamp_unix_ms": 1_709_000_000_000,
        "snapshot_hash_sha256": "old",
        "endpoint_count": 1,
        "endpoints": [
            {
                "hostname": "api.example.com",
                "port": 443,
                "tls_version": "TLSv1.3",
                "certificate_sha256": "sha256-current",
                "certificate_expiry_unix_ms": 1_760_000_000_000,
                "ports_responding": [443],
                "services_detected": ["https"],
                "discovered_by": ["protocol_observer"],
                "confidence": 1.0,
                "tls_jarm": None,
                "observation_state": "observed",
                "last_observed_cycle": 1,
                "last_observed_unix_ms": 1_709_000_000_000,
            }
        ],
    }
    previous_temporal = {
        "schema_version": "1.0",
        "last_cycle_id": "cycle_000001",
        "last_cycle_number": 1,
        "endpoints": {
            "api.example.com:443": {
                "endpoint_id": "api.example.com:443",
                "first_observed_cycle": 1,
                "last_observed_cycle": 1,
                "presence_history": [
                    {
                        "cycle_number": 1,
                        "timestamp_unix_ms": 1_709_000_000_000,
                        "present": True,
                    }
                ],
                "tls_change_history": [],
                "port_change_history": [],
                "certificate_change_history": [],
                "consecutive_absence": 0,
                "volatility_score": 0.0,
                "visibility_score": 1.0,
            }
        },
    }

    snapshot, diff, stats = builder.build_snapshot(
        cycle_id="cycle_000002",
        cycle_number=2,
        raw_observations=[],
        previous_snapshot=previous_snapshot,
        previous_temporal_state=previous_temporal,
    )

    assert snapshot.endpoint_count == 1
    assert snapshot.endpoints[0].endpoint_id() == "api.example.com:443"
    assert snapshot.endpoints[0].observation_state == "stale"
    assert diff.removed_endpoints == []
    assert stats.endpoints_canonical == 0
    assert stats.surface_endpoints == 1
    assert stats.stale_endpoints == 1


def test_phase10_snapshot_builder_removes_after_second_consecutive_absence() -> None:
    builder = SnapshotBuilder()
    previous_snapshot = {
        "schema_version": "1.2",
        "cycle_id": "cycle_000002",
        "cycle_number": 2,
        "timestamp_unix_ms": 1_710_000_000_000,
        "snapshot_hash_sha256": "old",
        "endpoint_count": 1,
        "endpoints": [
            {
                "hostname": "api.example.com",
                "port": 443,
                "tls_version": "TLSv1.3",
                "certificate_sha256": "sha256-current",
                "certificate_expiry_unix_ms": 1_760_000_000_000,
                "ports_responding": [443],
                "services_detected": ["https"],
                "discovered_by": ["protocol_observer"],
                "confidence": 1.0,
                "tls_jarm": None,
                "observation_state": "stale",
                "last_observed_cycle": 1,
                "last_observed_unix_ms": 1_709_000_000_000,
            }
        ],
    }
    previous_temporal = {
        "schema_version": "1.0",
        "last_cycle_id": "cycle_000002",
        "last_cycle_number": 2,
        "endpoints": {
            "api.example.com:443": {
                "endpoint_id": "api.example.com:443",
                "first_observed_cycle": 1,
                "last_observed_cycle": 1,
                "presence_history": [
                    {
                        "cycle_number": 1,
                        "timestamp_unix_ms": 1_709_000_000_000,
                        "present": True,
                    },
                    {
                        "cycle_number": 2,
                        "timestamp_unix_ms": 1_710_000_000_000,
                        "present": False,
                    },
                ],
                "tls_change_history": [],
                "port_change_history": [],
                "certificate_change_history": [],
                "consecutive_absence": 1,
                "volatility_score": 0.0,
                "visibility_score": 0.0,
            }
        },
    }

    snapshot, diff, stats = builder.build_snapshot(
        cycle_id="cycle_000003",
        cycle_number=3,
        raw_observations=[],
        previous_snapshot=previous_snapshot,
        previous_temporal_state=previous_temporal,
    )

    assert snapshot.endpoint_count == 0
    assert diff.removed_endpoints == ["api.example.com:443"]
    assert stats.surface_endpoints == 0
    assert stats.stale_endpoints == 0


def test_phase10_temporal_engine_treats_stale_snapshot_endpoint_as_absent() -> None:
    builder = SnapshotBuilder()
    engine = TemporalStateEngine()
    previous_snapshot = {
        "schema_version": "1.2",
        "cycle_id": "cycle_000001",
        "cycle_number": 1,
        "timestamp_unix_ms": 1_709_000_000_000,
        "snapshot_hash_sha256": "old",
        "endpoint_count": 1,
        "endpoints": [
            {
                "hostname": "api.example.com",
                "port": 443,
                "tls_version": "TLSv1.3",
                "certificate_sha256": "sha256-current",
                "certificate_expiry_unix_ms": 1_760_000_000_000,
                "ports_responding": [443],
                "services_detected": ["https"],
                "discovered_by": ["protocol_observer"],
                "confidence": 1.0,
                "tls_jarm": None,
                "observation_state": "observed",
                "last_observed_cycle": 1,
                "last_observed_unix_ms": 1_709_000_000_000,
            }
        ],
    }
    previous_temporal = {
        "schema_version": "1.0",
        "last_cycle_id": "cycle_000001",
        "last_cycle_number": 1,
        "endpoints": {
            "api.example.com:443": {
                "endpoint_id": "api.example.com:443",
                "first_observed_cycle": 1,
                "last_observed_cycle": 1,
                "presence_history": [
                    {
                        "cycle_number": 1,
                        "timestamp_unix_ms": 1_709_000_000_000,
                        "present": True,
                    }
                ],
                "tls_change_history": [],
                "port_change_history": [],
                "certificate_change_history": [],
                "consecutive_absence": 0,
                "volatility_score": 0.0,
                "visibility_score": 1.0,
            }
        },
    }

    current_snapshot, _, _ = builder.build_snapshot(
        cycle_id="cycle_000002",
        cycle_number=2,
        raw_observations=[],
        previous_snapshot=previous_snapshot,
        previous_temporal_state=previous_temporal,
    )

    updated = engine.update_state(
        current_snapshot=current_snapshot,
        previous_state=previous_temporal,
    )

    state = updated.endpoints["api.example.com:443"]
    assert state.last_observed_cycle == 1
    assert state.consecutive_absence == 1
    assert state.presence_history[-1].present is False


def test_phase10_category_a_skips_speculative_modules_on_non_registrable_scope() -> None:
    graph = PassiveDiscoveryGraph()
    graph.add_node("www.example.com", NodeType.DOMAIN, method="root", confidence=1.0)
    context = ExpansionContext(root_domain="www.example.com")
    observer_rows: List[dict] = []

    ExpansionCategoryA().run_modules(
        graph,
        context,
        enabled_module_names={"NameMutationModule", "SearchEngineModule"},
        module_observer=observer_rows.append,
        time_budget_seconds=5,
        per_module_time_slice_seconds=1,
    )

    assert observer_rows
    assert all(row["status"] == "skipped" for row in observer_rows)
    assert all(row["skip_reason"] == "scope_quality_requires_registrable_base" for row in observer_rows)
