from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import List

import layers.layer0_observation.acquisition.protocol_observer as protocol_observer

from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.discovery.expansion_bcde.impl import ActiveProbeEngine, BCDEExpansionContext
from infrastructure.discovery.expansion_wrapper import ExpansionConfig, ExpansionResult
from infrastructure.storage_manager.storage_manager import StorageManager
from layers.layer0_observation.acquisition.observation_bridge import ObservationBridge
from layers.layer0_observation.acquisition.protocol_observer import (
    DNSObservation,
    HTTPObservation,
    RawObservation,
    TCPObservation,
    TLSObservation,
)


@dataclass
class _FakeSeries:
    observations: List[RawObservation]
    elapsed_ms: int = 5


class _BudgetRecordingExpansionWrapper:
    def __init__(self) -> None:
        self.calls: List[ExpansionConfig] = []

    def expand(self, root_domain: str, config: ExpansionConfig, stage_callback=None, progress_callback=None) -> ExpansionResult:
        self.calls.append(config)
        return ExpansionResult(
            root_domain=root_domain,
            endpoint_candidates=set(),
            node_count=1,
            edge_count=0,
            ceilings_hit=False,
            diagnostics={},
        )


def _observation(endpoint: str) -> RawObservation:
    return RawObservation(
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


def _new_storage(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    storage.save_seed_endpoints("tenant_a", ["www.example.com:443"])
    return storage


def test_phase8_discovery_scope_budgets_do_not_exceed_cycle_budget(
    monkeypatch,
    tmp_path: Path,
) -> None:
    storage = _new_storage(tmp_path)
    wrapper = _BudgetRecordingExpansionWrapper()
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
        lambda endpoint, samples, **kwargs: _FakeSeries(observations=[_observation(endpoint)]),
    )
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    deadline_ms = int(time.time() * 1000) + (900 * 1000)
    engine.run_discovery(
        tenant_id="tenant_a",
        rate_controller=None,
        cycle_id="cycle_000001",
        cycle_deadline_unix_ms=deadline_ms,
    )

    assert len(wrapper.calls) >= 1
    first_scope = wrapper.calls[0]
    assert first_scope.category_a_time_budget_seconds == 300
    assert first_scope.bcde_time_budget_seconds == 300
    assert first_scope.exploration_budget_seconds == 300
    assert 0 <= first_scope.exploitation_budget_seconds <= 600
    assert (
        first_scope.exploration_budget_seconds + first_scope.exploitation_budget_seconds
    ) <= 900


def test_phase8_active_probe_timeout_clamps_to_remaining_deadline() -> None:
    context = BCDEExpansionContext(
        root_domain="example.com",
        deadline_unix_ms=int(time.time() * 1000) + 900,
    )

    effective_timeout = ActiveProbeEngine._remaining_timeout_seconds(8.0, context)

    assert effective_timeout is not None
    assert 0.05 <= effective_timeout <= 0.9


def test_phase8_active_probe_timeout_returns_none_when_deadline_is_exhausted() -> None:
    context = BCDEExpansionContext(
        root_domain="example.com",
        deadline_unix_ms=int(time.time() * 1000) - 10,
    )

    assert ActiveProbeEngine._remaining_timeout_seconds(8.0, context) is None
