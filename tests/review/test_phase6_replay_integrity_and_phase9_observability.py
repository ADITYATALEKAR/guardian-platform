from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

import layers.layer0_observation.acquisition.protocol_observer as protocol_observer

from infrastructure.aggregation.authz_contract import AuthorizedTenantScope
from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.discovery.expansion_wrapper import ExpansionResult
from infrastructure.layer5_api.services.runtime_read_adapter import RuntimeReadAdapter
from infrastructure.runtime.engine_runtime import EngineRuntime
from infrastructure.storage_manager.storage_manager import StorageManager
from infrastructure.unified_discovery_v2.snapshot_builder import SnapshotBuilder
from infrastructure.unified_discovery_v2.temporal_state_engine import TemporalStateEngine
from infrastructure.unified_discovery_v2.unified_cycle_orchestrator import UnifiedCycleOrchestrator
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
    elapsed_ms: int = 10


class _StubExpansionWrapper:
    def expand(self, root_domain: str, config, stage_callback=None, progress_callback=None) -> ExpansionResult:
        return ExpansionResult(
            root_domain=root_domain,
            endpoint_candidates={"api.example.com:443"},
            node_count=2,
            edge_count=1,
            ceilings_hit=False,
            diagnostics={},
        )


def _observation(endpoint: str) -> RawObservation:
    return RawObservation(
        endpoint=endpoint,
        entity_id=endpoint,
        observation_id=f"obs_{endpoint.replace(':', '_')}",
        timestamp_ms=1_710_000_000_123,
        dns=DNSObservation(resolved_ip="1.1.1.1", resolution_time_ms=10.0),
        tcp=TCPObservation(connected=True, connect_time_ms=8.5),
        tls=TLSObservation(
            handshake_time_ms=22.0,
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            cert_subject="commonName=api.example.com",
            cert_issuer="commonName=Demo CA",
            cert_not_before="Jan  1 00:00:00 2026 GMT",
            cert_not_after="Jan  1 00:00:00 2027 GMT",
            cert_san=["api.example.com"],
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
            response_time_ms=30.0,
            headers={"server": "cloudflare"},
        ),
        success=True,
    )


def _new_storage(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    storage.save_seed_endpoints("tenant_a", ["api.example.com:443"])
    return storage


def _orchestrator(storage: StorageManager) -> UnifiedCycleOrchestrator:
    engine = DiscoveryEngine(
        storage=storage,
        max_workers=2,
        max_endpoints=4,
        expansion_wrapper=_StubExpansionWrapper(),
        enable_phase5_findings=False,
    )
    return UnifiedCycleOrchestrator(
        storage=storage,
        discovery_engine=engine,
        snapshot_builder=SnapshotBuilder(),
        temporal_engine=TemporalStateEngine(),
    )


def test_phase6_cycle_bundle_reports_exact_replay_integrity(monkeypatch, tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    monkeypatch.setattr(
        protocol_observer,
        "observe_endpoint_series",
        lambda endpoint, samples, **kwargs: _FakeSeries(observations=[_observation(endpoint)], elapsed_ms=10),
    )
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    result = _orchestrator(storage).run_cycle("tenant_a")

    runtime = EngineRuntime(storage=storage)
    adapter = RuntimeReadAdapter(runtime)
    scope = AuthorizedTenantScope.from_iterable("operator_a", ["tenant_a"])
    payload = adapter.cycle_bundle(
        "tenant_a",
        result.metadata.cycle_id,
        authz_scope=scope,
    )

    integrity = payload["integrity_summary"]
    assert integrity["exact_cycle_replayable"] is True
    assert integrity["served_view_complete"] is True
    assert integrity["coverage"]["snapshot_vs_metadata_endpoint_count_match"] is True
    assert integrity["persisted_counts"]["snapshot_endpoints"] >= 1
    assert integrity["persisted_counts"]["telemetry_records"] >= 1
    assert integrity["served_counts"]["guardian_records"] >= 1


def test_phase6_cycle_bundle_flags_latest_state_fallback(monkeypatch, tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    monkeypatch.setattr(
        protocol_observer,
        "observe_endpoint_series",
        lambda endpoint, samples, **kwargs: _FakeSeries(observations=[_observation(endpoint)], elapsed_ms=10),
    )
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    result = _orchestrator(storage).run_cycle("tenant_a")
    tenant_path = storage.get_tenant_path("tenant_a")
    (tenant_path / "layer3_state" / f"{result.metadata.cycle_id}.json").unlink()

    runtime = EngineRuntime(storage=storage)
    adapter = RuntimeReadAdapter(runtime)
    scope = AuthorizedTenantScope.from_iterable("operator_a", ["tenant_a"])
    payload = adapter.cycle_bundle(
        "tenant_a",
        result.metadata.cycle_id,
        authz_scope=scope,
    )

    integrity = payload["integrity_summary"]
    assert integrity["exact_cycle_replayable"] is False
    assert integrity["served_view_complete"] is True
    assert integrity["fallbacks_used"]["layer3_state_latest"] is True
    assert any("fallback" in warning for warning in integrity["warnings"])
