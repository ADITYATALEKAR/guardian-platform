from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

import layers.layer0_observation.acquisition.protocol_observer as protocol_observer

from infrastructure.aggregation.authz_contract import AuthorizedTenantScope
from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.discovery.expansion_wrapper import ExpansionResult
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
    elapsed_ms: int = 12


class _StubExpansionWrapper:
    def expand(self, root_domain: str, config) -> ExpansionResult:
        return ExpansionResult(
            root_domain=root_domain,
            endpoint_candidates=set(),
            node_count=1,
            edge_count=0,
            ceilings_hit=False,
            diagnostics={},
        )


def _observation_for(endpoint: str) -> RawObservation:
    return RawObservation(
        endpoint=endpoint,
        entity_id=endpoint,
        observation_id=f"obs_{endpoint.replace(':', '_')}",
        timestamp_ms=1_710_000_000_123,
        dns=DNSObservation(resolved_ip="1.1.1.1", resolution_time_ms=10.0),
        tcp=TCPObservation(connected=True, connect_time_ms=8.5),
        tls=TLSObservation(
            handshake_time_ms=22.0,
            tls_version="TLSv1.2",
            cipher_suite="RSA-AES256-GCM-SHA384",
            cert_subject="commonName=pay.example.com",
            cert_issuer="commonName=Demo CA",
            cert_not_before="Jan  1 00:00:00 2026 GMT",
            cert_not_after="Jan  1 00:00:00 2027 GMT",
            cert_san=["pay.example.com", "api.example.com"],
            cert_public_key_algorithm="RSA",
            cert_public_key_size_bits=2048,
            cert_must_staple=False,
            cert_ocsp_urls=[],
            alpn_protocol="h2",
            sni_mismatch=False,
            ocsp_stapled=False,
        ),
        http=HTTPObservation(
            status_code=403,
            response_time_ms=30.0,
            headers={
                "server": "cloudflare",
                "cf-ray": "xyz123",
                "strict-transport-security": "max-age=300",
            },
        ),
        success=True,
    )


def _new_storage(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    storage.save_seed_endpoints("tenant_a", ["pay.example.com:443"])
    return storage


def test_phase5_cycle_metadata_persists_existing_runtime_outputs(monkeypatch, tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    engine = DiscoveryEngine(
        storage=storage,
        max_workers=2,
        max_endpoints=2,
        expansion_wrapper=_StubExpansionWrapper(),
        enable_phase5_findings=True,
        enable_ct_longitudinal=False,
    )

    def _fake_observe(endpoint: str, samples: int, **kwargs) -> _FakeSeries:
        return _FakeSeries(observations=[_observation_for(endpoint)], elapsed_ms=12)

    monkeypatch.setattr(protocol_observer, "observe_endpoint_series", _fake_observe)
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    orchestrator = UnifiedCycleOrchestrator(
        storage=storage,
        discovery_engine=engine,
        snapshot_builder=SnapshotBuilder(),
        temporal_engine=TemporalStateEngine(),
    )
    result = orchestrator.run_cycle("tenant_a")

    metadata_rows = storage.load_cycle_metadata("tenant_a")
    completed_rows = [
        row
        for row in metadata_rows
        if str(row.get("cycle_id", "")).strip() == result.metadata.cycle_id
        and str(row.get("status", "")).strip().lower() == "completed"
    ]
    assert len(completed_rows) == 1
    completed = completed_rows[0]

    assert isinstance(completed.get("build_stats"), dict)
    assert isinstance(completed.get("diff"), dict)
    assert isinstance(completed.get("rate_controller_stats"), dict)

    build_stats = completed["build_stats"]
    assert "total_discovered_domains" in build_stats
    assert "total_successful_observations" in build_stats
    assert "total_failed_observations" in build_stats
    assert "posture_summary" in build_stats

    diff = completed["diff"]
    assert "new_endpoints" in diff
    assert "removed_endpoints" in diff
    assert "changed_endpoints" in diff
    assert "unchanged_endpoints" in diff


def test_phase5_cycle_bundle_surfaces_persisted_runtime_outputs(monkeypatch, tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    engine = DiscoveryEngine(
        storage=storage,
        max_workers=2,
        max_endpoints=2,
        expansion_wrapper=_StubExpansionWrapper(),
        enable_phase5_findings=True,
        enable_ct_longitudinal=False,
    )

    def _fake_observe(endpoint: str, samples: int, **kwargs) -> _FakeSeries:
        return _FakeSeries(observations=[_observation_for(endpoint)], elapsed_ms=12)

    monkeypatch.setattr(protocol_observer, "observe_endpoint_series", _fake_observe)
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    orchestrator = UnifiedCycleOrchestrator(
        storage=storage,
        discovery_engine=engine,
        snapshot_builder=SnapshotBuilder(),
        temporal_engine=TemporalStateEngine(),
    )
    result = orchestrator.run_cycle("tenant_a")

    runtime = EngineRuntime(storage=storage)
    scope = AuthorizedTenantScope.from_iterable("operator_a", ["tenant_a"])
    bundle = runtime.build_cycle_artifact_bundle(
        "tenant_a",
        authz_scope=scope,
        cycle_id=result.metadata.cycle_id,
    )

    completed_rows = [
        row
        for row in bundle["cycle_metadata"]
        if str(row.get("status", "")).strip().lower() == "completed"
    ]
    assert len(completed_rows) == 1
    completed = completed_rows[0]

    assert isinstance(completed.get("build_stats"), dict)
    assert isinstance(completed.get("diff"), dict)
    assert isinstance(completed.get("rate_controller_stats"), dict)
