from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

import pytest

import layers.layer0_observation.acquisition.protocol_observer as protocol_observer
from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.discovery.expansion_wrapper import ExpansionResult
from infrastructure.operator_plane.services.operator_service import OperatorService
from infrastructure.policy_integration.compliance import resolve_tenant_frameworks
from infrastructure.policy_integration.policies import PolicyStore
from infrastructure.storage_manager.identity_manager import IdentityManager
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
    return storage


def test_phase8_static_wiring_uses_canonical_policy_integration_only() -> None:
    targets = [
        Path("infrastructure/discovery/discovery_engine.py"),
        Path("infrastructure/posture/finding_engine.py"),
        Path("infrastructure/operator_plane/services/operator_service.py"),
        Path("infrastructure/unified_discovery_v2/unified_cycle_orchestrator.py"),
    ]
    for path in targets:
        source = path.read_text(encoding="utf-8")
        assert "from integration." not in source
        assert "import integration." not in source
        assert "infrastructure.policy_integration" in source or path.name in {
            "operator_service.py",
            "unified_cycle_orchestrator.py",
        }


def test_phase8_operator_to_runtime_boundary_calls_lifecycle_and_orchestrator(tmp_path: Path) -> None:
    storage = StorageManager(str(tmp_path / "runtime_root"))
    identity = IdentityManager(storage)
    operator_storage_root = str(tmp_path / "operator_root")
    simulation_root = str(tmp_path / "simulation_root")
    called: List[str] = []

    class _FakeOrchestrator:
        def run_cycle(self, tenant_id: str):
            called.append(tenant_id)
            return {"ok": True}

    os.environ["OPERATOR_MASTER_PASSWORD"] = "master-secret"
    service = OperatorService(
        operator_storage_root=operator_storage_root,
        storage_manager=storage,
        identity_manager=identity,
        simulation_root=simulation_root,
        orchestrator=_FakeOrchestrator(),
    )

    service.register_operator(
        operator_id="op_a",
        email="op@example.com",
        password="StrongPassword123!",
        created_at_unix_ms=1_710_000_000_000,
        master_password="master-secret",
    )
    out = service.register_tenant(
        operator_id="op_a",
        institution_name="Example Bank",
        main_url="https://api.example.com",
        seed_endpoints=[],
        password="TenantPassword123!",
    )

    assert out.get("cycle_started") is True
    tenant_id = str(out.get("tenant_id"))
    assert tenant_id
    assert called == [tenant_id]
    assert storage.tenant_exists(tenant_id)


def test_phase8_orchestrator_wiring_persists_cycle_artifacts_and_posture(tmp_path: Path, monkeypatch) -> None:
    storage = _new_storage(tmp_path)
    storage.save_seed_endpoints("tenant_a", ["pay.example.com:443"])
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

    # Final artifacts exist and are readable via canonical storage APIs
    assert storage.load_latest_snapshot("tenant_a") is not None
    assert storage.load_temporal_state("tenant_a") is not None
    assert storage.load_graph_snapshot("tenant_a") is not None
    assert storage.load_layer3_snapshot("tenant_a") is not None
    assert storage.load_latest_guardian_records("tenant_a")
    telemetry = storage.load_telemetry_for_cycle("tenant_a", result.metadata.cycle_id)
    assert telemetry
    assert all("posture_signals" in record for record in telemetry)
    assert all("posture_findings" in record for record in telemetry)

    records = storage.load_cycle_metadata("tenant_a")
    statuses = [str(r.get("status", "")) for r in records if r.get("cycle_id") == result.metadata.cycle_id]
    assert "running" in statuses
    assert "completed" in statuses
    assert "failed" not in statuses

    posture_summary = result.build_stats.posture_summary
    assert posture_summary.get("waf_findings_count", 0) >= 1
    assert posture_summary.get("tls_findings_count", 0) >= 1
    assert "avg_cryptographic_health_score" in posture_summary
    assert "avg_protection_posture_score" in posture_summary


def test_phase8_policy_aware_compliance_mapping_uses_canonical_policy_store(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    store = PolicyStore(storage_manager=storage, tenant_id="tenant_a")
    store.save_approved_policy(
        {
            "policy_id": "approved_rbi_1",
            "title": "RBI Transport Policy",
            "jurisdiction": "INDIA",
            "tags": ["rbi", "transport", "tls"],
        }
    )

    frameworks = resolve_tenant_frameworks(storage, "tenant_a")
    assert frameworks == ["RBI"]
