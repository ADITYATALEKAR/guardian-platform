from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import List

import pytest

import layers.layer0_observation.acquisition.protocol_observer as protocol_observer
import infrastructure.operator_plane.services.operator_service as operator_service_module
from infrastructure.aggregation.authz_contract import AuthorizedTenantScope
from infrastructure.aggregation.global_identity import endpoint_gid
from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.discovery.expansion_wrapper import ExpansionResult
from infrastructure.operator_plane.registry.operator_registry import get_operator
from infrastructure.operator_plane.registry.operator_tenant_links import list_tenants
from infrastructure.operator_plane.services.operator_service import OperatorService
from infrastructure.operator_plane.sessions.session_manager import create_session, validate_session
from infrastructure.runtime.engine_runtime import EngineRuntime
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
    elapsed_ms: int = 8


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


def _obs(endpoint: str) -> RawObservation:
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


def _orchestrator(storage: StorageManager) -> UnifiedCycleOrchestrator:
    engine = DiscoveryEngine(
        storage=storage,
        max_workers=2,
        max_endpoints=2,
        expansion_wrapper=_StubExpansionWrapper(),
        enable_phase5_findings=True,
        enable_ct_longitudinal=False,
    )
    return UnifiedCycleOrchestrator(
        storage=storage,
        discovery_engine=engine,
        snapshot_builder=SnapshotBuilder(),
        temporal_engine=TemporalStateEngine(),
    )


def test_deep_wiring_dataflow_two_tenants_identity_isolation(monkeypatch, tmp_path: Path) -> None:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    storage.create_tenant("tenant_b")
    storage.save_seed_endpoints("tenant_a", ["pay.example.com:443"])
    storage.save_seed_endpoints("tenant_b", ["pay.example.com:443"])

    def _fake_observe(endpoint: str, samples: int, **kwargs) -> _FakeSeries:
        return _FakeSeries(observations=[_obs(endpoint)], elapsed_ms=8)

    monkeypatch.setattr(protocol_observer, "observe_endpoint_series", _fake_observe)
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    orchestrator = _orchestrator(storage)
    result_a = orchestrator.run_cycle("tenant_a")
    result_b = orchestrator.run_cycle("tenant_b")

    runtime = EngineRuntime(storage=storage)
    scope_a = AuthorizedTenantScope.from_iterable("operator_a", ["tenant_a"])
    scope_b = AuthorizedTenantScope.from_iterable("operator_b", ["tenant_b"])

    dash_a = runtime.build_dashboard("tenant_a", authz_scope=scope_a)
    dash_b = runtime.build_dashboard("tenant_b", authz_scope=scope_b)
    bundle_a = runtime.build_cycle_artifact_bundle(
        "tenant_a",
        authz_scope=scope_a,
        cycle_id=result_a.metadata.cycle_id,
    )
    bundle_b = runtime.build_cycle_artifact_bundle(
        "tenant_b",
        authz_scope=scope_b,
        cycle_id=result_b.metadata.cycle_id,
    )

    # Identity and tenant isolation in dashboard and bundle
    assert dash_a["tenant_id"] == "tenant_a"
    assert dash_b["tenant_id"] == "tenant_b"
    assert bundle_a["tenant_id"] == "tenant_a"
    assert bundle_b["tenant_id"] == "tenant_b"
    assert bundle_a["cycle_id"] == result_a.metadata.cycle_id
    assert bundle_b["cycle_id"] == result_b.metadata.cycle_id

    a_by_host = {row["hostname"]: row for row in dash_a["endpoints"]}
    b_by_host = {row["hostname"]: row for row in dash_b["endpoints"]}
    assert "pay.example.com" in a_by_host
    assert "pay.example.com" in b_by_host
    gid_a = a_by_host["pay.example.com"]["endpoint_gid"]
    gid_b = b_by_host["pay.example.com"]["endpoint_gid"]
    assert gid_a == endpoint_gid("tenant_a", "pay.example.com", 443)
    assert gid_b == endpoint_gid("tenant_b", "pay.example.com", 443)
    assert gid_a != gid_b

    # All main cycle artifacts exist and include rich runtime outputs
    completed_a = [
        row for row in bundle_a["cycle_metadata"] if str(row.get("status", "")).lower() == "completed"
    ][0]
    assert isinstance(completed_a.get("build_stats"), dict)
    assert isinstance(completed_a.get("diff"), dict)
    assert isinstance(completed_a.get("rate_controller_stats"), dict)

    # Telemetry and guardian records carry identity overlays
    assert bundle_a["telemetry"]
    assert all("endpoint_gid" in row for row in bundle_a["telemetry"])
    assert all("posture_signals" in row for row in bundle_a["telemetry"])
    assert all("posture_findings" in row for row in bundle_a["telemetry"])
    assert bundle_a["guardian_records"]
    assert all("endpoint_gid" in row for row in bundle_a["guardian_records"])

    # Cross-tenant authz must reject access
    with pytest.raises(RuntimeError, match="unauthorized tenant access"):
        runtime.build_cycle_artifact_bundle("tenant_b", authz_scope=scope_a)


def test_deep_operator_tenant_creation_wiring_and_storage_isolation(tmp_path: Path) -> None:
    storage = StorageManager(str(tmp_path / "storage_root"))
    identity = IdentityManager(storage)
    operator_root = str(tmp_path / "operator_storage")
    simulation_root = str(tmp_path / "simulation_storage")
    called = []

    class _FakeOrchestrator:
        def run_cycle(self, tenant_id: str):
            called.append(tenant_id)
            return {"ok": True}

    os.environ["OPERATOR_MASTER_PASSWORD"] = "master-secret"
    service = OperatorService(
        operator_storage_root=operator_root,
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
        main_url="https://pay.example.com",
        seed_endpoints=[],
        password="TenantPassword123!",
    )
    tenant_id = out["tenant_id"]

    assert out["cycle_started"] is True
    assert called == [tenant_id]
    assert storage.tenant_exists(tenant_id)
    assert (Path(simulation_root) / "tenants" / tenant_id).exists()
    assert (Path(operator_root) / "meta.json").exists()
    assert tenant_id in list_tenants(operator_root, "op_a")


def test_deep_operator_delete_rolls_back_on_final_step_failure(tmp_path: Path, monkeypatch) -> None:
    storage = StorageManager(str(tmp_path / "storage_root"))
    identity = IdentityManager(storage)
    operator_root = str(tmp_path / "operator_storage")
    simulation_root = str(tmp_path / "simulation_storage")

    class _FakeOrchestrator:
        def run_cycle(self, tenant_id: str):
            return {"ok": True}

    os.environ["OPERATOR_MASTER_PASSWORD"] = "master-secret"
    service = OperatorService(
        operator_storage_root=operator_root,
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
    tenant_id = service.register_tenant(
        operator_id="op_a",
        institution_name="Example Bank",
        main_url="https://pay.example.com",
        seed_endpoints=[],
        password="TenantPassword123!",
    )["tenant_id"]

    session = create_session(operator_root, "op_a")
    assert validate_session(operator_root, session.token) == "op_a"

    def _raise_delete(root: str, operator_id: str) -> None:
        raise RuntimeError("forced final-step failure")

    monkeypatch.setattr(operator_service_module, "delete_operator_record_only", _raise_delete)

    with pytest.raises(RuntimeError, match="operator deletion failed"):
        service.delete_operator("op_a")

    # Operator + links + sessions restored after rollback
    assert get_operator(operator_root, "op_a")["operator_id"] == "op_a"
    assert tenant_id in list_tenants(operator_root, "op_a")
    assert validate_session(operator_root, session.token) == "op_a"
