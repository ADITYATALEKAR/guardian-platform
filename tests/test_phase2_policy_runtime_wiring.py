from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

import pytest

import layers.layer0_observation.acquisition.protocol_observer as protocol_observer
from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.discovery.expansion_wrapper import ExpansionResult
from infrastructure.policy_integration.enforcement import PolicyRuntimeBridge
from infrastructure.policy_integration.policies.updates import (
    PolicyUpdateApprovalStore,
    PolicyUpdatePlan,
    PolicyUpdatePlanStore,
)
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


class _FakeSocket:
    def getsockname(self):
        return ("127.0.0.1", 44321)

    def close(self):
        return None


class _StubExpansionWrapper:
    def expand(self, root_domain: str, config, stage_callback=None) -> ExpansionResult:
        return ExpansionResult(
            root_domain=root_domain,
            endpoint_candidates=set(),
            node_count=1,
            edge_count=0,
            ceilings_hit=False,
            diagnostics={},
        )


class _ProgressEmittingExpansionWrapper:
    def expand(
        self,
        root_domain: str,
        config,
        stage_callback=None,
        progress_callback=None,
    ) -> ExpansionResult:
        if callable(progress_callback):
            progress_callback(
                {
                    "expansion_active_category": "A",
                    "expansion_current_module": "SyntheticModule",
                    "expansion_modules_completed_count": 1,
                    "expansion_module_total_count": 1,
                    "expansion_node_count": 3,
                    "expansion_edge_count": 2,
                    "expansion_graph_endpoint_count": 1,
                }
            )
        return ExpansionResult(
            root_domain=root_domain,
            endpoint_candidates={"pay.example.com:443"},
            node_count=3,
            edge_count=2,
            ceilings_hit=False,
            diagnostics={},
        )


def _new_storage(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    return storage


def _seed_plan(storage: StorageManager, *, tenant_id: str = "tenant_a") -> str:
    plan_store = PolicyUpdatePlanStore(storage_manager=storage, tenant_id=tenant_id)
    approvals = PolicyUpdateApprovalStore(storage_manager=storage, tenant_id=tenant_id)

    plan = PolicyUpdatePlan(
        plan_id="plan_phase2_tls_1",
        tenant_id=tenant_id,
        jurisdiction_id="GLOBAL",
        source_pack_id="pack_core",
        source_id="src_tls",
        source_url="https://example.com/policy",
        old_fingerprint="old",
        new_fingerprint="new",
        effective_date_utc="2026-03-01",
        summary="TLS enforcement",
        created_ts_ms=1_710_000_000_000,
        raw_metadata={
            "framework": "PCI_DSS",
            "policy_name": "TLS minimum",
            "requirement_text": "Disallow deprecated transport profile",
            "violation_risk": "HIGH",
            "pattern_labels": "TLS_DOWNGRADE,WEAK_CIPHER",
        },
    )
    plan_store.upsert_plan(plan)
    approvals.schedule_activation(
        plan.plan_id,
        activation_ts_ms=1_710_000_000_100,
        effective_date_utc=plan.effective_date_utc,
        ts_ms=1_710_000_000_050,
    )
    return plan.plan_id


def _legacy_tls_observation(endpoint: str) -> RawObservation:
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
            cert_san=["pay.example.com"],
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
            headers={"server": "cloudflare"},
        ),
        success=True,
    )


def test_phase2_policy_runtime_bridge_applies_and_evaluates(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    plan_id = _seed_plan(storage)
    bridge = PolicyRuntimeBridge(storage_manager=storage, tenant_id="tenant_a")

    sync = bridge.sync_runtime_policies(now_ts_ms=1_710_000_001_000)
    assert plan_id in sync["due_activations"]
    assert plan_id in sync["applied_activations"]
    assert bridge.has_active_policies() is True

    evaluated = bridge.evaluate_patterns(pattern_labels=["TLS_DOWNGRADE"])
    assert evaluated["violation_count"] >= 1
    assert any(str(row.get("policy_id", "")).startswith("upd_") for row in evaluated["findings"])


def test_phase2_policy_runtime_bridge_fail_loud_on_corrupt_activation_request(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    tenant_root = storage.get_tenant_path("tenant_a")
    request_dir = tenant_root / "policy_integration" / "updates" / "activation_requests"
    request_dir.mkdir(parents=True, exist_ok=True)
    (request_dir / "bad.json").write_text("{bad-json", encoding="utf-8")

    bridge = PolicyRuntimeBridge(storage_manager=storage, tenant_id="tenant_a")
    with pytest.raises(RuntimeError, match="corrupt policy activation request"):
        bridge.apply_pending_activation_requests(now_ts_ms=1_710_000_001_000)


def test_phase2_orchestrator_persists_policy_runtime_artifacts(monkeypatch, tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    _seed_plan(storage)
    storage.save_seed_endpoints("tenant_a", ["pay.example.com:443"])

    engine = DiscoveryEngine(
        storage=storage,
        max_workers=2,
        max_endpoints=2,
        expansion_wrapper=_StubExpansionWrapper(),
        enable_phase5_findings=False,
    )

    def _fake_observe(endpoint: str, samples: int, **kwargs) -> _FakeSeries:
        return _FakeSeries(observations=[_legacy_tls_observation(endpoint)], elapsed_ms=12)

    monkeypatch.setattr(protocol_observer, "observe_endpoint_series", _fake_observe)
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    orchestrator = UnifiedCycleOrchestrator(
        storage=storage,
        discovery_engine=engine,
        snapshot_builder=SnapshotBuilder(),
        temporal_engine=TemporalStateEngine(),
    )
    result = orchestrator.run_cycle("tenant_a")

    cycle_meta_rows = storage.load_cycle_metadata("tenant_a")
    completed_rows = [row for row in cycle_meta_rows if row.get("cycle_id") == result.metadata.cycle_id]
    assert completed_rows
    latest = completed_rows[-1]
    assert latest.get("policy_enforcement_enabled") is True
    assert isinstance(latest.get("policy_runtime_sync"), dict)

    guardian_rows = storage.load_guardian_records_for_cycle("tenant_a", result.metadata.cycle_id)
    assert guardian_rows
    assert all(row.get("policy_enforcement_mode") == "enabled" for row in guardian_rows)
    assert all(isinstance(row.get("policy_evaluation"), dict) for row in guardian_rows)


def test_phase2_orchestrator_uses_a_bcde_on_first_cycle(monkeypatch, tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    storage.save_seed_endpoints("tenant_a", ["pay.example.com:443"])

    engine = DiscoveryEngine(
        storage=storage,
        max_workers=2,
        max_endpoints=2,
        expansion_wrapper=_StubExpansionWrapper(),
        enable_phase5_findings=False,
    )

    captured: dict[str, str] = {}
    original_run_discovery = engine.run_discovery

    def _capture_run_discovery(*args, **kwargs):
        captured["expansion_mode"] = str(kwargs.get("expansion_mode"))
        return original_run_discovery(*args, **kwargs)

    def _fake_observe(endpoint: str, samples: int, **kwargs) -> _FakeSeries:
        return _FakeSeries(observations=[_legacy_tls_observation(endpoint)], elapsed_ms=12)

    monkeypatch.setattr(engine, "run_discovery", _capture_run_discovery)
    monkeypatch.setattr(protocol_observer, "observe_endpoint_series", _fake_observe)
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    orchestrator = UnifiedCycleOrchestrator(
        storage=storage,
        discovery_engine=engine,
        snapshot_builder=SnapshotBuilder(),
        temporal_engine=TemporalStateEngine(),
    )

    orchestrator.run_cycle("tenant_a")

    assert captured["expansion_mode"] == "A_BCDE"


def test_phase2_orchestrator_enables_ct_longitudinal_from_cycle_two(
    monkeypatch,
    tmp_path: Path,
) -> None:
    storage = _new_storage(tmp_path)
    storage.save_seed_endpoints("tenant_a", ["pay.example.com:443"])

    engine = DiscoveryEngine(
        storage=storage,
        max_workers=2,
        max_endpoints=2,
        expansion_wrapper=_StubExpansionWrapper(),
        enable_phase5_findings=False,
    )

    captured: list[bool | None] = []
    original_run_discovery = engine.run_discovery

    def _capture_run_discovery(*args, **kwargs):
        captured.append(kwargs.get("enable_ct_longitudinal"))
        return original_run_discovery(*args, **kwargs)

    def _fake_observe(endpoint: str, samples: int, **kwargs) -> _FakeSeries:
        return _FakeSeries(observations=[_legacy_tls_observation(endpoint)], elapsed_ms=12)

    monkeypatch.setattr(storage, "load_latest_snapshot", lambda tenant_id: None)
    monkeypatch.setattr(storage, "load_temporal_state", lambda tenant_id: None)
    monkeypatch.setattr(engine, "run_discovery", _capture_run_discovery)
    monkeypatch.setattr(protocol_observer, "observe_endpoint_series", _fake_observe)
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    orchestrator = UnifiedCycleOrchestrator(
        storage=storage,
        discovery_engine=engine,
        snapshot_builder=SnapshotBuilder(),
        temporal_engine=TemporalStateEngine(),
    )

    orchestrator.run_cycle("tenant_a")
    orchestrator.run_cycle("tenant_a")

    assert captured == [False, True]


def test_phase2_orchestrator_accepts_progress_payload_mapping(
    monkeypatch,
    tmp_path: Path,
) -> None:
    storage = _new_storage(tmp_path)
    storage.save_seed_endpoints("tenant_a", ["pay.example.com:443"])

    engine = DiscoveryEngine(
        storage=storage,
        max_workers=2,
        max_endpoints=2,
        expansion_wrapper=_StubExpansionWrapper(),
        enable_phase5_findings=False,
    )

    original_run_discovery = engine.run_discovery

    def _capture_run_discovery(*args, **kwargs):
        progress_callback = kwargs.get("progress_callback")
        if callable(progress_callback):
            progress_callback({"seed_endpoint_count": 1, "root_scope_count": 1})
        return original_run_discovery(*args, **kwargs)

    def _fake_observe(endpoint: str, samples: int, **kwargs) -> _FakeSeries:
        return _FakeSeries(observations=[_legacy_tls_observation(endpoint)], elapsed_ms=12)

    monkeypatch.setattr(engine, "run_discovery", _capture_run_discovery)
    monkeypatch.setattr(protocol_observer, "observe_endpoint_series", _fake_observe)
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    orchestrator = UnifiedCycleOrchestrator(
        storage=storage,
        discovery_engine=engine,
        snapshot_builder=SnapshotBuilder(),
        temporal_engine=TemporalStateEngine(),
    )

    orchestrator.run_cycle("tenant_a")

    lock = storage.load_cycle_lock("tenant_a")
    assert lock is None
    rows = storage.load_cycle_metadata("tenant_a")
    completed = [row for row in rows if row.get("status") == "completed"]
    assert completed


def test_phase2_discovery_engine_accepts_mapping_progress_payloads(
    monkeypatch,
    tmp_path: Path,
) -> None:
    storage = _new_storage(tmp_path)
    storage.save_seed_endpoints("tenant_a", ["pay.example.com:443"])

    engine = DiscoveryEngine(
        storage=storage,
        max_workers=1,
        max_endpoints=2,
        expansion_wrapper=_ProgressEmittingExpansionWrapper(),
        enable_phase5_findings=False,
    )

    def _fake_observe(endpoint: str, samples: int, **kwargs) -> _FakeSeries:
        return _FakeSeries(observations=[_legacy_tls_observation(endpoint)], elapsed_ms=12)

    monkeypatch.setattr(protocol_observer, "observe_endpoint_series", _fake_observe)
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    captured_updates: list[dict[str, object]] = []
    engine.run_discovery(
        tenant_id="tenant_a",
        rate_controller=object(),
        cycle_id="cycle_000001",
        progress_callback=lambda payload: captured_updates.append(dict(payload)),
    )

    assert any(update.get("expansion_current_module") == "SyntheticModule" for update in captured_updates)
    assert any(update.get("expanded_candidate_count") == 1 for update in captured_updates)


def test_phase2_observe_endpoint_marks_plain_http_contact_as_success(monkeypatch) -> None:
    monkeypatch.setattr(
        protocol_observer,
        "observe_dns",
        lambda hostname, timeout=0: DNSObservation(
            resolved_ip="203.0.113.10",
            resolution_time_ms=1.0,
        ),
    )
    monkeypatch.setattr(
        protocol_observer,
        "observe_tcp",
        lambda ip, port, timeout=0: (
            TCPObservation(connected=True, connect_time_ms=2.0),
            _FakeSocket(),
        ),
    )
    monkeypatch.setattr(
        protocol_observer,
        "observe_http_head",
        lambda hostname, port, timeout=0, request_headers=None: HTTPObservation(
            status_code=200,
            response_time_ms=3.0,
            headers={"server": "test"},
        ),
    )

    def _unexpected_tls(*args, **kwargs):
        raise AssertionError("TLS should not be attempted for port 80")

    monkeypatch.setattr(protocol_observer, "observe_tls", _unexpected_tls)

    obs = protocol_observer.observe_endpoint("example.com:80", include_http=True, timeout=1.0)

    assert obs.success is True
    assert obs.error in (None, "")
    assert obs.attempt_protocols == ["dns", "tcp", "http_head"]
    assert obs.http is not None
    assert obs.http.status_code == 200


def test_phase2_snapshot_builder_preserves_tcp_contact_when_tls_fails(monkeypatch) -> None:
    monkeypatch.setattr(
        protocol_observer,
        "observe_dns",
        lambda hostname, timeout=0: DNSObservation(
            resolved_ip="203.0.113.20",
            resolution_time_ms=1.0,
        ),
    )
    monkeypatch.setattr(
        protocol_observer,
        "observe_tcp",
        lambda ip, port, timeout=0: (
            TCPObservation(connected=True, connect_time_ms=2.0),
            _FakeSocket(),
        ),
    )
    monkeypatch.setattr(
        protocol_observer,
        "observe_tls",
        lambda sock, hostname, timeout=0: TLSObservation(error="TLS alert"),
    )

    obs = protocol_observer.observe_endpoint("example.com:443", include_http=False, timeout=1.0)
    assert obs.success is True
    assert obs.error == "TLS alert"

    converted = SnapshotBuilder()._convert_protocol_raw_to_snapshot_raw(obs)
    assert converted.confidence == pytest.approx(0.6)
    assert converted.tls_handshake_success is False
    assert converted.ports_open == [443]
