from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List

import layers.layer0_observation.acquisition.protocol_observer as protocol_observer

import infrastructure.storage_manager.storage_manager as storage_manager_module
from infrastructure.aggregation.authz_contract import AuthorizedTenantScope
from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.discovery.expansion_wrapper import ExpansionResult
from infrastructure.runtime.engine_runtime import EngineRuntime
from infrastructure.runtime.tenant_lifecycle_manager import TenantLifecycleManager
from infrastructure.storage_manager.identity_manager import IdentityManager
from infrastructure.storage_manager.storage_manager import StorageManager
from infrastructure.unified_discovery_v2.snapshot_builder import SnapshotBuilder
from infrastructure.unified_discovery_v2.temporal_state_engine import TemporalStateEngine
from infrastructure.unified_discovery_v2.unified_cycle_orchestrator import (
    UnifiedCycleOrchestrator,
)
from layers.layer0_observation.acquisition.observation_bridge import ObservationBridge
from layers.layer0_observation.acquisition.protocol_observer import (
    DNSObservation,
    HTTPObservation,
    RawObservation,
    TCPObservation,
    TLSObservation,
)
from layers.layer0_observation.acquisition.cycle_scheduler import CycleScheduler


@dataclass
class _FakeSeries:
    observations: List[RawObservation]
    elapsed_ms: int = 12


class _DiagnosticsExpansionWrapper:
    def expand(
        self,
        root_domain: str,
        config,
        stage_callback=None,
        progress_callback=None,
    ) -> ExpansionResult:
        if callable(stage_callback):
            stage_callback("category_a_exploration")
        if callable(progress_callback):
            progress_callback(
                {
                    "expansion_active_category": "BCDE",
                    "expansion_current_module": "CommonPortScanModule",
                    "expansion_modules_completed_count": 1,
                    "expansion_module_total_count": 2,
                    "expansion_node_count": 4,
                    "expansion_edge_count": 5,
                    "expansion_graph_endpoint_count": 1,
                }
            )
        return ExpansionResult(
            root_domain=root_domain,
            endpoint_candidates={f"api.{root_domain}:443"},
            node_count=4,
            edge_count=5,
            ceilings_hit=False,
            diagnostics={
                "t_total_s": 1.2,
                "raw_candidate_count": 1,
                "canonical_candidate_count": 1,
                "timing": {
                    "a_exploration_s": 0.3,
                    "bcde_exploration_s": 0.3,
                    "a_exploitation_s": 0.3,
                    "bcde_exploitation_s": 0.3,
                },
                "productive_category_a_modules": ["CertificateTransparencyModule"],
                "productive_bcde_modules": ["CommonPortScanModule"],
                "module_timings": {
                    "CertificateTransparencyModule": 0.3,
                    "CommonPortScanModule": 0.3,
                },
                "module_summaries": [
                    {
                        "category": "A",
                        "module_name": "CertificateTransparencyModule",
                        "elapsed_s": 0.3,
                        "new_domain_count": 1,
                        "new_endpoint_count": 0,
                        "new_candidate_count": 1,
                        "productive": True,
                    },
                    {
                        "category": "BCDE",
                        "module_name": "CommonPortScanModule",
                        "elapsed_s": 0.3,
                        "new_domain_count": 0,
                        "new_endpoint_count": 1,
                        "new_candidate_count": 1,
                        "productive": True,
                    },
                ],
            },
        )


@dataclass
class _FakeScheduledOperatorService:
    launches: list[str] = field(default_factory=list)

    def start_scheduled_cycle(self, *, tenant_id: str):
        self.launches.append(str(tenant_id))
        return {
            "tenant_id": tenant_id,
            "cycle_id": "cycle_000002",
            "cycle_number": 2,
        }


def _new_storage(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    storage.save_seed_endpoints("tenant_a", ["pay.example.com:443"])
    return storage


def _observation_for(endpoint: str) -> RawObservation:
    return RawObservation(
        endpoint=endpoint,
        entity_id=endpoint,
        observation_id=f"obs::{endpoint}",
        timestamp_ms=int(time.time() * 1000),
        dns=DNSObservation(resolved_ip="203.0.113.10"),
        tcp=TCPObservation(success=True, rtt_ms=11.0),
        tls=TLSObservation(
            success=True,
            handshake_time_ms=22.0,
            tls_version="TLSv1.3",
            cert_subject="CN=example.com",
            cert_issuer="CN=Unit Test CA",
            cert_valid_from="2026-01-01T00:00:00Z",
            cert_valid_to="2027-01-01T00:00:00Z",
            cert_san=["api.example.com"],
        ),
        http=HTTPObservation(
            status_code=200,
            title="Unit Test",
            server="unit",
        ),
        success=True,
    )


def _orchestrator(storage: StorageManager) -> UnifiedCycleOrchestrator:
    engine = DiscoveryEngine(
        storage=storage,
        max_workers=2,
        max_endpoints=10,
        expansion_wrapper=_DiagnosticsExpansionWrapper(),
        enable_phase5_findings=False,
    )
    return UnifiedCycleOrchestrator(
        storage=storage,
        discovery_engine=engine,
        snapshot_builder=SnapshotBuilder(),
        temporal_engine=TemporalStateEngine(),
    )


def _build_lifecycle(tmp_path: Path) -> TenantLifecycleManager:
    storage = StorageManager(str(tmp_path / "storage"))
    identity = IdentityManager(storage)
    return TenantLifecycleManager(
        storage=storage,
        identity=identity,
        simulation_root=str(tmp_path / "simulation"),
    )


def test_phase12_cycle_lock_writer_falls_back_when_replace_is_denied(
    monkeypatch,
    tmp_path: Path,
) -> None:
    storage = _new_storage(tmp_path)
    storage.acquire_cycle_lock("tenant_a", "cycle_000001", 1)

    real_replace = storage_manager_module.os.replace

    def _deny_cycle_lock_replace(src, dst):
        if str(dst).endswith(".cycle.lock"):
            raise PermissionError("[WinError 5] Access is denied")
        return real_replace(src, dst)

    monkeypatch.setattr(storage_manager_module.os, "replace", _deny_cycle_lock_replace)

    storage.update_cycle_lock("tenant_a", {"stage": "discovery", "marker": 7})

    lock = storage.load_cycle_lock("tenant_a")
    assert isinstance(lock, dict)
    assert lock["stage"] == "discovery"
    assert lock["marker"] == 7


def test_phase12_release_cycle_lock_permission_error_is_non_fatal(
    monkeypatch,
    tmp_path: Path,
) -> None:
    storage = _new_storage(tmp_path)
    storage.acquire_cycle_lock("tenant_a", "cycle_000001", 1)

    real_unlink = Path.unlink

    def _deny_cycle_lock_unlink(self: Path, *args, **kwargs):
        if self.name == ".cycle.lock":
            raise PermissionError("[WinError 32] The process cannot access the file")
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", _deny_cycle_lock_unlink)

    storage.release_cycle_lock("tenant_a")

    assert storage.load_cycle_lock("tenant_a") is None


def test_phase12_orchestrator_completes_when_progress_lock_writes_fail(
    monkeypatch,
    tmp_path: Path,
) -> None:
    storage = _new_storage(tmp_path)
    monkeypatch.setattr(
        protocol_observer,
        "observe_endpoint_series",
        lambda endpoint, samples, **kwargs: _FakeSeries(
            observations=[_observation_for(endpoint)],
            elapsed_ms=12,
        ),
    )
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    original_update = storage.update_cycle_lock
    call_count = {"value": 0}

    def _flaky_update_cycle_lock(tenant_id: str, updates: dict) -> None:
        call_count["value"] += 1
        if call_count["value"] >= 2:
            raise PermissionError(
                "[WinError 5] Access is denied: '.cycle.lock'"
            )
        original_update(tenant_id, updates)

    monkeypatch.setattr(storage, "update_cycle_lock", _flaky_update_cycle_lock)

    result = _orchestrator(storage).run_cycle("tenant_a")

    rows = storage.load_cycle_metadata_for_cycle("tenant_a", result.metadata.cycle_id)
    completed = [
        row for row in rows if str(row.get("status", "")).strip().lower() == "completed"
    ][0]

    assert completed["progress_channel_degraded"] is True
    assert int(completed["lock_write_warning_count"]) >= 1
    runtime_summary = completed["runtime_summary"]
    assert runtime_summary["progress_snapshot"]["progress_channel_degraded"] is True

    runtime = EngineRuntime(storage=storage)
    scope = AuthorizedTenantScope.from_iterable("operator_a", ["tenant_a"])
    payload = runtime.get_scan_status("tenant_a", authz_scope=scope)

    assert payload["status"] == "completed"
    assert payload["progress_channel_degraded"] is True
    assert int(payload["lock_write_warning_count"] or 0) >= 1


def test_phase12_scheduler_applies_infra_failure_cooldown_and_does_not_launch(
    tmp_path: Path,
) -> None:
    lifecycle = _build_lifecycle(tmp_path)
    tenant_id = lifecycle.register_tenant(
        name="Bank Indonesia",
        password="tenant-secret",
        main_url="https://www.bi.go.id",
        seed_endpoints=["www.bi.go.id:443"],
    )
    now_ms = int(time.time() * 1000)
    lifecycle.storage.save_scheduler_state(
        tenant_id,
        {
            "last_run_unix_ms": now_ms - 60_000,
            "next_run_unix_ms": 1,
            "last_status": "failed",
            "last_cycle_id": "cycle_000001",
            "last_cycle_number": 1,
            "consecutive_failures": 1,
            "last_error": "PermissionError: .cycle.lock Access is denied",
        },
    )
    lifecycle.storage.append_cycle_metadata(
        tenant_id,
        {
            "schema_version": "v2.6",
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
            "timestamp_unix_ms": now_ms - 15_000,
            "duration_ms": 5_000,
            "status": "failed",
            "endpoints_scanned": 0,
            "error_messages": [
                "PermissionError: [WinError 5] Access is denied while writing .cycle.lock"
            ],
            "failure_class": "infrastructure",
        },
    )

    service = _FakeScheduledOperatorService()
    scheduler = CycleScheduler(
        operator_service=service,
        storage=lifecycle.storage,
        tick_seconds=5,
        tenant_ids=[tenant_id],
    )

    scheduler.run_once()

    assert service.launches == []
    state = lifecycle.storage.load_scheduler_state(tenant_id)
    assert isinstance(state, dict)
    assert state["last_status"] == "infra_cooldown"
    assert state["last_failure_class"] == "infrastructure"
    assert int(state["next_run_unix_ms"]) - now_ms >= 9 * 60 * 1000
