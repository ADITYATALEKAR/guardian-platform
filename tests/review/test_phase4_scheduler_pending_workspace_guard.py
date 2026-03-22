from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from infrastructure.operator_plane.services.operator_service import OperatorService
from infrastructure.operator_plane.registry.operator_registry import create_operator
from infrastructure.runtime.tenant_lifecycle_manager import TenantLifecycleManager
from infrastructure.storage_manager.identity_manager import IdentityManager
from infrastructure.storage_manager.storage_manager import StorageManager
from layers.layer0_observation.acquisition.cycle_scheduler import CycleScheduler


def _build_lifecycle(tmp_path: Path) -> TenantLifecycleManager:
    storage = StorageManager(str(tmp_path / "storage"))
    identity = IdentityManager(storage)
    return TenantLifecycleManager(
        storage=storage,
        identity=identity,
        simulation_root=str(tmp_path / "simulation"),
    )


@dataclass
class _FakeScheduledOperatorService:
    storage: StorageManager | None = None
    launches: list[str] = field(default_factory=list)
    syncs: list[dict] = field(default_factory=list)

    def start_scheduled_cycle(self, *, tenant_id: str):
        self.launches.append(str(tenant_id))
        return {
            "tenant_id": tenant_id,
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
        }

    def sync_scheduler_state_from_cycle_result(
        self,
        *,
        tenant_id: str,
        cycle_id: str | None = None,
        cycle_number: int | None = None,
        status: str | None = None,
        error_message: str | None = None,
    ):
        self.syncs.append(
            {
                "tenant_id": tenant_id,
                "cycle_id": cycle_id,
                "cycle_number": cycle_number,
                "status": status,
                "error_message": error_message,
            }
        )
        now_ms = int(time.time() * 1000)
        payload = {
            "last_run_unix_ms": now_ms,
            "next_run_unix_ms": now_ms + (7_200 * 1000),
            "last_status": str(status or "completed"),
            "last_cycle_id": str(cycle_id or ""),
            "last_cycle_number": int(cycle_number or 0),
            "consecutive_failures": 0,
        }
        if self.storage is not None:
            self.storage.save_scheduler_state(tenant_id, payload)
        return payload


class _NoopOrchestrator:
    def run_cycle(self, tenant_id: str, **kwargs):
        return {"tenant_id": tenant_id, **kwargs}


def _build_operator_service(tmp_path: Path) -> tuple[OperatorService, str]:
    lifecycle = _build_lifecycle(tmp_path)
    operator_root = tmp_path / "operator_storage"
    service = OperatorService(
        operator_storage_root=str(operator_root),
        storage_manager=lifecycle.storage,
        identity_manager=lifecycle.identity,
        simulation_root=str(tmp_path / "simulation"),
        orchestrator=_NoopOrchestrator(),
    )
    create_operator(
        str(operator_root),
        operator_id="op_owner",
        email="owner@example.com",
        password="StrongPassword123!",
        created_at_unix_ms=1_710_000_000_000,
        status="ACTIVE",
    )
    return service, "op_owner"


def test_phase4_scheduler_skips_pending_workspace_before_first_onboarding_scan(tmp_path: Path) -> None:
    lifecycle = _build_lifecycle(tmp_path)
    tenant_id = lifecycle.register_pending_tenant(
        name="Bank Of Japan",
        password="tenant-secret",
    )
    service = _FakeScheduledOperatorService(storage=lifecycle.storage)
    scheduler = CycleScheduler(
        operator_service=service,
        storage=lifecycle.storage,
        tick_seconds=5,
        tenant_ids=[tenant_id],
    )

    scheduler.run_once()

    assert service.launches == []
    scheduler_state_path = lifecycle.storage.get_tenant_path(tenant_id) / "scheduler_state.json"
    scheduler_state = json.loads(scheduler_state_path.read_text(encoding="utf-8"))
    assert scheduler_state["last_status"] == "pending_onboarding"
    assert scheduler_state["consecutive_failures"] == 0


def test_phase4_scheduler_launches_only_after_onboarding_completion(tmp_path: Path) -> None:
    lifecycle = _build_lifecycle(tmp_path)
    tenant_id = lifecycle.register_tenant(
        name="Bank Of Japan",
        password="tenant-secret",
        main_url="https://www.boj.or.jp/en/",
        seed_endpoints=["www.boj.or.jp:443"],
    )
    service = _FakeScheduledOperatorService(storage=lifecycle.storage)
    scheduler = CycleScheduler(
        operator_service=service,
        storage=lifecycle.storage,
        tick_seconds=5,
        tenant_ids=[tenant_id],
    )

    scheduler.run_once()

    assert service.launches == [tenant_id]
    scheduler_state_path = lifecycle.storage.get_tenant_path(tenant_id) / "scheduler_state.json"
    scheduler_state = json.loads(scheduler_state_path.read_text(encoding="utf-8"))
    assert scheduler_state["last_status"] == "launched"
    assert scheduler_state["last_cycle_number"] == 1


def test_phase4_operator_service_rejects_scheduled_cycle_for_pending_workspace(tmp_path: Path) -> None:
    lifecycle = _build_lifecycle(tmp_path)
    tenant_id = lifecycle.register_pending_tenant(
        name="Bank Of Japan",
        password="tenant-secret",
    )
    service = OperatorService(
        operator_storage_root=str(tmp_path / "operator_storage"),
        storage_manager=lifecycle.storage,
        identity_manager=lifecycle.identity,
        simulation_root=str(tmp_path / "simulation"),
        orchestrator=_NoopOrchestrator(),
    )

    try:
        service.start_scheduled_cycle(tenant_id=tenant_id)
    except RuntimeError as exc:
        assert "completed onboarding" in str(exc)
    else:
        raise AssertionError("expected scheduled cycle to be rejected for pending workspace")


def test_phase4_create_workspace_seeds_pending_scheduler_state(tmp_path: Path) -> None:
    service, operator_id = _build_operator_service(tmp_path)

    created = service.create_workspace(
        operator_id=operator_id,
        institution_name="Bank Of Japan",
    )

    state = service._storage_manager.load_scheduler_state(created["tenant_id"])
    assert isinstance(state, dict)
    assert state["last_status"] == "pending_onboarding"
    assert int(state["next_run_unix_ms"]) > 0


def test_phase4_scheduler_observes_manual_active_cycle_before_onboarding_completion(tmp_path: Path) -> None:
    lifecycle = _build_lifecycle(tmp_path)
    tenant_id = lifecycle.register_pending_tenant(
        name="Bank Of Japan",
        password="tenant-secret",
    )
    lifecycle.configure_tenant_onboarding(
        tenant_id=tenant_id,
        name="Bank Of Japan",
        main_url="https://www.boj.or.jp/en/",
        seed_endpoints=["www.boj.or.jp:443"],
    )
    lifecycle.storage.reserve_cycle_launch(
        tenant_id=tenant_id,
        cycle_id="cycle_000001",
        cycle_number=1,
    )
    service = _FakeScheduledOperatorService(storage=lifecycle.storage)
    scheduler = CycleScheduler(
        operator_service=service,
        storage=lifecycle.storage,
        tick_seconds=5,
        tenant_ids=[tenant_id],
    )

    scheduler.run_once()

    assert service.launches == []
    scheduler_state = lifecycle.storage.load_scheduler_state(tenant_id)
    assert isinstance(scheduler_state, dict)
    assert scheduler_state["last_status"] == "active_cycle"
    assert scheduler_state["last_cycle_id"] == "cycle_000001"


def test_phase4_manual_first_scan_syncs_scheduler_state_to_real_cycle(tmp_path: Path) -> None:
    service, operator_id = _build_operator_service(tmp_path)
    created = service.create_workspace(
        operator_id=operator_id,
        institution_name="Bank Of Mexico",
    )

    result = service.onboard_workspace_and_start_cycle(
        operator_id=operator_id,
        tenant_id=created["tenant_id"],
        institution_name="Bank Of Mexico",
        main_url="https://www.banxico.org.mx/indexen.html",
        seed_endpoints=["www.banxico.org.mx:443"],
    )

    assert result["cycle_started"] is True
    state = service._storage_manager.load_scheduler_state(created["tenant_id"])
    assert isinstance(state, dict)
    assert state["last_cycle_id"] == "cycle_000001"
    assert state["last_cycle_number"] == 1
    assert state["last_status"] == "completed"
    assert int(state["next_run_unix_ms"]) > int(state["last_run_unix_ms"])


def test_phase4_scheduler_reconciles_stale_launched_state_from_completed_cycle(tmp_path: Path) -> None:
    lifecycle = _build_lifecycle(tmp_path)
    tenant_id = lifecycle.register_tenant(
        name="Bank Of Mexico",
        password="tenant-secret",
        main_url="https://www.banxico.org.mx/indexen.html",
        seed_endpoints=["www.banxico.org.mx:443"],
    )
    lifecycle.storage.save_scheduler_state(
        tenant_id,
        {
            "last_run_unix_ms": 1_710_000_000_000,
            "next_run_unix_ms": 1,
            "last_status": "launched",
            "last_cycle_id": "cycle_000001",
            "last_cycle_number": 1,
            "consecutive_failures": 0,
        },
    )
    lifecycle.storage.append_cycle_metadata(
        tenant_id,
        {
            "schema_version": "v2.6",
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
            "timestamp_unix_ms": 1_710_000_100_000,
            "duration_ms": 42_000,
            "status": "completed",
            "endpoints_scanned": 4,
        },
    )

    service = _FakeScheduledOperatorService(storage=lifecycle.storage)
    scheduler = CycleScheduler(
        operator_service=service,
        storage=lifecycle.storage,
        cadence_seconds=7_200,
        tick_seconds=5,
        tenant_ids=[tenant_id],
    )

    scheduler.run_once()

    assert service.launches == []
    assert service.syncs[0]["cycle_id"] == "cycle_000001"
    state = lifecycle.storage.load_scheduler_state(tenant_id)
    assert isinstance(state, dict)
    assert state["last_status"] == "completed"
    assert int(state["next_run_unix_ms"]) > int(state["last_run_unix_ms"])
