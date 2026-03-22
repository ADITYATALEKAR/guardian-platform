from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List
from types import SimpleNamespace

import pytest

from infrastructure.layer5_api import APIRequest, Layer5API, Layer5BootstrapConfig, build_layer5_runtime_bundle
from infrastructure.operator_plane.services import cycle_worker
import infrastructure.operator_plane.services.operator_service as operator_service_module
from infrastructure.operator_plane.registry.operator_registry import create_operator
from infrastructure.operator_plane.registry.operator_tenant_links import add_link
from infrastructure.operator_plane.storage.operator_storage import ensure_operator_storage
from infrastructure.runtime.engine_runtime import EngineRuntime
from infrastructure.storage_manager.storage_manager import StorageManager


def test_phase2_auth_register_creates_workspace_and_login_scope(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPERATOR_MASTER_PASSWORD", "master-secret")
    bundle = build_layer5_runtime_bundle(
        Layer5BootstrapConfig(
            storage_root=str(tmp_path / "storage"),
            operator_storage_root=str(tmp_path / "operator_storage"),
            simulation_root=str(tmp_path / "simulation"),
        )
    )

    reg = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/register",
            json_body={
                "email": "phase2.user@example.com",
                "password": "StrongPassword123!",
                "master_password": "master-secret",
                "institution_name": "Phase2 Bank",
            },
        )
    )
    assert reg.status_code == 200
    payload = reg.payload["data"]
    tenant_id = str(payload["tenant_id"])
    assert tenant_id.startswith("tenant_")
    assert payload["onboarding_status"] == "PENDING"
    assert payload["cycle_started"] is False

    login = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/login",
            json_body={
                "operator_id": "phase2.user@example.com",
                "password": "StrongPassword123!",
            },
        )
    )
    assert login.status_code == 200
    assert login.payload["data"]["role"] == "OWNER"
    assert login.payload["data"]["tenant_id"] == tenant_id
    assert tenant_id in list(login.payload["data"]["tenant_ids"])


def test_phase2_auth_register_duplicate_account_returns_conflict(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPERATOR_MASTER_PASSWORD", "master-secret")
    bundle = build_layer5_runtime_bundle(
        Layer5BootstrapConfig(
            storage_root=str(tmp_path / "storage"),
            operator_storage_root=str(tmp_path / "operator_storage"),
            simulation_root=str(tmp_path / "simulation"),
        )
    )

    first = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/register",
            json_body={
                "email": "duplicate@example.com",
                "password": "StrongPassword123!",
                "master_password": "master-secret",
            },
        )
    )
    assert first.status_code == 200

    second = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/register",
            json_body={
                "email": "duplicate@example.com",
                "password": "StrongPassword123!",
                "master_password": "master-secret",
            },
        )
    )
    assert second.status_code == 409
    assert second.payload["error"]["message"] == "account already exists"


def test_phase2_registered_operator_cannot_create_second_tenant(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPERATOR_MASTER_PASSWORD", "master-secret")
    bundle = build_layer5_runtime_bundle(
        Layer5BootstrapConfig(
            storage_root=str(tmp_path / "storage"),
            operator_storage_root=str(tmp_path / "operator_storage"),
            simulation_root=str(tmp_path / "simulation"),
        )
    )

    reg = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/register",
            json_body={
                "email": "single.tenant@example.com",
                "password": "StrongPassword123!",
                "master_password": "master-secret",
                "institution_name": "Single Tenant Bank",
            },
        )
    )
    assert reg.status_code == 200

    with pytest.raises(RuntimeError, match="additional tenant creation is not permitted"):
        bundle.operator_service.register_tenant(
            operator_id=str(reg.payload["data"]["operator_id"]),
            institution_name="Second Workspace",
            main_url="https://second.example.com",
            seed_endpoints=[],
            password="TenantPassword123!",
        )


def test_phase2_owner_can_add_member_to_same_tenant_and_list_users(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPERATOR_MASTER_PASSWORD", "master-secret")
    bundle = build_layer5_runtime_bundle(
        Layer5BootstrapConfig(
            storage_root=str(tmp_path / "storage"),
            operator_storage_root=str(tmp_path / "operator_storage"),
            simulation_root=str(tmp_path / "simulation"),
        )
    )

    reg = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/register",
            json_body={
                "email": "owner@example.com",
                "password": "StrongPassword123!",
                "master_password": "master-secret",
                "institution_name": "Owner Bank",
            },
        )
    )
    assert reg.status_code == 200
    operator_id = str(reg.payload["data"]["operator_id"])
    tenant_id = str(reg.payload["data"]["tenant_id"])

    created = bundle.operator_service.add_user_to_tenant(
        operator_id=operator_id,
        tenant_id=tenant_id,
        new_operator_id="usr_member_001",
        email="member@example.com",
        password="StrongPassword123!",
        created_at_unix_ms=1_710_000_000_123,
    )
    assert created["role"] == "MEMBER"
    assert created["tenant_id"] == tenant_id

    users = bundle.operator_service.list_users_for_tenant(operator_id=operator_id, tenant_id=tenant_id)
    assert [row["role"] for row in users["users"]] == ["OWNER", "MEMBER"]
    assert sorted(row["operator_id"] for row in users["users"]) == sorted([operator_id, "usr_member_001"])

    member_login = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/login",
            json_body={"operator_id": "member@example.com", "password": "StrongPassword123!"},
        )
    )
    assert member_login.status_code == 200
    assert member_login.payload["data"]["tenant_id"] == tenant_id
    assert member_login.payload["data"]["role"] == "MEMBER"


def test_phase2_owner_can_add_user_without_manual_user_id_and_change_password(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("OPERATOR_MASTER_PASSWORD", "master-secret")
    bundle = build_layer5_runtime_bundle(
        Layer5BootstrapConfig(
            storage_root=str(tmp_path / "storage"),
            operator_storage_root=str(tmp_path / "operator_storage"),
            simulation_root=str(tmp_path / "simulation"),
        )
    )

    reg = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/register",
            json_body={
                "email": "owner2@example.com",
                "password": "StrongPassword123!",
                "master_password": "master-secret",
                "institution_name": "Owner Bank",
            },
        )
    )
    assert reg.status_code == 200
    owner_id = str(reg.payload["data"]["operator_id"])
    tenant_id = str(reg.payload["data"]["tenant_id"])

    owner_login = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/login",
            json_body={"operator_id": owner_id, "password": "StrongPassword123!"},
        )
    )
    assert owner_login.status_code == 200
    session_token = str(owner_login.payload["data"]["session_token"])

    add_user = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/admin/users",
            headers={"Authorization": f"Bearer {session_token}"},
            json_body={
                "email": "member2@example.com",
                "password": "StrongPassword123!",
                "tenant_id": tenant_id,
            },
        )
    )
    assert add_user.status_code == 200
    member_id = str(add_user.payload["data"]["operator_id"])
    assert member_id.startswith("usr_member2_")

    password_change = bundle.api.handle(
        APIRequest(
            method="POST",
            path=f"/v1/admin/users/{member_id}/change-password",
            headers={"Authorization": f"Bearer {session_token}"},
            query={"tenant_id": tenant_id},
            json_body={
                "current_password": "StrongPassword123!",
                "new_password": "ChangedPassword123!",
            },
        )
    )
    assert password_change.status_code == 200

    old_login = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/login",
            json_body={"operator_id": "member2@example.com", "password": "StrongPassword123!"},
        )
    )
    assert old_login.status_code == 401

    new_login = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/login",
            json_body={"operator_id": "member2@example.com", "password": "ChangedPassword123!"},
        )
    )
    assert new_login.status_code == 200
    assert new_login.payload["data"]["tenant_id"] == tenant_id


def test_phase2_admin_has_same_management_access_as_owner(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPERATOR_MASTER_PASSWORD", "master-secret")
    bundle = build_layer5_runtime_bundle(
        Layer5BootstrapConfig(
            storage_root=str(tmp_path / "storage"),
            operator_storage_root=str(tmp_path / "operator_storage"),
            simulation_root=str(tmp_path / "simulation"),
        )
    )

    reg = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/register",
            json_body={
                "email": "owner3@example.com",
                "password": "StrongPassword123!",
                "master_password": "master-secret",
                "institution_name": "Owner Bank",
            },
        )
    )
    assert reg.status_code == 200
    owner_id = str(reg.payload["data"]["operator_id"])
    tenant_id = str(reg.payload["data"]["tenant_id"])

    admin_user = bundle.operator_service.add_user_to_tenant(
        operator_id=owner_id,
        tenant_id=tenant_id,
        new_operator_id="usr_admin_001",
        email="admin3@example.com",
        password="StrongPassword123!",
        created_at_unix_ms=1_710_000_000_456,
        role=bundle.operator_service.ROLE_ADMIN,
    )
    assert admin_user["role"] == "ADMIN"

    admin_login = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/login",
            json_body={"operator_id": "admin3@example.com", "password": "StrongPassword123!"},
        )
    )
    assert admin_login.status_code == 200
    session_token = str(admin_login.payload["data"]["session_token"])

    add_member = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/admin/users",
            headers={"Authorization": f"Bearer {session_token}"},
            json_body={
                "email": "member3@example.com",
                "password": "StrongPassword123!",
                "tenant_id": tenant_id,
                "role": "MEMBER",
            },
        )
    )
    assert add_member.status_code == 200

    reset = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/admin/workspace/reset",
            headers={"Authorization": f"Bearer {session_token}"},
            json_body={"current_password": "StrongPassword123!"},
        )
    )
    assert reset.status_code == 200


def test_phase2_cannot_delete_last_owner(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPERATOR_MASTER_PASSWORD", "master-secret")
    bundle = build_layer5_runtime_bundle(
        Layer5BootstrapConfig(
            storage_root=str(tmp_path / "storage"),
            operator_storage_root=str(tmp_path / "operator_storage"),
            simulation_root=str(tmp_path / "simulation"),
        )
    )

    reg = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/register",
            json_body={
                "email": "sole.owner@example.com",
                "password": "StrongPassword123!",
                "master_password": "master-secret",
                "institution_name": "Owner Bank",
            },
        )
    )
    assert reg.status_code == 200

    with pytest.raises(RuntimeError, match="cannot delete last owner"):
        bundle.operator_service.delete_user_from_tenant(
            operator_id=str(reg.payload["data"]["operator_id"]),
            tenant_id=str(reg.payload["data"]["tenant_id"]),
            target_operator_id=str(reg.payload["data"]["operator_id"]),
            current_password="StrongPassword123!",
        )


def test_phase2_owner_can_reset_workspace_and_keep_same_tenant_id(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPERATOR_MASTER_PASSWORD", "master-secret")
    bundle = build_layer5_runtime_bundle(
        Layer5BootstrapConfig(
            storage_root=str(tmp_path / "storage"),
            operator_storage_root=str(tmp_path / "operator_storage"),
            simulation_root=str(tmp_path / "simulation"),
        )
    )

    reg = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/register",
            json_body={
                "email": "reset.owner@example.com",
                "password": "StrongPassword123!",
                "master_password": "master-secret",
                "institution_name": "Resettable Bank",
            },
        )
    )
    assert reg.status_code == 200
    operator_id = str(reg.payload["data"]["operator_id"])
    tenant_id = str(reg.payload["data"]["tenant_id"])

    bundle.storage.append_cycle_metadata(
        tenant_id,
        {
            "schema_version": "v1",
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
            "status": "completed",
            "timestamp_unix_ms": 1_710_000_000_000,
        },
    )
    bundle.storage.persist_guardian_record(
        tenant_id,
        {
            "timestamp_ms": 1_710_000_000_000,
            "entity_id": "api.resettable.bank:443",
            "severity": 0.8,
            "confidence": 0.7,
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
        },
    )
    simulation_path = Path(tmp_path / "simulation" / "tenants" / tenant_id / "artifact.json")
    simulation_path.parent.mkdir(parents=True, exist_ok=True)
    simulation_path.write_text("{}", encoding="utf-8")

    reset = bundle.operator_service.reset_workspace(
        operator_id=operator_id,
        tenant_id=tenant_id,
        current_password="StrongPassword123!",
    )
    assert reset["tenant_id"] == tenant_id
    assert reset["onboarding_status"] == "PENDING"

    config = bundle.storage.load_tenant_config(tenant_id)
    assert config["tenant_id"] == tenant_id
    assert config["name"] == ""
    assert config["main_url"] == ""
    assert config["seed_endpoints"] == []
    assert config["onboarding_status"] == "PENDING"
    assert config["onboarded_at_unix_ms"] is None
    assert bundle.storage.load_cycle_metadata(tenant_id) == []
    assert bundle.storage.load_latest_guardian_records(tenant_id) == []
    assert not simulation_path.exists()
    relogin = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/login",
            json_body={"operator_id": operator_id, "password": "StrongPassword123!"},
        )
    )
    assert relogin.status_code == 200
    assert relogin.payload["data"]["tenant_id"] == tenant_id


def test_phase2_member_can_self_delete_without_affecting_tenant(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPERATOR_MASTER_PASSWORD", "master-secret")
    bundle = build_layer5_runtime_bundle(
        Layer5BootstrapConfig(
            storage_root=str(tmp_path / "storage"),
            operator_storage_root=str(tmp_path / "operator_storage"),
            simulation_root=str(tmp_path / "simulation"),
        )
    )

    reg = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/register",
            json_body={
                "email": "owner.selfdelete@example.com",
                "password": "StrongPassword123!",
                "master_password": "master-secret",
                "institution_name": "Self Delete Bank",
            },
        )
    )
    assert reg.status_code == 200
    owner_id = str(reg.payload["data"]["operator_id"])
    tenant_id = str(reg.payload["data"]["tenant_id"])

    created = bundle.operator_service.add_user_to_tenant(
        operator_id=owner_id,
        tenant_id=tenant_id,
        new_operator_id="usr_member_self_delete",
        email="member.selfdelete@example.com",
        password="StrongPassword123!",
        created_at_unix_ms=1_710_000_000_456,
    )
    assert created["role"] == "MEMBER"

    deleted = bundle.operator_service.delete_current_user(
        operator_id="usr_member_self_delete",
        current_password="StrongPassword123!",
    )
    assert deleted["deleted"] is True
    assert deleted["operator_id"] == "usr_member_self_delete"
    assert deleted["tenant_id"] == tenant_id

    users = bundle.operator_service.list_users_for_tenant(operator_id=owner_id, tenant_id=tenant_id)
    assert [row["operator_id"] for row in users["users"]] == [owner_id]

    relogin = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/login",
            json_body={"operator_id": "member.selfdelete@example.com", "password": "StrongPassword123!"},
        )
    )
    assert relogin.status_code == 401


def test_phase2_last_owner_can_self_delete_and_leave_workspace_data_intact(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPERATOR_MASTER_PASSWORD", "master-secret")
    bundle = build_layer5_runtime_bundle(
        Layer5BootstrapConfig(
            storage_root=str(tmp_path / "storage"),
            operator_storage_root=str(tmp_path / "operator_storage"),
            simulation_root=str(tmp_path / "simulation"),
        )
    )

    reg = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/register",
            json_body={
                "email": "sole.selfdelete@example.com",
                "password": "StrongPassword123!",
                "master_password": "master-secret",
                "institution_name": "Protected Owner Bank",
            },
        )
    )
    assert reg.status_code == 200
    operator_id = str(reg.payload["data"]["operator_id"])
    tenant_id = str(reg.payload["data"]["tenant_id"])

    bundle.storage.append_cycle_metadata(
        tenant_id,
        {
            "schema_version": "v1",
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
            "status": "completed",
            "timestamp_unix_ms": 1_710_000_000_000,
        },
    )

    deleted = bundle.operator_service.delete_current_user(
        operator_id=operator_id,
        current_password="StrongPassword123!",
    )
    assert deleted["deleted"] is True
    assert deleted["operator_id"] == operator_id
    assert deleted["tenant_id"] == tenant_id
    assert bundle.storage.load_cycle_metadata(tenant_id) != []

    relogin = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/login",
            json_body={"operator_id": operator_id, "password": "StrongPassword123!"},
        )
    )
    assert relogin.status_code == 401


def test_phase2_auth_register_requires_master_password_when_operator_exists(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("OPERATOR_MASTER_PASSWORD", "master-secret")
    bundle = build_layer5_runtime_bundle(
        Layer5BootstrapConfig(
            storage_root=str(tmp_path / "storage"),
            operator_storage_root=str(tmp_path / "operator_storage"),
            simulation_root=str(tmp_path / "simulation"),
        )
    )

    bootstrap = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/register",
            json_body={
                "email": "bootstrap@example.com",
                "password": "StrongPassword123!",
                "master_password": "master-secret",
            },
        )
    )
    assert bootstrap.status_code == 200

    blocked = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/register",
            json_body={
                "email": "no.master@example.com",
                "password": "StrongPassword123!",
            },
        )
    )
    assert blocked.status_code == 403


@dataclass
class _FakeOperatorService:
    onboard_calls: List[Dict[str, Any]]

    def onboard_workspace_and_start_cycle(self, **kwargs):
        self.onboard_calls.append(dict(kwargs))
        return {
            "tenant_id": kwargs["tenant_id"],
            "onboarding_status": "PENDING",
            "cycle_started": True,
        }


def _new_app_for_onboard(tmp_path: Path, fake_service: _FakeOperatorService) -> tuple[Layer5API, Path]:
    storage = StorageManager(str(tmp_path / "storage"))
    storage.create_tenant("tenant_a")
    storage.create_tenant("tenant_b")
    runtime = EngineRuntime(storage=storage, simulation_root=str(tmp_path / "sim"))
    operator_root = tmp_path / "operator_storage"
    ensure_operator_storage(str(operator_root))
    create_operator(
        str(operator_root),
        operator_id="op_a",
        email="op_a@example.com",
        password="StrongPassword123!",
        created_at_unix_ms=1_710_000_000_000,
        status="ACTIVE",
    )
    add_link(str(operator_root), "op_a", "tenant_a")
    app = Layer5API(
        runtime=runtime,
        operator_storage_root=str(operator_root),
        operator_service=fake_service,  # type: ignore[arg-type]
    )
    return app, operator_root


def _login(app: Layer5API) -> str:
    resp = app.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/login",
            json_body={"operator_id": "op_a", "password": "StrongPassword123!"},
        )
    )
    assert resp.status_code == 200
    return str(resp.payload["data"]["session_token"])


def test_phase2_onboard_and_scan_uses_session_scope_and_operator_context(tmp_path: Path) -> None:
    fake = _FakeOperatorService(onboard_calls=[])
    app, _ = _new_app_for_onboard(tmp_path, fake)
    token = _login(app)

    ok = app.handle(
        APIRequest(
            method="POST",
            path="/v1/tenants/tenant_a/onboard-and-scan",
            headers={"Authorization": f"Bearer {token}"},
            json_body={
                "institution_name": "Demo Bank",
                "main_url": "https://demo.bank",
                "seed_endpoints": ["demo.bank:443"],
            },
        )
    )
    assert ok.status_code == 200
    assert len(fake.onboard_calls) == 1
    assert fake.onboard_calls[0]["operator_id"] == "op_a"
    assert fake.onboard_calls[0]["tenant_id"] == "tenant_a"

    forbidden = app.handle(
        APIRequest(
            method="POST",
            path="/v1/tenants/tenant_b/onboard-and-scan",
            headers={"Authorization": f"Bearer {token}"},
            json_body={
                "institution_name": "Other",
                "main_url": "https://other.bank",
            },
        )
    )
    assert forbidden.status_code == 403


def test_phase2_onboard_and_scan_persists_pending_config_and_marks_completed_after_success(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("OPERATOR_MASTER_PASSWORD", "master-secret")
    bundle = build_layer5_runtime_bundle(
        Layer5BootstrapConfig(
            storage_root=str(tmp_path / "storage"),
            operator_storage_root=str(tmp_path / "operator_storage"),
            simulation_root=str(tmp_path / "simulation"),
        )
    )

    reg = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/register",
            json_body={
                "email": "async-owner@example.com",
                "password": "StrongPassword123!",
                "master_password": "master-secret",
                "institution_name": "Async Bank",
            },
        )
    )
    assert reg.status_code == 200
    tenant_id = str(reg.payload["data"]["tenant_id"])

    login = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/login",
            json_body={
                "operator_id": "async-owner@example.com",
                "password": "StrongPassword123!",
            },
        )
    )
    token = str(login.payload["data"]["session_token"])

    started = []

    def _fake_start_cycle_async(
        start_tenant_id: str,
        *,
        cycle_id: str,
        cycle_number: int,
    ) -> None:
        started.append((start_tenant_id, cycle_id, cycle_number))
        bundle.operator_service._tenant_lifecycle.mark_tenant_onboarding_completed(
            start_tenant_id
        )

    monkeypatch.setattr(bundle.operator_service, "_start_cycle_async", _fake_start_cycle_async)

    onboard = bundle.api.handle(
        APIRequest(
            method="POST",
            path=f"/v1/tenants/{tenant_id}/onboard-and-scan",
            headers={"Authorization": f"Bearer {token}"},
            json_body={
                "institution_name": "Bank of Japan",
                "main_url": "https://www.boj.or.jp/en/",
                "seed_endpoints": ["www.boj.or.jp:443"],
            },
        )
    )
    assert onboard.status_code == 200
    assert onboard.payload["data"]["onboarding_status"] == "PENDING"
    assert started == [(tenant_id, "cycle_000001", 1)]

    config = bundle.storage.load_tenant_config(tenant_id)
    assert config["name"] == "Bank of Japan"
    assert config["main_url"] == "https://www.boj.or.jp/en/"
    assert config["seed_endpoints"] == ["www.boj.or.jp:443"]
    assert config["onboarding_status"] == "COMPLETED"


def test_phase2_async_cycle_launch_uses_subprocess_worker(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("OPERATOR_MASTER_PASSWORD", "master-secret")
    bundle = build_layer5_runtime_bundle(
        Layer5BootstrapConfig(
            storage_root=str(tmp_path / "storage"),
            operator_storage_root=str(tmp_path / "operator_storage"),
            simulation_root=str(tmp_path / "simulation"),
        )
    )

    reg = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/register",
            json_body={
                "email": "worker-owner@example.com",
                "password": "StrongPassword123!",
                "master_password": "master-secret",
                "institution_name": "Worker Bank",
            },
        )
    )
    assert reg.status_code == 200
    tenant_id = str(reg.payload["data"]["tenant_id"])

    captured: Dict[str, Any] = {}

    def _fake_popen(*args: Any, **kwargs: Any) -> Any:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return SimpleNamespace(pid=12345)

    monkeypatch.setattr(operator_service_module.subprocess, "Popen", _fake_popen)
    bundle.storage.reserve_cycle_launch(
        tenant_id=tenant_id,
        cycle_id="cycle_000001",
        cycle_number=1,
    )

    bundle.operator_service._start_cycle_async(
        tenant_id,
        cycle_id="cycle_000001",
        cycle_number=1,
    )

    command = captured["args"][0]
    assert command[0]
    assert command[1:4] == ["-u", "-m", "infrastructure.operator_plane.services.cycle_worker"]
    assert "--tenant-id" in command
    assert tenant_id in command
    assert "--cycle-id" in command
    assert "cycle_000001" in command
    assert "--cycle-number" in command
    assert "1" in command
    assert captured["kwargs"]["cwd"] == str(Path(__file__).resolve().parents[2])
    assert captured["kwargs"]["stdin"] is operator_service_module.subprocess.DEVNULL


def test_phase2_cycle_worker_marks_onboarding_completed_after_success(monkeypatch) -> None:
    calls: List[str] = []

    fake_bundle = SimpleNamespace(
        orchestrator=SimpleNamespace(
            run_cycle=lambda tenant_id, **kwargs: calls.append(
                f"run:{tenant_id}:{kwargs.get('cycle_id', '-')}:{kwargs.get('cycle_number', '-')}"
            )
        ),
        operator_service=SimpleNamespace(
            _tenant_lifecycle=SimpleNamespace(
                mark_tenant_onboarding_completed=lambda tenant_id: calls.append(
                    f"complete:{tenant_id}"
                )
            )
        ),
    )

    monkeypatch.setattr(cycle_worker, "build_layer5_runtime_bundle", lambda config: fake_bundle)

    exit_code = cycle_worker.main(
        [
            "--tenant-id",
            "tenant_test",
            "--storage-root",
            "storage",
            "--operator-storage-root",
            "operator_storage",
            "--simulation-root",
            "simulation",
        ]
    )

    assert exit_code == 0
    assert calls == ["run:tenant_test:None:None", "complete:tenant_test"]
