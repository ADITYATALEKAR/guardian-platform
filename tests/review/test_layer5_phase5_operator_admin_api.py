from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from infrastructure.layer5_api import APIRequest, Layer5API
from infrastructure.operator_plane.registry.operator_registry import create_operator
from infrastructure.operator_plane.registry.operator_tenant_links import add_link
from infrastructure.operator_plane.storage.operator_storage import ensure_operator_storage
from infrastructure.runtime.engine_runtime import EngineRuntime
from infrastructure.storage_manager.storage_manager import StorageManager


@dataclass
class _FakeOperatorService:
    operator_calls: List[Dict[str, Any]]
    tenant_calls: List[Dict[str, Any]]
    user_list_calls: List[Dict[str, Any]]
    user_delete_calls: List[Dict[str, Any]]
    user_password_change_calls: List[Dict[str, Any]]
    workspace_reset_calls: List[Dict[str, Any]]
    self_delete_calls: List[Dict[str, Any]]

    def register_operator(self, **kwargs):
        self.operator_calls.append(dict(kwargs))
        return {
            "operator_id": kwargs["operator_id"],
            "email": kwargs["email"],
            "status": kwargs.get("status", "ACTIVE"),
        }

    def register_tenant(self, **kwargs):
        self.tenant_calls.append(dict(kwargs))
        return {"tenant_id": "tenant_new", "cycle_started": True}

    def add_user_to_tenant(self, **kwargs):
        self.operator_calls.append(dict(kwargs))
        return {
            "operator_id": kwargs["new_operator_id"],
            "email": kwargs["email"],
            "status": kwargs.get("status", "ACTIVE"),
            "role": kwargs.get("role", "MEMBER"),
            "tenant_id": kwargs.get("tenant_id") or "tenant_a",
            "linked": True,
        }

    def list_users_for_tenant(self, **kwargs):
        self.user_list_calls.append(dict(kwargs))
        return {
            "tenant_id": kwargs.get("tenant_id") or "tenant_a",
            "users": [
                {
                    "operator_id": "op_a",
                    "email": "op_a@example.com",
                    "status": "ACTIVE",
                    "role": "OWNER",
                    "tenant_id": kwargs.get("tenant_id") or "tenant_a",
                }
            ],
        }

    def delete_user_from_tenant(self, **kwargs):
        self.user_delete_calls.append(dict(kwargs))
        return {
            "deleted": True,
            "operator_id": kwargs["target_operator_id"],
            "tenant_id": kwargs.get("tenant_id") or "tenant_a",
        }

    def change_user_password_in_tenant(self, **kwargs):
        self.user_password_change_calls.append(dict(kwargs))
        return {
            "operator_id": kwargs["target_operator_id"],
            "tenant_id": kwargs.get("tenant_id") or "tenant_a",
            "password_changed": True,
        }

    def reset_workspace(self, **kwargs):
        self.workspace_reset_calls.append(dict(kwargs))
        return {
            "tenant_id": kwargs.get("tenant_id") or "tenant_a",
            "onboarding_status": "PENDING",
            "reset": True,
        }

    def delete_current_user(self, **kwargs):
        self.self_delete_calls.append(dict(kwargs))
        return {
            "deleted": True,
            "operator_id": kwargs["operator_id"],
            "tenant_id": "tenant_a",
            "self_deleted": True,
        }


def _new_storage(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage"))
    storage.create_tenant("tenant_a")
    return storage


def _new_app(
    tmp_path: Path,
    *,
    operator_service: _FakeOperatorService | None = None,
) -> tuple[Layer5API, Path]:
    storage = _new_storage(tmp_path)
    runtime = EngineRuntime(storage=storage, simulation_root=str(tmp_path / "sim_root"))
    operator_root = tmp_path / "operator_storage"
    ensure_operator_storage(str(operator_root))
    app = Layer5API(
        runtime=runtime,
        operator_storage_root=str(operator_root),
        operator_service=operator_service,  # type: ignore[arg-type]
    )
    return app, operator_root


def _create_operator(operator_root: Path, operator_id: str, password: str = "StrongPassword123!") -> None:
    create_operator(
        str(operator_root),
        operator_id=operator_id,
        email=f"{operator_id}@example.com",
        password=password,
        created_at_unix_ms=1_710_000_000_000,
        status="ACTIVE",
    )


def _link_operator(operator_root: Path, operator_id: str, tenant_id: str = "tenant_a") -> None:
    add_link(str(operator_root), operator_id, tenant_id)


def _login(app: Layer5API, operator_id: str, password: str = "StrongPassword123!") -> str:
    resp = app.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/login",
            json_body={"operator_id": operator_id, "password": password},
        )
    )
    assert resp.status_code == 200
    return str(resp.payload["data"]["session_token"])


def test_phase5_operator_register_bootstrap_allows_no_session(tmp_path: Path) -> None:
    fake = _FakeOperatorService(operator_calls=[], tenant_calls=[], user_list_calls=[], user_delete_calls=[], user_password_change_calls=[], workspace_reset_calls=[], self_delete_calls=[])
    app, _ = _new_app(tmp_path, operator_service=fake)

    resp = app.handle(
        APIRequest(
            method="POST",
            path="/v1/admin/operators/register",
            json_body={
                "operator_id": "op_bootstrap",
                "email": "bootstrap@example.com",
                "password": "StrongPassword123!",
                "created_at_unix_ms": 1_710_000_000_000,
                "master_password": "master",
            },
        )
    )

    assert resp.status_code == 200
    assert resp.payload["data"]["operator_id"] == "op_bootstrap"
    assert len(fake.operator_calls) == 1


def test_phase5_operator_register_requires_session_after_bootstrap(tmp_path: Path) -> None:
    fake = _FakeOperatorService(operator_calls=[], tenant_calls=[], user_list_calls=[], user_delete_calls=[], user_password_change_calls=[], workspace_reset_calls=[], self_delete_calls=[])
    app, operator_root = _new_app(tmp_path, operator_service=fake)
    _create_operator(operator_root, "op_a")
    _link_operator(operator_root, "op_a")

    unauth = app.handle(
        APIRequest(
            method="POST",
            path="/v1/admin/operators/register",
            json_body={
                "operator_id": "op_b",
                "email": "opb@example.com",
                "password": "StrongPassword123!",
                "created_at_unix_ms": 1_710_000_000_001,
            },
        )
    )
    assert unauth.status_code == 401

    token = _login(app, "op_a")
    authed = app.handle(
        APIRequest(
            method="POST",
            path="/v1/admin/operators/register",
            headers={"Authorization": f"Bearer {token}"},
            json_body={
                "operator_id": "op_b",
                "email": "opb@example.com",
                "password": "StrongPassword123!",
                "created_at_unix_ms": 1_710_000_000_001,
            },
        )
    )
    assert authed.status_code == 200
    assert len(fake.operator_calls) == 1
    assert fake.operator_calls[0]["operator_id"] == "op_a"
    assert fake.operator_calls[0]["new_operator_id"] == "op_b"


def test_phase5_operator_register_derives_user_id_from_email_when_missing(tmp_path: Path) -> None:
    fake = _FakeOperatorService(operator_calls=[], tenant_calls=[], user_list_calls=[], user_delete_calls=[], user_password_change_calls=[], workspace_reset_calls=[], self_delete_calls=[])
    app, operator_root = _new_app(tmp_path, operator_service=fake)
    _create_operator(operator_root, "op_a")
    _link_operator(operator_root, "op_a")
    token = _login(app, "op_a")

    authed = app.handle(
        APIRequest(
            method="POST",
            path="/v1/admin/users",
            headers={"Authorization": f"Bearer {token}"},
            json_body={
                "email": "new.member@example.com",
                "password": "StrongPassword123!",
                "created_at_unix_ms": 1_710_000_000_001,
            },
        )
    )
    assert authed.status_code == 200
    assert len(fake.operator_calls) == 1
    assert fake.operator_calls[0]["new_operator_id"].startswith("usr_newmember_")
    assert str(authed.payload["data"]["operator_id"]).startswith("usr_newmember_")


def test_phase5_tenant_register_uses_session_operator_context(tmp_path: Path) -> None:
    fake = _FakeOperatorService(operator_calls=[], tenant_calls=[], user_list_calls=[], user_delete_calls=[], user_password_change_calls=[], workspace_reset_calls=[], self_delete_calls=[])
    app, operator_root = _new_app(tmp_path, operator_service=fake)
    _create_operator(operator_root, "op_a")
    token = _login(app, "op_a")

    resp = app.handle(
        APIRequest(
            method="POST",
            path="/v1/admin/tenants/register",
            headers={"Authorization": f"Bearer {token}"},
            json_body={
                "operator_id": "forged_operator",
                "institution_name": "Demo Bank",
                "main_url": "https://demo.bank",
                "seed_endpoints": ["demo.bank:443"],
                "password": "TenantPass123!",
            },
        )
    )

    assert resp.status_code == 403
    assert len(fake.tenant_calls) == 0


def test_phase5_tenant_register_accepts_missing_password_for_onboarding(tmp_path: Path) -> None:
    fake = _FakeOperatorService(operator_calls=[], tenant_calls=[], user_list_calls=[], user_delete_calls=[], user_password_change_calls=[], workspace_reset_calls=[], self_delete_calls=[])
    app, operator_root = _new_app(tmp_path, operator_service=fake)
    _create_operator(operator_root, "op_a")
    token = _login(app, "op_a")

    resp = app.handle(
        APIRequest(
            method="POST",
            path="/v1/admin/tenants/register",
            headers={"Authorization": f"Bearer {token}"},
            json_body={
                "institution_name": "Demo Bank",
                "main_url": "https://demo.bank",
            },
        )
    )

    assert resp.status_code == 403
    assert len(fake.tenant_calls) == 0


def test_phase5_operator_admin_endpoints_fail_when_service_not_configured(tmp_path: Path) -> None:
    app, operator_root = _new_app(tmp_path, operator_service=None)
    _create_operator(operator_root, "op_a")
    token = _login(app, "op_a")

    resp = app.handle(
        APIRequest(
            method="POST",
            path="/v1/admin/tenants/register",
            headers={"Authorization": f"Bearer {token}"},
            json_body={
                "institution_name": "Demo Bank",
                "main_url": "https://demo.bank",
                "password": "TenantPass123!",
            },
        )
    )
    assert resp.status_code == 403
    assert resp.payload["error"]["message"] == "additional tenant creation is not permitted"


def test_phase5_admin_users_list_and_delete_routes(tmp_path: Path) -> None:
    fake = _FakeOperatorService(operator_calls=[], tenant_calls=[], user_list_calls=[], user_delete_calls=[], user_password_change_calls=[], workspace_reset_calls=[], self_delete_calls=[])
    app, operator_root = _new_app(tmp_path, operator_service=fake)
    _create_operator(operator_root, "op_a")
    _link_operator(operator_root, "op_a")
    token = _login(app, "op_a")

    listed = app.handle(
        APIRequest(
            method="GET",
            path="/v1/admin/users",
            headers={"Authorization": f"Bearer {token}"},
        )
    )
    assert listed.status_code == 200
    assert len(fake.user_list_calls) == 1
    assert listed.payload["data"]["users"][0]["operator_id"] == "op_a"

    deleted = app.handle(
        APIRequest(
            method="DELETE",
            path="/v1/admin/users/op_b",
            headers={"Authorization": f"Bearer {token}"},
            json_body={"current_password": "StrongPassword123!"},
        )
    )
    assert deleted.status_code == 200
    assert len(fake.user_delete_calls) == 1
    assert fake.user_delete_calls[0]["target_operator_id"] == "op_b"


def test_phase5_admin_user_change_password_route(tmp_path: Path) -> None:
    fake = _FakeOperatorService(operator_calls=[], tenant_calls=[], user_list_calls=[], user_delete_calls=[], user_password_change_calls=[], workspace_reset_calls=[], self_delete_calls=[])
    app, operator_root = _new_app(tmp_path, operator_service=fake)
    _create_operator(operator_root, "op_a")
    _link_operator(operator_root, "op_a")
    token = _login(app, "op_a")

    changed = app.handle(
        APIRequest(
            method="POST",
            path="/v1/admin/users/op_b/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json_body={"current_password": "StrongPassword123!", "new_password": "ChangedPassword123!"},
        )
    )
    assert changed.status_code == 200
    assert len(fake.user_password_change_calls) == 1
    assert fake.user_password_change_calls[0]["target_operator_id"] == "op_b"


def test_phase5_workspace_reset_route(tmp_path: Path) -> None:
    fake = _FakeOperatorService(operator_calls=[], tenant_calls=[], user_list_calls=[], user_delete_calls=[], user_password_change_calls=[], workspace_reset_calls=[], self_delete_calls=[])
    app, operator_root = _new_app(tmp_path, operator_service=fake)
    _create_operator(operator_root, "op_a")
    _link_operator(operator_root, "op_a")
    token = _login(app, "op_a")

    reset = app.handle(
        APIRequest(
            method="POST",
            path="/v1/admin/workspace/reset",
            headers={"Authorization": f"Bearer {token}"},
            json_body={"current_password": "StrongPassword123!"},
        )
    )
    assert reset.status_code == 200
    assert len(fake.workspace_reset_calls) == 1
    assert fake.workspace_reset_calls[0]["operator_id"] == "op_a"


def test_phase5_delete_current_user_route(tmp_path: Path) -> None:
    fake = _FakeOperatorService(operator_calls=[], tenant_calls=[], user_list_calls=[], user_delete_calls=[], user_password_change_calls=[], workspace_reset_calls=[], self_delete_calls=[])
    app, operator_root = _new_app(tmp_path, operator_service=fake)
    _create_operator(operator_root, "op_a")
    _link_operator(operator_root, "op_a")
    token = _login(app, "op_a")

    deleted = app.handle(
        APIRequest(
            method="DELETE",
            path="/v1/admin/me",
            headers={"Authorization": f"Bearer {token}"},
            json_body={"current_password": "StrongPassword123!"},
        )
    )
    assert deleted.status_code == 200
    assert len(fake.self_delete_calls) == 1
    assert fake.self_delete_calls[0]["operator_id"] == "op_a"
