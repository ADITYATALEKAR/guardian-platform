from __future__ import annotations

from pathlib import Path

from infrastructure.layer5_api import APIRequest, Layer5BootstrapConfig, build_layer5_runtime_bundle


def test_phase5_register_login_onboard_scan_end_to_end(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPERATOR_MASTER_PASSWORD", "master-secret")
    bundle = build_layer5_runtime_bundle(
        Layer5BootstrapConfig(
            storage_root=str(tmp_path / "storage"),
            operator_storage_root=str(tmp_path / "operator_storage"),
            simulation_root=str(tmp_path / "simulation"),
        )
    )
    monkeypatch.setattr(bundle.orchestrator, "run_cycle", lambda _tenant_id: {"cycle_id": "cycle_stub"})

    register = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/register",
            json_body={
                "email": "phase5.user@example.com",
                "password": "StrongPassword123!",
                "master_password": "master-secret",
                "institution_name": "Phase5 Bank",
            },
        )
    )
    assert register.status_code == 200
    registered = register.payload["data"]
    tenant_id = str(registered["tenant_id"])
    assert tenant_id.startswith("tenant_")
    assert registered["onboarding_status"] == "PENDING"
    assert registered["cycle_started"] is False

    login = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/login",
            json_body={
                "operator_id": "phase5.user@example.com",
                "password": "StrongPassword123!",
            },
        )
    )
    assert login.status_code == 200
    session = login.payload["data"]
    token = str(session["session_token"])
    assert tenant_id in list(session["tenant_ids"])

    issued = int(session["issued_at_unix_ms"])
    expires = int(session["expires_at_unix_ms"])
    assert expires - issued == 60 * 60 * 1000

    dashboard_pending = bundle.api.handle(
        APIRequest(
            method="GET",
            path=f"/v1/tenants/{tenant_id}/dashboard",
            headers={"Authorization": f"Bearer {token}"},
        )
    )
    assert dashboard_pending.status_code == 200
    pending_workspace = dashboard_pending.payload["data"]["workspace"]
    assert pending_workspace["onboarding_status"] == "PENDING"
    assert pending_workspace["main_url"] == ""

    onboard = bundle.api.handle(
        APIRequest(
            method="POST",
            path=f"/v1/tenants/{tenant_id}/onboard-and-scan",
            headers={"Authorization": f"Bearer {token}"},
            json_body={
                "institution_name": "Phase5 Bank",
                "main_url": "https://www.phase5.bank",
                "seed_endpoints": ["www.phase5.bank:443", "api.phase5.bank:443"],
            },
        )
    )
    assert onboard.status_code == 200
    onboarded = onboard.payload["data"]
    assert onboarded["tenant_id"] == tenant_id
    assert onboarded["onboarding_status"] == "COMPLETED"
    assert onboarded["cycle_started"] is True

    dashboard_completed = bundle.api.handle(
        APIRequest(
            method="GET",
            path=f"/v1/tenants/{tenant_id}/dashboard",
            headers={"Authorization": f"Bearer {token}"},
        )
    )
    assert dashboard_completed.status_code == 200
    completed_workspace = dashboard_completed.payload["data"]["workspace"]
    assert completed_workspace["onboarding_status"] == "COMPLETED"
    assert completed_workspace["main_url"] == "https://www.phase5.bank"
    assert len(bundle.storage.load_seed_endpoints(tenant_id)) >= 2
    assert int(completed_workspace.get("onboarded_at_unix_ms", 0)) > 0
