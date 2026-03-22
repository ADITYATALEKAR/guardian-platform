from __future__ import annotations

from pathlib import Path

from infrastructure.layer5_api import APIRequest, Layer5BootstrapConfig, build_layer5_runtime_bundle


def test_phase5_bootstrap_wires_operator_service_into_layer5_api(tmp_path: Path) -> None:
    bundle = build_layer5_runtime_bundle(
        Layer5BootstrapConfig(
            storage_root=str(tmp_path / "storage"),
            operator_storage_root=str(tmp_path / "operator_storage"),
            simulation_root=str(tmp_path / "simulation_root"),
        )
    )

    # With full wiring present, operator register endpoint should no longer return 501.
    resp = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/admin/operators/register",
            json_body={
                "operator_id": "op_bootstrap",
                "email": "bootstrap@example.com",
                "password": "StrongPassword123!",
                "created_at_unix_ms": 1_710_000_000_000,
                "master_password": "wrong",
            },
        )
    )
    assert resp.status_code in {200, 403, 409}
    assert resp.status_code != 501


def test_phase5_master_password_allows_operator_registration_without_session_after_bootstrap(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("OPERATOR_MASTER_PASSWORD", "master-secret")
    bundle = build_layer5_runtime_bundle(
        Layer5BootstrapConfig(
            storage_root=str(tmp_path / "storage"),
            operator_storage_root=str(tmp_path / "operator_storage"),
            simulation_root=str(tmp_path / "simulation_root"),
        )
    )

    first = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/admin/operators/register",
            json_body={
                "operator_id": "op_bootstrap",
                "email": "bootstrap@example.com",
                "password": "StrongPassword123!",
                "created_at_unix_ms": 1_710_000_000_000,
                "master_password": "master-secret",
            },
        )
    )
    assert first.status_code == 200

    second = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/admin/operators/register",
            json_body={
                "operator_id": "op_second",
                "email": "second@example.com",
                "password": "StrongPassword123!",
                "created_at_unix_ms": 1_710_000_000_100,
                "master_password": "master-secret",
            },
        )
    )
    assert second.status_code == 200


def test_phase5_operator_registration_rejects_duplicate_email(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPERATOR_MASTER_PASSWORD", "master-secret")
    bundle = build_layer5_runtime_bundle(
        Layer5BootstrapConfig(
            storage_root=str(tmp_path / "storage"),
            operator_storage_root=str(tmp_path / "operator_storage"),
            simulation_root=str(tmp_path / "simulation_root"),
        )
    )

    first = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/admin/operators/register",
            json_body={
                "operator_id": "op_one",
                "email": "same@example.com",
                "password": "StrongPassword123!",
                "created_at_unix_ms": 1_710_000_000_000,
                "master_password": "master-secret",
            },
        )
    )
    assert first.status_code == 200

    duplicate = bundle.api.handle(
        APIRequest(
            method="POST",
            path="/v1/admin/operators/register",
            json_body={
                "operator_id": "op_two",
                "email": "same@example.com",
                "password": "StrongPassword123!",
                "created_at_unix_ms": 1_710_000_000_100,
                "master_password": "master-secret",
            },
        )
    )
    assert duplicate.status_code == 409
