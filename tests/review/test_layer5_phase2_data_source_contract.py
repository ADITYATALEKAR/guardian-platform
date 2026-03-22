from __future__ import annotations

from pathlib import Path


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_phase2_data_connector_contains_phase1_endpoints() -> None:
    body = _read("layers/layer5_interface_ui_ux/data_source/data_connector_to_ui.ts")

    required_routes = [
        "/v1/auth/login",
        "/v1/auth/logout",
        "/v1/auth/me",
        "/v1/tenants/${encodeURIComponent(tenantId)}/dashboard",
        "/v1/tenants/${encodeURIComponent(tenantId)}/endpoints",
        "/v1/tenants/${encodeURIComponent(tenantId)}/endpoints/${encodeURIComponent(entityId)}",
        "/v1/tenants/${encodeURIComponent(tenantId)}/cycles",
        "/v1/tenants/${encodeURIComponent(tenantId)}/cycles/${encodeURIComponent(cycleId)}/bundle",
        "/v1/tenants/${encodeURIComponent(tenantId)}/cycles/${encodeURIComponent(cycleId)}/telemetry",
        "/v1/tenants/${encodeURIComponent(tenantId)}/simulations",
        "/v1/tenants/${encodeURIComponent(tenantId)}/simulations/${encodeURIComponent(simulationId)}",
    ]
    for route in required_routes:
        assert route in body


def test_phase2_master_connector_is_session_scoped() -> None:
    body = _read("layers/layer5_interface_ui_ux/data_source/master_data_connector_to_layer4.ts")
    assert "private session: SessionState | null = null;" in body
    assert "requireSession()" in body
    assert "getEndpointPage(" in body
    assert "getEndpointDetail(" in body
    assert "getAllEndpointPages(" in body
    assert "listCycles(" in body
    assert "getCycleBundle(" in body
    assert "getCycleTelemetry(" in body
    assert "getAllCycleTelemetry(" in body
    assert "getSimulationDetail(" in body


def test_phase2_tsconfig_and_typecheck_script_present() -> None:
    tsconfig = Path("layers/layer5_interface_ui_ux/tsconfig.json")
    assert tsconfig.exists()
    pkg = _read("layers/layer5_interface_ui_ux/package.json")
    assert "\"typecheck\"" in pkg
