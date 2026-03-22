from __future__ import annotations

from pathlib import Path


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_phase3_vite_root_entry_present() -> None:
    body = _read("layers/layer5_interface_ui_ux/index.html")
    assert 'id="root"' in body
    assert "/src/main.tsx" in body


def test_phase3_main_renders_app() -> None:
    body = _read("layers/layer5_interface_ui_ux/src/main.tsx")
    assert "createRoot" in body
    assert "<App />" in body


def test_phase3_app_has_required_console_tabs_and_error_paths() -> None:
    app = _read("layers/layer5_interface_ui_ux/src/App.tsx")
    connector = _read("layers/layer5_interface_ui_ux/data_source/data_connector_to_ui.ts")
    for token in [
        'path="/dashboard"',
        'path="/endpoints"',
        'path="/cycles/:cycleId/telemetry"',
        'path="/graph"',
        'path="/simulator"',
    ]:
        assert token in app
    for token in ["network_error", "invalid_payload", "request timeout"]:
        assert token in connector


def test_phase3_login_surface_exposes_signin_register_only_entry_modes() -> None:
    layout = _read("layers/layer5_interface_ui_ux/src/layouts/AuthLayout.tsx")
    login = _read("layers/layer5_interface_ui_ux/src/pages/LoginPage.tsx")
    register = _read("layers/layer5_interface_ui_ux/src/pages/RegisterPage.tsx")
    for token in ["Welcome to Guardian", "Guardian", "Sign In", "Register"]:
        assert token in layout
    for token in ["User ID", "Password"]:
        assert token in login
    for token in ["Activation Key", "Create Account"]:
        assert token in register


def test_phase3_quantum_and_unknown_semantics_are_rendered() -> None:
    dashboard = _read("layers/layer5_interface_ui_ux/src/pages/DashboardPage.tsx")
    formatters = _read("layers/layer5_interface_ui_ux/src/lib/formatters.ts")
    assert "var(--color-severity-unknown)" in formatters
    assert "var(--color-quantum-ready)" in dashboard
    assert "var(--color-quantum-not-ready)" in dashboard
    assert "var(--color-quantum-unknown)" in dashboard
