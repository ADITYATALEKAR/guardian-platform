from __future__ import annotations

from pathlib import Path


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_phase5_cycle_views_surface_reporting_metrics_without_new_backend_contracts() -> None:
    body = _read("layers/layer5_interface_ui_ux/src/pages/CycleDetailPage.tsx")
    for token in [
        "meta.build_stats",
        "total_discovered_domains",
        "total_successful_observations",
        "total_failed_observations",
        "Duplicates Merged",
        "Avg Crypto Health",
        "Avg Protection Posture",
    ]:
        assert token in body


def test_phase5_findings_views_surface_existing_posture_finding_payloads() -> None:
    findings_page = _read("layers/layer5_interface_ui_ux/src/pages/FindingsPage.tsx")
    dashboard = _read("layers/layer5_interface_ui_ux/src/pages/DashboardPage.tsx")
    extractors = _read("layers/layer5_interface_ui_ux/src/lib/extractors.ts")
    for token in [
        'recordType: "posture_findings"',
        "tls_findings_count",
        "waf_findings_count",
    ]:
        assert token in findings_page or token in dashboard
    for token in ["waf_findings", "tls_findings", "quantum_ready"]:
        assert token in extractors or token in dashboard


def test_phase5_preserves_unknown_and_quantum_semantics() -> None:
    dashboard = _read("layers/layer5_interface_ui_ux/src/pages/DashboardPage.tsx")
    formatters = _read("layers/layer5_interface_ui_ux/src/lib/formatters.ts")
    for token in [
        "var(--color-severity-unknown)",
        "var(--color-quantum-ready)",
        "var(--color-quantum-not-ready)",
        "var(--color-quantum-unknown)",
    ]:
        assert token in dashboard or token in formatters


def test_phase5_operator_admin_and_exports_are_wired() -> None:
    settings = _read("layers/layer5_interface_ui_ux/src/pages/SettingsPage.tsx")
    cycle_detail = _read("layers/layer5_interface_ui_ux/src/pages/CycleDetailPage.tsx")
    simulation_detail = _read("layers/layer5_interface_ui_ux/src/pages/SimulationDetailPage.tsx")
    findings = _read("layers/layer5_interface_ui_ux/src/pages/FindingsPage.tsx")
    endpoints = _read("layers/layer5_interface_ui_ux/src/pages/EndpointsPage.tsx")
    connector = _read("layers/layer5_interface_ui_ux/data_source/data_connector_to_ui.ts")

    for token in [
        '"admin"',
        "registerOperator",
        "registerTenant",
    ]:
        assert token in settings or token in connector

    for token in ["downloadJson(", "downloadCsv("]:
        assert token in cycle_detail or token in simulation_detail or token in findings or token in endpoints

    for token in [
        "/v1/admin/operators/register",
        "/v1/admin/tenants/register",
    ]:
        assert token in connector
