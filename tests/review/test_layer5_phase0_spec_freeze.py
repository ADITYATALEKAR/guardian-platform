from __future__ import annotations

from pathlib import Path


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_layer5_phase0_spec_documents_exist() -> None:
    required = [
        "layers/layer5_interface_ui_ux/contracts/layer5-phase0-spec-freeze.md",
        "layers/layer5_interface_ui_ux/contracts/api-contract-v1.md",
        "layers/layer5_interface_ui_ux/contracts/interaction-rules.md",
        "layers/layer5_interface_ui_ux/contracts/graph-rendering-contract.md",
    ]
    for path in required:
        assert Path(path).exists(), path


def test_layer5_phase0_simulation_detail_contract_frozen() -> None:
    body = _read("layers/layer5_interface_ui_ux/contracts/api-contract-v1.md")
    assert "GET /v1/tenants/{tenant_id}/simulations/{sim_id}" in body


def test_layer5_phase0_bundle_telemetry_split_frozen() -> None:
    body = _read("layers/layer5_interface_ui_ux/contracts/api-contract-v1.md")
    assert "Cycle Bundle (snapshot-style)" in body
    assert "Cycle Telemetry (stream-style)" in body
    assert "Must NOT accept" in body
    assert "telemetry_page" in body


def test_layer5_phase0_error_matrix_frozen() -> None:
    body = _read("layers/layer5_interface_ui_ux/contracts/interaction-rules.md")
    for token in ["401", "403", "404", "409", "500", "timeout"]:
        assert token in body


def test_layer5_phase0_graph_contract_frozen() -> None:
    body = _read("layers/layer5_interface_ui_ux/contracts/graph-rendering-contract.md")
    for token in ["nodes", "edges", "deterministic force-directed", "Node click", "Edge click"]:
        assert token in body


def test_layer5_phase0_typography_and_semantics_locked() -> None:
    tokens = _read("layers/layer5_interface_ui_ux/contracts/design-tokens.css")
    assert "--font-primary: \"IBM Plex Sans\"" in tokens
    assert "--font-mono: \"IBM Plex Mono\"" in tokens
    assert "--font-size-micro: 11px" in tokens
    assert "--color-alert-unknown: #4A5568" in tokens
    assert "--color-quantum-ready: #00C853" in tokens
    assert "--color-quantum-not-ready: #FF6D00" in tokens
    assert "--color-quantum-unknown: #546E7A" in tokens
