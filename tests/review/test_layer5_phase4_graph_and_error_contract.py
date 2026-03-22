from __future__ import annotations

from pathlib import Path


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_phase4_graph_viewer_contract_tokens_present() -> None:
    viewer = _read("layers/layer5_interface_ui_ux/src/components/GraphViewer.tsx")
    model = _read("layers/layer5_interface_ui_ux/src/components/graph-model.ts")
    for token in [
        "Graph unavailable for this cycle",
        "Graph payload invalid",
        "MAX_RENDER_NODES",
        "MAX_RENDER_EDGES",
        "buildDeterministicLayout",
        "setSelectedNodeId",
        "setSelectedEdgeId",
    ]:
        assert token in viewer
    assert "seededRandom" in model


def test_phase4_app_uses_graph_viewer_and_error_states() -> None:
    app = _read("layers/layer5_interface_ui_ux/src/App.tsx")
    graph_page = _read("layers/layer5_interface_ui_ux/src/pages/GraphPage.tsx")
    endpoint_page = _read("layers/layer5_interface_ui_ux/src/pages/EndpointDetailPage.tsx")
    connector = _read("layers/layer5_interface_ui_ux/data_source/data_connector_to_ui.ts")
    assert 'path="/graph"' in app
    assert "<GraphViewer" in graph_page
    assert "No trust graph data. Run a scan to build the graph." in graph_page
    assert "No trust graph data available for this cycle." in endpoint_page
    assert "network_error" in connector


def test_phase4_cycle_deep_dive_tabs_include_guardian_and_graph() -> None:
    body = _read("layers/layer5_interface_ui_ux/src/pages/CycleDetailPage.tsx")
    for token in [
        '"guardian"',
        '"graph"',
        "Guardian Records",
        "Trust Graph",
        "No guardian records in this bundle.",
        "No trust graph snapshot in this bundle.",
    ]:
        assert token in body
