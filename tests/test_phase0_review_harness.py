from __future__ import annotations

from pathlib import Path


def test_pytest_ini_network_marker_and_default_filter_present() -> None:
    config_path = Path("pytest.ini")
    assert config_path.exists()

    content = config_path.read_text(encoding="utf-8")
    normalized = content.replace("\r\n", "\n")

    assert "markers" in normalized
    assert "network: requires external network targets" in normalized
    assert 'addopts = -m "not network"' in normalized


def test_real_world_tests_are_network_marked() -> None:
    targets = [
        Path("tests/test_real_world_banconal_e2e.py"),
        Path("tests/test_banconal_dual_phase_expansion.py"),
        Path("tests/test_bank_indonesia_resilient_expansion.py"),
        Path("tests/test_banxico_expansion_A_only.py"),
        Path("tests/test_banxico_expansion_BCDE_only.py"),
        Path("tests/test_banxico_category_a_diagnostic.py"),
    ]

    for path in targets:
        assert path.exists(), f"missing expected real-world test file: {path}"
        content = path.read_text(encoding="utf-8")
        assert "pytest.mark.network" in content, f"network marker missing in {path}"
