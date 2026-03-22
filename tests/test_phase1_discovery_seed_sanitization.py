from __future__ import annotations

from pathlib import Path

import pytest

from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.storage_manager.storage_manager import StorageManager


def _new_engine(tmp_path: Path) -> DiscoveryEngine:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    return DiscoveryEngine(storage=storage, max_endpoints=10, max_workers=1)


def test_resolve_roots_drops_invalid_explicit_seeds_and_keeps_valid_canonical(
    tmp_path: Path,
) -> None:
    engine = _new_engine(tmp_path)

    roots = engine._resolve_roots(
        tenant_id="tenant_a",
        explicit_seeds=[
            "https://WWW.example.com",
            "www.example.com:443",
            "http://api.example.com/path?q=1",
            "localhost:443",
            "",
            "   ",
            "not-a-domain",
            "[::1]:443",
            "https://example..com",
        ],
    )

    assert roots == [
        "api.example.com:80",
        "www.example.com:443",
    ]


def test_run_discovery_errors_when_all_explicit_seeds_invalid(tmp_path: Path) -> None:
    engine = _new_engine(tmp_path)

    with pytest.raises(RuntimeError, match="No discovery roots available"):
        engine.run_discovery(
            tenant_id="tenant_a",
            rate_controller=None,
            cycle_id="cycle_000001",
            seed_endpoints=["", "localhost", "[::1]:443", "not-a-domain"],
            expansion_mode="A_ONLY",
        )
