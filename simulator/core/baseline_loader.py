"""
Baseline Loader Interface + Filesystem Implementation
=====================================================

Read-only interface for loading baseline snapshots.

No writes are permitted from this component.
"""

from __future__ import annotations

from typing import Protocol, Dict, Any, Optional
from pathlib import Path
import json

from simulator.core.sandbox_state import BaselineBundle


class BaselineLoader(Protocol):
    """
    Read-only baseline loader interface.

    Implementations must be deterministic and must not write
    to production storage.
    """

    def load_baseline(
        self,
        tenant_id: str,
        cycle_id: str,
    ) -> BaselineBundle:
        """Load baseline snapshots for a given tenant/cycle."""
        ...


class BaselineFilesystemLoader:
    """
    Filesystem-based baseline loader (read-only).

    Reads snapshots from the production storage layout without
    mutating any runtime state.
    """

    def __init__(self, production_root: str):
        self.production_root = Path(production_root)

    def load_baseline(self, tenant_id: str, cycle_id: str) -> BaselineBundle:
        tenant_id = str(tenant_id or "").strip()
        cycle_id = str(cycle_id or "").strip()
        if not tenant_id:
            raise ValueError("tenant_id cannot be empty")
        if not cycle_id:
            raise ValueError("cycle_id cannot be empty")
        if any(sep in tenant_id for sep in ("/", "\\", "..")):
            raise ValueError("Invalid tenant_id path sequence")
        if any(sep in cycle_id for sep in ("/", "\\", "..")):
            raise ValueError("Invalid cycle_id path sequence")

        tenant_path = self.production_root / "tenant_data_storage" / "tenants" / tenant_id
        if not tenant_path.exists():
            raise FileNotFoundError(f"Tenant not found: {tenant_id}")

        layer0_snapshot = self._read_json(
            tenant_path / "snapshots" / f"{cycle_id}.json",
            required=True,
            label="layer0_snapshot",
        )

        trust_graph_snapshot = self._load_trust_graph_snapshot(tenant_path, cycle_id)

        layer3_snapshot = self._read_json(
            tenant_path / "layer3_state" / "layer3_state_snapshot.json",
            required=False,
            label="layer3_snapshot",
        )

        return BaselineBundle(
            layer0_snapshot=layer0_snapshot,
            trust_graph_snapshot=trust_graph_snapshot,
            layer3_snapshot=layer3_snapshot,
        )

    def _load_trust_graph_snapshot(self, tenant_path: Path, cycle_id: str) -> Dict[str, Any]:
        graph_dir = tenant_path / "trust_graph"
        by_cycle = graph_dir / f"{cycle_id}.json"
        latest = graph_dir / "latest.json"

        if by_cycle.exists():
            return self._read_json(by_cycle, required=True, label="trust_graph_snapshot")

        if latest.exists():
            return self._read_json(latest, required=True, label="trust_graph_snapshot")

        raise FileNotFoundError("TrustGraph snapshot not found for tenant")

    def _read_json(self, path: Path, *, required: bool, label: str) -> Optional[Dict[str, Any]]:
        if not path.exists():
            if required:
                raise FileNotFoundError(f"Missing {label}: {path}")
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
