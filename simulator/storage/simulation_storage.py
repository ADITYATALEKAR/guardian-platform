"""
Simulation Storage
==================

Deterministic, isolated persistence for simulator outputs.

No production storage access.
Atomic write required.
"""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
from typing import Any, Dict, Optional

from simulator.storage.simulation_storage_manager import SimulationStorageManager


class SimulationStorage:
    """
    Deterministic storage for simulation artifacts.
    """

    def __init__(self, base_path: str):
        self._mgr = SimulationStorageManager(base_path)

    def compute_simulation_id(
        self,
        *,
        tenant_id: str,
        baseline_cycle_id: str,
        baseline_snapshot_hash: str,
        scenario_id: str,
        scenario_params: Dict[str, Any],
        mitigation_params: Optional[Dict[str, Any]] = None,
    ) -> str:
        payload = {
            "tenant_id": str(tenant_id),
            "baseline_cycle_id": str(baseline_cycle_id),
            "baseline_snapshot_hash": str(baseline_snapshot_hash),
            "scenario_id": str(scenario_id),
            "scenario_params": _sorted_json(scenario_params or {}),
            "mitigation_params": _sorted_json(mitigation_params or {}),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def load(self, tenant_id: str, sim_id: str) -> Optional[Dict[str, Any]]:
        tenant_path = self._mgr.get_tenant_path(tenant_id)
        path = tenant_path / "simulations" / f"{sim_id}.json"
        if not path.exists():
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def persist(self, tenant_id: str, sim_id: str, payload: Dict[str, Any]) -> None:
        tenant_path = self._mgr.ensure_tenant_exists(tenant_id)
        sim_dir = tenant_path / "simulations"
        sim_dir.mkdir(parents=True, exist_ok=True)

        path = sim_dir / f"{sim_id}.json"
        if path.exists():
            return

        tmp_path = sim_dir / f"{sim_id}.json.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, sort_keys=True, indent=2)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp_path, path)


def _sorted_json(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k in sorted(obj.keys()):
            out[str(k)] = _sorted_json(obj[k])
        return out
    if isinstance(obj, list):
        return [_sorted_json(v) for v in obj]
    return obj
