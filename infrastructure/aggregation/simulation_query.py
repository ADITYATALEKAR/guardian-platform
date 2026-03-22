from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from simulator.storage.simulation_storage_manager import SimulationStorageManager


@dataclass(frozen=True)
class SimulationSummary:
    simulation_id: str
    tenant_id: str
    baseline_cycle_id: Optional[str]
    scenario_id: Optional[str]
    status: str
    created_at_unix_ms: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "simulation_id": self.simulation_id,
            "tenant_id": self.tenant_id,
            "baseline_cycle_id": self.baseline_cycle_id,
            "scenario_id": self.scenario_id,
            "status": self.status,
            "created_at_unix_ms": self.created_at_unix_ms,
        }


@dataclass(frozen=True)
class SimulationPage:
    tenant_id: str
    page: int
    page_size: int
    total: int
    rows: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "page": self.page,
            "page_size": self.page_size,
            "total": self.total,
            "rows": list(self.rows),
        }


class SimulationQueryService:
    """
    Read-only simulation listing by artifact metadata.

    Reads simulation payloads and returns deterministic summaries.
    """

    def __init__(self, simulation_root: str):
        self._mgr = SimulationStorageManager(simulation_root)

    def list_simulations(
        self,
        tenant_id: str,
        *,
        page: int = 1,
        page_size: int = 100,
    ) -> SimulationPage:
        tid = str(tenant_id or "").strip()
        p = max(1, int(page))
        size = max(1, min(int(page_size), 1000))

        tenant_path = self._mgr.get_tenant_path(tid)
        sim_dir = tenant_path / "simulations"
        if not sim_dir.exists():
            return SimulationPage(tenant_id=tid, page=p, page_size=size, total=0, rows=[])

        rows: List[SimulationSummary] = []
        for path in sorted(sim_dir.glob("*.json")):
            rows.append(self._read_summary(tid, path))

        rows.sort(
            key=lambda row: (
                -int(row.created_at_unix_ms),
                row.simulation_id,
            )
        )

        total = len(rows)
        start = (p - 1) * size
        end = start + size
        paged = rows[start:end]
        return SimulationPage(
            tenant_id=tid,
            page=p,
            page_size=size,
            total=total,
            rows=[row.to_dict() for row in paged],
        )

    def get_simulation(
        self,
        tenant_id: str,
        simulation_id: str,
    ) -> Dict[str, Any]:
        tid = str(tenant_id or "").strip()
        sim_id = str(simulation_id or "").strip()
        if not tid:
            raise ValueError("tenant_id")
        if not sim_id:
            raise ValueError("simulation_id")

        tenant_path = self._mgr.get_tenant_path(tid)
        path = tenant_path / "simulations" / f"{sim_id}.json"
        if not path.exists():
            raise RuntimeError("simulation not found")

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise RuntimeError("corrupt simulation payload") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("corrupt simulation payload")
        return payload

    def _read_summary(self, tenant_id: str, path: Path) -> SimulationSummary:
        created_at = int(path.stat().st_mtime * 1000)
        default_sim_id = path.stem

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("invalid payload")
        except Exception:
            return SimulationSummary(
                simulation_id=default_sim_id,
                tenant_id=tenant_id,
                baseline_cycle_id=None,
                scenario_id=None,
                status="corrupt",
                created_at_unix_ms=created_at,
            )

        sim_id = str(payload.get("simulation_id", default_sim_id)).strip() or default_sim_id
        return SimulationSummary(
            simulation_id=sim_id,
            tenant_id=str(payload.get("tenant_id", tenant_id)),
            baseline_cycle_id=payload.get("baseline_cycle_id"),
            scenario_id=payload.get("scenario_id"),
            status="completed",
            created_at_unix_ms=created_at,
        )
