from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from infrastructure.storage_manager.storage_manager import StorageManager

from ...io import atomic_write_json, policy_root, read_json_fail_loud
from .policy_update_plan import PolicyUpdatePlan


def _safe_str(value: object, default: str = "") -> str:
    token = str(value or "").strip()
    return token if token else default


@dataclass(frozen=True)
class PolicyUpdatePlanStore:
    storage_manager: StorageManager
    tenant_id: str

    def _path(self) -> Path:
        root = policy_root(self.storage_manager, self.tenant_id)
        updates_dir = root / "updates"
        updates_dir.mkdir(parents=True, exist_ok=True)
        return updates_dir / "plans.json"

    def list_plans(self) -> List[PolicyUpdatePlan]:
        path = self._path()
        if not path.exists():
            return []
        payload = read_json_fail_loud(path, context="policy update plans")
        items = payload.get("plans", [])
        if not isinstance(items, list):
            raise RuntimeError("corrupt policy update plans")

        plans: List[PolicyUpdatePlan] = []
        for item in items:
            if not isinstance(item, dict):
                raise RuntimeError("corrupt policy update plans")
            plans.append(PolicyUpdatePlan(**item))

        plans.sort(key=lambda p: (-int(p.created_ts_ms), p.plan_id))
        return plans

    def get_plan(self, plan_id: str) -> Optional[PolicyUpdatePlan]:
        pid = _safe_str(plan_id)
        if not pid:
            return None
        for plan in self.list_plans():
            if plan.plan_id == pid:
                return plan
        return None

    def upsert_plan(self, plan: PolicyUpdatePlan) -> None:
        current = [p.to_dict() for p in self.list_plans() if p.plan_id != plan.plan_id]
        current.append(plan.to_dict())
        current.sort(key=lambda d: (-int(d.get("created_ts_ms", 0)), str(d.get("plan_id", ""))))
        atomic_write_json(
            self._path(),
            {
                "tenant_id": _safe_str(self.tenant_id, "unknown"),
                "plans": current,
            },
        )

    def delete_plan(self, plan_id: str) -> bool:
        pid = _safe_str(plan_id)
        if not pid:
            return False
        existing = self.list_plans()
        kept = [p for p in existing if p.plan_id != pid]
        removed = len(kept) != len(existing)
        if removed:
            atomic_write_json(
                self._path(),
                {
                    "tenant_id": _safe_str(self.tenant_id, "unknown"),
                    "plans": [p.to_dict() for p in kept],
                },
            )
        return removed
