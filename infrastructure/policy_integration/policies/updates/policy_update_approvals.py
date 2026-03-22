from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

from infrastructure.storage_manager.storage_manager import StorageManager

from ...io import atomic_write_json, policy_root, read_json_fail_loud


def _safe_str(value: object, default: str = "") -> str:
    token = str(value or "").strip()
    return token if token else default


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(float(value))
    except Exception:
        return default


@dataclass(frozen=True)
class PolicyUpdateApprovalStore:
    storage_manager: StorageManager
    tenant_id: str

    def _path(self) -> Path:
        root = policy_root(self.storage_manager, self.tenant_id)
        updates_dir = root / "updates"
        updates_dir.mkdir(parents=True, exist_ok=True)
        return updates_dir / "approvals.json"

    def _load(self) -> Dict[str, Any]:
        path = self._path()
        if not path.exists():
            return {"tenant_id": _safe_str(self.tenant_id, "unknown"), "states": {}}
        payload = read_json_fail_loud(path, context="policy update approvals")
        states = payload.get("states", {})
        if not isinstance(states, dict):
            raise RuntimeError("corrupt policy update approvals")
        return payload

    def _save(self, payload: Dict[str, Any]) -> None:
        states = payload.get("states", {})
        if not isinstance(states, dict):
            raise RuntimeError("corrupt policy update approvals")
        payload["tenant_id"] = _safe_str(self.tenant_id, "unknown")
        atomic_write_json(self._path(), payload)

    def get_state(self, plan_id: str) -> Dict[str, Any]:
        key = _safe_str(plan_id)
        if not key:
            return {}
        states = self._load()["states"]
        state = states.get(key, {})
        if not isinstance(state, dict):
            raise RuntimeError("corrupt policy update approvals")
        return state

    def _set_state(self, plan_id: str, state: Dict[str, Any]) -> None:
        key = _safe_str(plan_id)
        if not key:
            raise RuntimeError("invalid plan_id")
        payload = self._load()
        states = payload["states"]
        states[key] = state
        payload["states"] = states
        self._save(payload)

    def mark_detected(self, plan_id: str, ts_ms: int) -> None:
        self._set_state(
            plan_id,
            {"plan_id": _safe_str(plan_id), "status": "detected", "ts_detected_ms": _safe_int(ts_ms)},
        )

    def approve(self, plan_id: str, *, approved_by: str = "unknown", reason: str = "", ts_ms: int = 0) -> None:
        state = self.get_state(plan_id)
        state.update(
            {
                "plan_id": _safe_str(plan_id),
                "status": "approved",
                "approved_by": _safe_str(approved_by, "unknown"),
                "reason": _safe_str(reason)[:512],
                "ts_approved_ms": _safe_int(ts_ms),
            }
        )
        self._set_state(plan_id, state)

    def reject(self, plan_id: str, *, rejected_by: str = "unknown", reason: str = "", ts_ms: int = 0) -> None:
        state = self.get_state(plan_id)
        state.update(
            {
                "plan_id": _safe_str(plan_id),
                "status": "rejected",
                "rejected_by": _safe_str(rejected_by, "unknown"),
                "reason": _safe_str(reason)[:512],
                "ts_rejected_ms": _safe_int(ts_ms),
            }
        )
        self._set_state(plan_id, state)

    def schedule_activation(
        self,
        plan_id: str,
        *,
        activation_ts_ms: int,
        effective_date_utc: str,
        ts_ms: int = 0,
    ) -> None:
        state = self.get_state(plan_id)
        state.update(
            {
                "plan_id": _safe_str(plan_id),
                "status": "scheduled",
                "scheduled_activation_ts_ms": _safe_int(activation_ts_ms),
                "effective_date_utc": _safe_str(effective_date_utc)[:16],
                "ts_scheduled_ms": _safe_int(ts_ms),
            }
        )
        self._set_state(plan_id, state)

    def mark_activated(self, plan_id: str, ts_ms: int) -> None:
        state = self.get_state(plan_id)
        state.update(
            {
                "plan_id": _safe_str(plan_id),
                "status": "activated",
                "ts_activated_ms": _safe_int(ts_ms),
            }
        )
        self._set_state(plan_id, state)
