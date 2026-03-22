from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from infrastructure.storage_manager.storage_manager import StorageManager

from ...io import atomic_write_json, policy_root
from .policy_update_approvals import PolicyUpdateApprovalStore


def _safe_str(value: object, default: str = "") -> str:
    token = str(value or "").strip()
    return token if token else default


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(float(value))
    except Exception:
        return default


@dataclass(frozen=True)
class PolicyUpdateExecutor:
    storage_manager: StorageManager
    tenant_id: str
    approvals: PolicyUpdateApprovalStore

    def _activation_request_path(self, plan_id: str) -> Path:
        root = policy_root(self.storage_manager, self.tenant_id)
        path = root / "updates" / "activation_requests"
        path.mkdir(parents=True, exist_ok=True)
        return path / f"{_safe_str(plan_id, 'unknown')}.json"

    def _all_states(self) -> Dict[str, Any]:
        return self.approvals._load().get("states", {})  # controlled internal reuse

    def execute_due_activations(self, *, now_ts_ms: int, max_to_execute: int = 32) -> List[str]:
        now_ms = _safe_int(now_ts_ms, 0)
        limit = min(max(0, int(max_to_execute)), 256)
        states = self._all_states()
        if not isinstance(states, dict):
            raise RuntimeError("corrupt policy update approvals")

        due: List[str] = []
        for plan_id, state in sorted(states.items(), key=lambda kv: str(kv[0])):
            if not isinstance(state, dict):
                raise RuntimeError("corrupt policy update approvals")
            if _safe_str(state.get("status")) != "scheduled":
                continue
            activation_ts = _safe_int(state.get("scheduled_activation_ts_ms"), 0)
            if activation_ts <= 0 or activation_ts > now_ms:
                continue
            due.append(_safe_str(plan_id))

        activated: List[str] = []
        for plan_id in due[:limit]:
            atomic_write_json(
                self._activation_request_path(plan_id),
                {
                    "tenant_id": _safe_str(self.tenant_id, "unknown"),
                    "plan_id": plan_id,
                    "kind": "policy_update_activation_request",
                    "requested_activation_ts_ms": now_ms,
                },
            )
            self.approvals.mark_activated(plan_id, now_ms)
            activated.append(plan_id)
        return activated
