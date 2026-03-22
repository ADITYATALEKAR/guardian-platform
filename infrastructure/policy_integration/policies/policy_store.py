from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from infrastructure.storage_manager.storage_manager import StorageManager

from ..io import (
    atomic_write_json,
    list_json_files_sorted,
    policy_root,
    read_json_fail_loud,
    stable_dedupe_sorted,
)
from .policy_utils import safe_str


@dataclass(frozen=True)
class PolicyStoreConfig:
    max_items_per_list: int = 2048


class PolicyStore:
    def __init__(
        self,
        *,
        storage_manager: StorageManager,
        tenant_id: str,
        config: Optional[PolicyStoreConfig] = None,
    ) -> None:
        self._storage_manager = storage_manager
        self._tenant_id = safe_str(tenant_id)
        if not self._tenant_id:
            raise RuntimeError("invalid tenant_id")
        self._config = config or PolicyStoreConfig()

    def _root(self) -> Path:
        return policy_root(self._storage_manager, self._tenant_id)

    def _proposed_dir(self) -> Path:
        path = self._root() / "proposed_policies"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _approved_dir(self) -> Path:
        path = self._root() / "approved_policies"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def save_proposed_policy(self, policy: Dict[str, Any]) -> str:
        if not isinstance(policy, dict):
            raise TypeError("policy must be a dict")
        policy_id = safe_str(policy.get("policy_id") or policy.get("id"))
        if not policy_id:
            raise RuntimeError("proposed policy requires policy_id")

        payload = dict(policy)
        payload["policy_id"] = policy_id
        payload["status"] = "proposed"
        payload["tags"] = stable_dedupe_sorted(payload.get("tags", []))

        atomic_write_json(self._proposed_dir() / f"{policy_id}.json", payload)
        return policy_id

    def list_proposed_policies(self) -> List[Dict[str, Any]]:
        return self._list_from_dir(self._proposed_dir())

    def save_approved_policy(self, policy: Dict[str, Any]) -> str:
        if not isinstance(policy, dict):
            raise TypeError("policy must be a dict")
        policy_id = safe_str(policy.get("policy_id") or policy.get("id"))
        if not policy_id:
            raise RuntimeError("approved policy requires policy_id")

        payload = dict(policy)
        payload["policy_id"] = policy_id
        payload["status"] = "approved"
        payload["tags"] = stable_dedupe_sorted(payload.get("tags", []))
        atomic_write_json(self._approved_dir() / f"{policy_id}.json", payload)
        return policy_id

    def list_approved_policies(self) -> List[Dict[str, Any]]:
        return self._list_from_dir(self._approved_dir())

    def _list_from_dir(self, directory: Path) -> List[Dict[str, Any]]:
        files = list_json_files_sorted(directory, limit=self._config.max_items_per_list)
        out: List[Dict[str, Any]] = []
        for path in files:
            out.append(read_json_fail_loud(path, context=f"policy file {path.name}"))
        return out
