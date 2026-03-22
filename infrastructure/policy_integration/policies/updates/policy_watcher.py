from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from infrastructure.storage_manager.storage_manager import StorageManager

from ...io import atomic_write_json, policy_root, read_json_fail_loud
from ..sources.policy_source_pack import PolicySourcePack


@dataclass(frozen=True)
class PolicyPackChange:
    jurisdiction_code: str
    old_hash: str
    new_hash: str
    old_version: str
    new_version: str


@dataclass(frozen=True)
class PolicyWatcher:
    storage_manager: StorageManager
    tenant_id: str

    def _snapshot_path(self) -> Path:
        root = policy_root(self.storage_manager, self.tenant_id)
        updates_dir = root / "updates"
        updates_dir.mkdir(parents=True, exist_ok=True)
        return updates_dir / "policy_pack_snapshot.json"

    def _load_snapshot(self) -> Dict[str, Dict[str, str]]:
        path = self._snapshot_path()
        if not path.exists():
            return {}
        payload = read_json_fail_loud(path, context="policy pack snapshot")
        if not isinstance(payload, dict):
            raise RuntimeError("corrupt policy pack snapshot")
        return payload

    def _save_snapshot(self, snapshot: Dict[str, Dict[str, str]]) -> None:
        atomic_write_json(self._snapshot_path(), snapshot)

    def detect_changes(self, packs: List[PolicySourcePack]) -> List[PolicyPackChange]:
        snapshot = self._load_snapshot()
        changes: List[PolicyPackChange] = []

        for pack in packs if isinstance(packs, list) else []:
            if not isinstance(pack, PolicySourcePack):
                raise RuntimeError("invalid policy source pack")

            code = str(pack.jurisdiction_code).strip().upper()
            if not code:
                continue

            new_hash = pack.stable_hash()
            new_version = str(pack.version).strip() or "unknown"

            previous = snapshot.get(code)
            if previous is None:
                snapshot[code] = {"hash": new_hash, "version": new_version}
                continue
            if not isinstance(previous, dict):
                raise RuntimeError("corrupt policy pack snapshot")

            old_hash = str(previous.get("hash", "")).strip()
            old_version = str(previous.get("version", "")).strip() or "unknown"
            if old_hash != new_hash:
                changes.append(
                    PolicyPackChange(
                        jurisdiction_code=code,
                        old_hash=old_hash,
                        new_hash=new_hash,
                        old_version=old_version,
                        new_version=new_version,
                    )
                )
                snapshot[code] = {"hash": new_hash, "version": new_version}

        self._save_snapshot(snapshot)
        return changes
