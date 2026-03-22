"""
Simulation Storage Manager
==========================

Isolated storage manager for simulator artifacts.

Guarantees:
- Uses simulation_storage root only
- Never touches production tenant_data_storage
- Deterministic directory layout
"""

import shutil
from pathlib import Path


class SimulationStorageManager:
    """
    Storage manager for simulator artifacts only.

    This class is intentionally isolated from the runtime StorageManager.
    It must never reference production storage paths.
    """

    def __init__(self, base_path: str):
        self.base_path = Path(base_path)
        self.tenants_dir = self.base_path / "tenants"
        self.tenants_dir.mkdir(parents=True, exist_ok=True)

    def ensure_tenant_exists(self, tenant_id: str) -> Path:
        tid = str(tenant_id or "").strip()
        if not tid:
            raise ValueError("tenant_id cannot be empty")
        if any(sep in tid for sep in ("/", "\\", "..")):
            raise ValueError("Invalid tenant_id path sequence")
        tenant_path = self.tenants_dir / tid
        tenant_path.mkdir(parents=True, exist_ok=True)
        return tenant_path

    def get_tenant_path(self, tenant_id: str) -> Path:
        return self.ensure_tenant_exists(tenant_id)

    def delete_tenant(self, tenant_id: str) -> None:
        tid = str(tenant_id or "").strip()
        if not tid:
            raise ValueError("tenant_id cannot be empty")
        if any(sep in tid for sep in ("/", "\\", "..")):
            raise ValueError("Invalid tenant_id path sequence")
        tenant_path = self.tenants_dir / tid
        if tenant_path.exists():
            shutil.rmtree(tenant_path)

    def reset_tenant(self, tenant_id: str) -> Path:
        self.delete_tenant(tenant_id)
        return self.ensure_tenant_exists(tenant_id)
