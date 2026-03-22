from __future__ import annotations

import hashlib
import json
import re
import secrets
import shutil
import tempfile
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

from infrastructure.storage_manager.storage_manager import StorageManager
from infrastructure.storage_manager.identity_manager import IdentityManager
from simulator.storage.simulation_storage_manager import SimulationStorageManager


CANONICAL_ENDPOINT_PATTERN = re.compile(
    r"^[a-z0-9\.\-]+:[0-9]{1,5}$"
)


class TenantLifecycleManager:
    """
    Canonical tenant onboarding manager.

    Responsibilities:
        - Generate tenant_id
        - Create production storage structure
        - Create simulator storage structure
        - Store hashed credentials (via IdentityManager)
        - Write tenant_config.json (main_url, seed_endpoints, metadata)

    Does NOT:
        - Trigger cycles
        - Mutate graph
        - Inject fingerprints
        - Bypass discovery pipeline
        - Modify Layer 0-4 state
    """

    CONFIG_SCHEMA_VERSION = "v3"
    ONBOARDING_PENDING = "PENDING"
    ONBOARDING_COMPLETED = "COMPLETED"

    def __init__(
        self,
        storage: StorageManager,
        identity: IdentityManager,
        simulation_root: str,
    ):
        self.storage = storage
        self.identity = identity
        self.simulation_storage = SimulationStorageManager(simulation_root)

    # ============================================================
    # PUBLIC API
    # ============================================================

    def register_tenant(
        self,
        name: str,
        password: str,
        main_url: str,
        seed_endpoints: List[str],
    ) -> str:
        """
        Registers a new tenant.

        Steps:
            1. Generate tenant_id
            2. Validate endpoints
            3. Create production storage
            4. Create simulator storage
            5. Store hashed credentials
            6. Write tenant_config.json
        """

        if not name or not name.strip():
            raise ValueError("name cannot be empty")
        if not password or not password.strip():
            raise ValueError("password cannot be empty")
        if not main_url or not str(main_url).strip():
            raise ValueError("main_url cannot be empty")
        if not seed_endpoints:
            raise ValueError("seed_endpoints cannot be empty")

        canonical = self._validate_and_canonicalize(seed_endpoints)
        tenant_id = self._generate_tenant_id(name)

        # Ensure uniqueness across identity + storage
        attempts = 0
        while (
            self.storage.tenant_exists(tenant_id)
            or self.identity.has_tenant(tenant_id)
        ):
            attempts += 1
            if attempts > 5:
                raise RuntimeError("Unable to generate unique tenant_id")
            tenant_id = self._generate_tenant_id(name)

        try:
            self._validate_tenant_id(tenant_id)
            self.storage.create_tenant(tenant_id)
            self.simulation_storage.ensure_tenant_exists(tenant_id)
            self.identity.set_credentials(tenant_id, password)

            config = self._build_tenant_config(
                tenant_id=tenant_id,
                name=name,
                main_url=main_url,
                seed_endpoints=canonical,
                onboarding_status=self.ONBOARDING_COMPLETED,
                onboarding_completed_at_unix_ms=int(time.time() * 1000),
            )
            self._write_tenant_config(tenant_id, config)

        except Exception:
            # Rollback: best-effort cleanup
            try:
                if self.storage.tenant_exists(tenant_id):
                    self.storage.delete_tenant(tenant_id)
            except Exception:
                pass
            try:
                if self.identity.has_tenant(tenant_id):
                    self.identity.delete_credentials(tenant_id, password)
            except Exception:
                pass
            try:
                sim_path = self.simulation_storage.tenants_dir / tenant_id
                if sim_path.exists():
                    shutil.rmtree(sim_path)
            except Exception:
                pass
            raise

        return tenant_id

    def register_pending_tenant(
        self,
        *,
        name: str,
        password: str,
        tenant_id: Optional[str] = None,
    ) -> str:
        """
        Registers tenant workspace and credentials without scan onboarding details.

        This creates:
            - tenant_id
            - production + simulation storage folders
            - tenant credentials
            - tenant_config.json with onboarding_status=PENDING
        """
        if not name or not name.strip():
            raise ValueError("name cannot be empty")
        if not password or not password.strip():
            raise ValueError("password cannot be empty")

        if tenant_id:
            # Caller supplied a deterministic ID — use it directly.
            self._validate_tenant_id(tenant_id)
        else:
            tenant_id = self._generate_tenant_id(name)
            attempts = 0
            while (
                self.storage.tenant_exists(tenant_id)
                or self.identity.has_tenant(tenant_id)
            ):
                attempts += 1
                if attempts > 5:
                    raise RuntimeError("Unable to generate unique tenant_id")
                tenant_id = self._generate_tenant_id(name)

        try:
            self._validate_tenant_id(tenant_id)
            self.storage.create_tenant(tenant_id)
            self.simulation_storage.ensure_tenant_exists(tenant_id)
            self.identity.set_credentials(tenant_id, password)

            config = self._build_tenant_config(
                tenant_id=tenant_id,
                name=name,
                main_url="",
                seed_endpoints=[],
                onboarding_status=self.ONBOARDING_PENDING,
                onboarding_completed_at_unix_ms=None,
            )
            self._write_tenant_config(tenant_id, config)
        except Exception:
            # Rollback: best-effort cleanup
            try:
                if self.storage.tenant_exists(tenant_id):
                    self.storage.delete_tenant(tenant_id)
            except Exception:
                pass
            try:
                if self.identity.has_tenant(tenant_id):
                    self.identity.delete_credentials(tenant_id, password)
            except Exception:
                pass
            try:
                sim_path = self.simulation_storage.tenants_dir / tenant_id
                if sim_path.exists():
                    shutil.rmtree(sim_path)
            except Exception:
                pass
            raise

        return tenant_id

    def complete_tenant_onboarding(
        self,
        *,
        tenant_id: str,
        name: str,
        main_url: str,
        seed_endpoints: List[str],
    ) -> None:
        """
        Completes onboarding fields for an existing tenant workspace.
        """
        self.configure_tenant_onboarding(
            tenant_id=tenant_id,
            name=name,
            main_url=main_url,
            seed_endpoints=seed_endpoints,
        )
        self.mark_tenant_onboarding_completed(tenant_id)

    def configure_tenant_onboarding(
        self,
        *,
        tenant_id: str,
        name: str,
        main_url: str,
        seed_endpoints: List[str],
    ) -> None:
        """
        Persists onboarding fields for an existing tenant workspace while
        keeping onboarding state pending until the first scan completes.
        """
        if not name or not name.strip():
            raise ValueError("name cannot be empty")
        if not main_url or not str(main_url).strip():
            raise ValueError("main_url cannot be empty")
        if not seed_endpoints:
            raise ValueError("seed_endpoints cannot be empty")

        self._validate_tenant_id(tenant_id)
        canonical = self._validate_and_canonicalize(seed_endpoints)
        config = self._load_tenant_config(tenant_id)
        existing_onboarded_at = (
            config.get("onboarded_at_unix_ms")
            if str(config.get("onboarding_status", "")).strip().upper() == self.ONBOARDING_COMPLETED
            else None
        )
        if not isinstance(existing_onboarded_at, int):
            existing_onboarded_at = None
        config["name"] = name
        config["main_url"] = main_url
        config["seed_endpoints"] = canonical
        config["onboarding_status"] = self.ONBOARDING_PENDING
        config["onboarded_at_unix_ms"] = existing_onboarded_at
        self._write_tenant_config(tenant_id, config)

    def mark_tenant_onboarding_completed(self, tenant_id: str) -> None:
        """
        Marks onboarding complete only after a successful first cycle.
        """
        self._validate_tenant_id(tenant_id)
        config = self._load_tenant_config(tenant_id)
        existing_onboarded_at = config.get("onboarded_at_unix_ms")
        if not isinstance(existing_onboarded_at, int):
            existing_onboarded_at = int(time.time() * 1000)
        config["onboarding_status"] = self.ONBOARDING_COMPLETED
        config["onboarded_at_unix_ms"] = existing_onboarded_at
        self._write_tenant_config(tenant_id, config)

    def update_seed_endpoints(
        self,
        tenant_id: str,
        endpoints: List[str],
    ) -> None:
        """
        Updates seed endpoints for tenant.
        """

        self._validate_tenant_id(tenant_id)
        canonical = self._validate_and_canonicalize(endpoints)
        config = self._load_tenant_config(tenant_id)
        config["seed_endpoints"] = canonical
        self._write_tenant_config(tenant_id, config)

    def reset_tenant_workspace(self, tenant_id: str) -> Dict[str, Any]:
        """
        Resets tenant runtime workspace while preserving the same tenant_id.

        This clears production and simulation artifacts, rewrites tenant config
        to a fresh pending state, and preserves tenant linkage at the operator layer.
        """

        self._validate_tenant_id(tenant_id)
        existing = self._load_tenant_config(tenant_id)
        registered_at = existing.get("registered_at_unix_ms")
        registration_meta = existing.get("registration_meta")
        if not isinstance(registered_at, int):
            registered_at = int(time.time() * 1000)
        if not isinstance(registration_meta, dict):
            registration_meta = {"source": "tenant_lifecycle_manager"}

        self.storage.reset_tenant(tenant_id)
        self.simulation_storage.reset_tenant(tenant_id)

        config = self._build_tenant_config(
            tenant_id=tenant_id,
            name="",
            main_url="",
            seed_endpoints=[],
            onboarding_status=self.ONBOARDING_PENDING,
            onboarding_completed_at_unix_ms=None,
        )
        config["registered_at_unix_ms"] = registered_at
        config["registration_meta"] = registration_meta
        config["workspace_reset_at_unix_ms"] = int(time.time() * 1000)
        self._write_tenant_config(tenant_id, config)
        return {
            "tenant_id": tenant_id,
            "onboarding_status": self.ONBOARDING_PENDING,
            "reset": True,
        }

    # ============================================================
    # INTERNAL
    # ============================================================

    def _validate_and_canonicalize(
        self,
        endpoints: List[str],
    ) -> List[str]:
        """
        Ensures endpoints are canonical 'hostname:port' format.
        Enforces lowercase and sorting.
        """

        canonical: List[str] = []

        for ep in endpoints:
            if not isinstance(ep, str):
                raise ValueError(f"Invalid endpoint: {ep}")

            ep_clean = ep.strip().lower()

            # Allow hostname only -> default 443
            if ":" not in ep_clean:
                ep_clean = f"{ep_clean}:443"

            if not CANONICAL_ENDPOINT_PATTERN.match(ep_clean):
                raise ValueError(f"Invalid canonical endpoint: {ep}")

            canonical.append(ep_clean)

        # Deduplicate + deterministic order
        return sorted(set(canonical))

    def _generate_tenant_id(self, name: str) -> str:
        # 8 bytes = 64 bits of entropy
        suffix = secrets.token_hex(8)
        return f"tenant_{suffix}"

    @staticmethod
    def derive_tenant_id_from_operator(operator_id: str) -> str:
        """Return a stable tenant_id derived deterministically from operator_id.

        Used so that on ephemeral filesystems (Render free tier) the same
        operator always gets the same tenant directory after a cold restart,
        preserving scan data within the same deployment session.
        """
        digest = hashlib.sha1(operator_id.encode("utf-8")).hexdigest()[:16]
        return f"tenant_{digest}"

    def _validate_tenant_id(self, tenant_id: str) -> None:
        if not tenant_id:
            raise ValueError("tenant_id cannot be empty")
        if any(sep in tenant_id for sep in ("/", "\\", "..")):
            raise ValueError("Invalid tenant_id path sequence")

    def _tenant_config_path(self, tenant_id: str) -> Path:
        tenant_path = self.storage.get_tenant_path(tenant_id)
        return tenant_path / "tenant_config.json"

    def _build_tenant_config(
        self,
        *,
        tenant_id: str,
        name: str,
        main_url: str,
        seed_endpoints: List[str],
        onboarding_status: str,
        onboarding_completed_at_unix_ms: int | None,
    ) -> Dict[str, Any]:
        return {
            "schema_version": self.CONFIG_SCHEMA_VERSION,
            "tenant_id": tenant_id,
            "name": name,
            "main_url": main_url,
            "seed_endpoints": seed_endpoints,
            "registered_at_unix_ms": int(time.time() * 1000),
            "onboarding_status": str(onboarding_status),
            "onboarded_at_unix_ms": onboarding_completed_at_unix_ms,
            "registration_meta": {
                "source": "tenant_lifecycle_manager",
            },
        }

    def _load_tenant_config(self, tenant_id: str) -> Dict[str, Any]:
        path = self._tenant_config_path(tenant_id)
        if not path.exists():
            return {
                "schema_version": self.CONFIG_SCHEMA_VERSION,
                "tenant_id": tenant_id,
                "name": "",
                "main_url": "",
                "seed_endpoints": [],
                "onboarding_status": self.ONBOARDING_PENDING,
                "onboarded_at_unix_ms": None,
                "registered_at_unix_ms": int(time.time() * 1000),
                "registration_meta": {
                    "source": "tenant_lifecycle_manager",
                },
            }
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _write_tenant_config(self, tenant_id: str, config: Dict[str, Any]) -> None:
        path = self._tenant_config_path(tenant_id)
        path.parent.mkdir(parents=True, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            mode="w",
            delete=False,
            dir=path.parent,
            encoding="utf-8",
        ) as tmp_file:
            json.dump(config, tmp_file, indent=2, sort_keys=True)
            tmp_file.flush()
            tmp_path = Path(tmp_file.name)

        tmp_path.replace(path)
