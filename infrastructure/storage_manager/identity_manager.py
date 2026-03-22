from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Dict

from infrastructure.storage_manager.storage_manager import StorageManager


class IdentityManager:
    """
    Control-plane identity manager.

    Responsibilities:
        - Secure password hashing (PBKDF2)
        - Credential storage
        - Authentication

    Does NOT:
        - Register tenants
        - Create storage
        - Manage seed endpoints
        - Run discovery
        - Modify graph
        - Touch telemetry or baseline
    """

    IDENTITY_FILE = "identity_store.json"
    PBKDF2_ITERATIONS = 200_000
    SALT_BYTES = 16

    # ============================================================
    # INIT
    # ============================================================

    def __init__(self, storage: StorageManager):
        self.storage = storage
        self.identity_path = storage.identity_dir / self.IDENTITY_FILE

        if not self.identity_path.exists():
            self._atomic_write({"tenants": {}})

    # ============================================================
    # CREDENTIAL STORAGE
    # ============================================================

    def set_credentials(
        self,
        tenant_id: str,
        password: str,
    ) -> None:
        """
        Stores hashed credentials for a tenant.

        IdentityManager does NOT create tenant storage.
        """

        if not tenant_id:
            raise ValueError("tenant_id cannot be empty")

        identity_data = self._load_all()

        if tenant_id in identity_data["tenants"]:
            raise RuntimeError("Tenant already exists in identity store")

        identity_data["tenants"][tenant_id] = {
            "password_hash": self._hash_password(password),
        }

        self._atomic_write(identity_data)

    # ============================================================
    # AUTHENTICATION
    # ============================================================

    def authenticate(
        self,
        tenant_id: str,
        password: str,
    ) -> bool:

        identity_data = self._load_all()

        tenant = identity_data["tenants"].get(tenant_id)
        if not tenant:
            return False

        return self._verify_password(
            password,
            tenant["password_hash"],
        )

    def has_tenant(self, tenant_id: str) -> bool:
        identity_data = self._load_all()
        return tenant_id in identity_data.get("tenants", {})

    # ============================================================
    # CREDENTIAL REMOVAL
    # ============================================================

    def delete_credentials(
        self,
        tenant_id: str,
        password: str,
    ) -> None:
        """
        Removes credentials for a tenant (auth only).
        """

        if not self.authenticate(tenant_id, password):
            raise RuntimeError("Authentication failed")

        identity_data = self._load_all()

        if tenant_id not in identity_data["tenants"]:
            raise RuntimeError("Tenant not found")

        del identity_data["tenants"][tenant_id]

        self._atomic_write(identity_data)

    # ============================================================
    # INTERNAL HELPERS
    # ============================================================

    # -------------------------
    # SECURE PASSWORD HASHING
    # -------------------------

    def _hash_password(self, password: str) -> str:
        salt = secrets.token_bytes(self.SALT_BYTES)

        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            self.PBKDF2_ITERATIONS,
        )

        return f"{salt.hex()}${digest.hex()}"

    def _verify_password(self, password: str, stored: str) -> bool:
        try:
            salt_hex, digest_hex = stored.split("$", 1)
        except ValueError:
            return False

        salt = bytes.fromhex(salt_hex)

        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            self.PBKDF2_ITERATIONS,
        )

        return hmac.compare_digest(candidate.hex(), digest_hex)

    # -------------------------
    # STORAGE HELPERS
    # -------------------------

    def _load_all(self) -> Dict:
        if not self.identity_path.exists():
            return {"tenants": {}}

        with open(self.identity_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _atomic_write(self, data: Dict) -> None:
        self.identity_path.parent.mkdir(parents=True, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            mode="w",
            delete=False,
            dir=self.identity_path.parent,
            encoding="utf-8",
        ) as tmp_file:
            json.dump(data, tmp_file, indent=2)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
            tmp_path = Path(tmp_file.name)

        os.replace(tmp_path, self.identity_path)
