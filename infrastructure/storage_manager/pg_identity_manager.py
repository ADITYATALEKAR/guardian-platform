"""
Postgres-backed IdentityManager.

Implements the same public interface as IdentityManager.
Uses PBKDF2-SHA256 with the same parameters as the filesystem version.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

from infrastructure.storage_manager.pg_storage_manager import PgStorageManager


class PgIdentityManager:
    """
    Postgres-backed control-plane identity manager.

    Drop-in replacement for IdentityManager when GUARDIAN_DATABASE_URL is set.
    """

    PBKDF2_ITERATIONS = 200_000
    SALT_BYTES = 16

    def __init__(self, storage: PgStorageManager) -> None:
        self.storage = storage

    # ------------------------------------------------------------------
    # Public interface (matches IdentityManager exactly)
    # ------------------------------------------------------------------

    def set_credentials(self, tenant_id: str, password: str) -> None:
        """
        Hash and store credentials for a tenant.
        Raises RuntimeError if the tenant already exists in the identity store.
        """
        if not tenant_id:
            raise ValueError("tenant_id cannot be empty")
        password_hash = self._hash_password(password)
        self.storage.set_identity_credentials(tenant_id, password_hash)

    def authenticate(self, tenant_id: str, password: str) -> bool:
        stored_hash = self.storage.get_identity_credentials(tenant_id)
        if stored_hash is None:
            return False
        return self._verify_password(password, stored_hash)

    def has_tenant(self, tenant_id: str) -> bool:
        return self.storage.get_identity_credentials(tenant_id) is not None

    def delete_credentials(self, tenant_id: str, password: str) -> None:
        if not self.authenticate(tenant_id, password):
            raise RuntimeError("Authentication failed")
        self.storage.delete_identity_credentials(tenant_id)

    # ------------------------------------------------------------------
    # Internal helpers — same algorithm as IdentityManager
    # ------------------------------------------------------------------

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
