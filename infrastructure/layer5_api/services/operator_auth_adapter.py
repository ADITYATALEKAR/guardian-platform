from __future__ import annotations

from typing import Any, Dict

from infrastructure.layer5_api.errors import BadRequestError, UnauthorizedError
from infrastructure.operator_plane.registry.operator_registry import (
    authenticate_operator,
    get_operator,
    list_operators,
)
from infrastructure.operator_plane.registry.operator_tenant_links import get_tenant, list_tenants
from infrastructure.operator_plane.sessions.session_manager import (
    create_session,
    revoke_session,
    validate_session,
)


class OperatorAuthAdapter:
    """
    Authentication adapter for Layer 5 API.
    """

    def __init__(self, operator_storage_root: str):
        self._root = str(operator_storage_root)

    def login(
        self,
        operator_id: str,
        password: str,
        *,
        client_ip: str = "",
        user_agent: str = "",
    ) -> Dict[str, Any]:
        oid = str(operator_id or "").strip()
        pwd = str(password or "")
        if not oid or not pwd:
            raise BadRequestError("operator_id and password are required")
        resolved_operator_id = self._resolve_login_identifier(oid)

        try:
            _ = authenticate_operator(self._root, resolved_operator_id, pwd)
        except Exception as exc:
            raise UnauthorizedError("invalid credentials", code="invalid_credentials") from exc

        session = create_session(
            self._root,
            resolved_operator_id,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        tenants = list_tenants(self._root, resolved_operator_id)
        tenant_id = get_tenant(self._root, resolved_operator_id)
        operator_record = get_operator(self._root, resolved_operator_id)

        return {
            "operator_id": resolved_operator_id,
            "email": str(operator_record.get("email", "")).strip(),
            "created_at_unix_ms": operator_record.get("created_at_unix_ms"),
            "role": str(operator_record.get("role", "OWNER")).strip().upper() or "OWNER",
            "tenant_id": tenant_id,
            "tenant_ids": tenants,
            "session_token": session.token,
            "issued_at_unix_ms": session.issued_at_unix_ms,
            "expires_at_unix_ms": session.expires_at_unix_ms,
        }

    def logout(self, token: str) -> Dict[str, Any]:
        tk = str(token or "").strip()
        if not tk:
            raise UnauthorizedError("missing session token")
        try:
            revoke_session(self._root, tk)
        except Exception as exc:
            raise UnauthorizedError("invalid session") from exc
        return {"revoked": True}

    def me(
        self,
        token: str,
        *,
        client_ip: str = "",
        user_agent: str = "",
    ) -> Dict[str, Any]:
        tk = str(token or "").strip()
        if not tk:
            raise UnauthorizedError("missing session token")
        try:
            operator_id = validate_session(
                self._root,
                tk,
                client_ip=client_ip,
                user_agent=user_agent,
            )
        except Exception as exc:
            raise UnauthorizedError("invalid session") from exc
        tenants = list_tenants(self._root, operator_id)
        tenant_id = get_tenant(self._root, operator_id)
        operator_record = get_operator(self._root, operator_id)
        return {
            "operator_id": operator_id,
            "email": str(operator_record.get("email", "")).strip(),
            "created_at_unix_ms": operator_record.get("created_at_unix_ms"),
            "role": str(operator_record.get("role", "OWNER")).strip().upper() or "OWNER",
            "tenant_id": tenant_id,
            "tenant_ids": tenants,
        }

    def _resolve_login_identifier(self, identifier: str) -> str:
        token = str(identifier or "").strip()
        if not token:
            return token

        operators = list_operators(self._root)
        if token in operators:
            return token

        normalized = token.lower()

        # Email login support (unique email only).
        email_matches = [
            oid
            for oid, record in operators.items()
            if str(record.get("email", "")).strip().lower() == normalized
        ]
        if len(email_matches) == 1:
            return email_matches[0]

        # Fallback preserves constant outward auth error behavior.
        return token
