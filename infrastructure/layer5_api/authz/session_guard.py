from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet

from infrastructure.aggregation.authz_contract import AuthorizedTenantScope
from infrastructure.layer5_api.errors import UnauthorizedError
from infrastructure.operator_plane.registry.operator_tenant_links import list_tenants
from infrastructure.operator_plane.sessions.session_manager import validate_session


@dataclass(frozen=True)
class SessionContext:
    operator_id: str
    token: str
    tenant_scope: AuthorizedTenantScope
    tenant_ids: FrozenSet[str]


class SessionGuard:
    """
    Session token validation + tenant scope materialization.
    """

    def __init__(self, operator_storage_root: str):
        self._root = str(operator_storage_root)

    def require_session(
        self,
        authorization_header: str,
        *,
        client_ip: str = "",
        user_agent: str = "",
    ) -> SessionContext:
        token = self._extract_bearer_token(authorization_header)
        if not token:
            raise UnauthorizedError("missing session token")

        try:
            operator_id = validate_session(
                self._root,
                token,
                client_ip=client_ip,
                user_agent=user_agent,
            )
        except Exception as exc:
            raise UnauthorizedError("invalid session") from exc

        tenant_ids = frozenset(list_tenants(self._root, operator_id))
        scope = AuthorizedTenantScope.from_iterable(operator_id, tenant_ids)
        return SessionContext(
            operator_id=operator_id,
            token=token,
            tenant_scope=scope,
            tenant_ids=tenant_ids,
        )

    def _extract_bearer_token(self, authorization_header: str) -> str:
        header = str(authorization_header or "").strip()
        if not header:
            return ""
        parts = header.split(" ", 1)
        if len(parts) != 2:
            return ""
        if parts[0].strip().lower() != "bearer":
            return ""
        return parts[1].strip()
