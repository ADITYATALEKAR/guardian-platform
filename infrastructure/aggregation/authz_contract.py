from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, FrozenSet


@dataclass(frozen=True)
class AuthorizedTenantScope:
    """
    Connector/query authorization contract.

    All aggregation read-model methods should accept this scope and reject
    tenant reads outside the authorized set.
    """

    actor_id: str
    authorized_tenant_ids: FrozenSet[str]

    @staticmethod
    def from_iterable(actor_id: str, tenant_ids: Iterable[str]) -> "AuthorizedTenantScope":
        aid = str(actor_id or "").strip()
        if not aid:
            raise ValueError("actor_id")
        normalized = {
            str(tid or "").strip()
            for tid in (tenant_ids or [])
            if str(tid or "").strip()
        }
        return AuthorizedTenantScope(actor_id=aid, authorized_tenant_ids=frozenset(normalized))

    def assert_allowed(self, tenant_id: str) -> None:
        tid = str(tenant_id or "").strip()
        if not tid:
            raise RuntimeError("unauthorized tenant access")
        if tid not in self.authorized_tenant_ids:
            raise RuntimeError("unauthorized tenant access")
