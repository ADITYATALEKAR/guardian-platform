from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class OperatorAccount:
    operator_id: str
    email: str
    password_hash: str
    created_at_unix_ms: int
    status: str
    role: str


@dataclass(frozen=True)
class SessionToken:
    token: str
    operator_id: str
    issued_at_unix_ms: int
    expires_at_unix_ms: int


@dataclass(frozen=True)
class OperatorTenantLink:
    operator_id: str
    tenant_ids: List[str]


def validate_operator_account(account: OperatorAccount) -> None:
    if not account.operator_id:
        raise ValueError("operator_id")
    if not account.email:
        raise ValueError("email")
    if not account.password_hash:
        raise ValueError("password_hash")
    if account.created_at_unix_ms < 0:
        raise ValueError("created_at_unix_ms")
    if account.status not in ("ACTIVE", "DISABLED"):
        raise ValueError("status")
    if account.role not in ("OWNER", "ADMIN", "MEMBER"):
        raise ValueError("role")


def validate_session_token(token: SessionToken) -> None:
    if not token.token:
        raise ValueError("token")
    if not token.operator_id:
        raise ValueError("operator_id")
    if token.issued_at_unix_ms < 0:
        raise ValueError("issued_at_unix_ms")
    if token.expires_at_unix_ms <= token.issued_at_unix_ms:
        raise ValueError("expires_at_unix_ms")


def validate_operator_link(link: OperatorTenantLink) -> None:
    if not link.operator_id:
        raise ValueError("operator_id")
    if link.tenant_ids is None:
        raise ValueError("tenant_ids")
    for tenant_id in link.tenant_ids:
        if not tenant_id:
            raise ValueError("tenant_ids")


def normalize_tenant_ids(tenant_ids: List[str]) -> List[str]:
    deduped = sorted(set(tenant_ids))
    return deduped
