from __future__ import annotations

import secrets
import time
from pathlib import Path

from infrastructure.operator_plane.models.operator_models import (
    SessionToken,
    validate_session_token,
)
from infrastructure.operator_plane.storage.pg_operator_storage import (
    delete_session,
    read_session,
    write_session,
)


TOKEN_HEX_BYTES = 16
DEFAULT_SESSION_TTL_SECONDS = 60 * 60


def create_session(
    root: str,
    operator_id: str,
    *,
    client_ip: str = "",
    user_agent: str = "",
) -> SessionToken:
    now_ms = int(time.time() * 1000)
    token = secrets.token_hex(TOKEN_HEX_BYTES)
    expires_at = now_ms + DEFAULT_SESSION_TTL_SECONDS * 1000
    session = SessionToken(
        token=token,
        operator_id=operator_id,
        issued_at_unix_ms=now_ms,
        expires_at_unix_ms=expires_at,
    )
    validate_session_token(session)
    write_session(
        root,
        token,
        {
            "token": session.token,
            "operator_id": session.operator_id,
            "issued_at_unix_ms": session.issued_at_unix_ms,
            "expires_at_unix_ms": session.expires_at_unix_ms,
            "client_ip": str(client_ip or "").strip() or None,
            "user_agent": str(user_agent or "").strip() or None,
        },
    )
    return session


def validate_session(
    root: str,
    token: str,
    *,
    client_ip: str = "",
    user_agent: str = "",
) -> str:
    payload = read_session(root, token)
    issued_at = payload.get("issued_at_unix_ms")
    expires_at = payload.get("expires_at_unix_ms")
    if not isinstance(issued_at, int) or not isinstance(expires_at, int):
        raise RuntimeError("Corrupt operator storage: sessions")
    now_ms = int(time.time() * 1000)
    if now_ms > expires_at:
        delete_session(root, token)
        raise RuntimeError("invalid session")
    expected_client_ip = str(payload.get("client_ip") or "").strip()
    expected_user_agent = str(payload.get("user_agent") or "").strip()
    observed_client_ip = str(client_ip or "").strip()
    observed_user_agent = str(user_agent or "").strip()
    if expected_client_ip and expected_client_ip != observed_client_ip:
        delete_session(root, token)
        raise RuntimeError("invalid session")
    if expected_user_agent and expected_user_agent != observed_user_agent:
        delete_session(root, token)
        raise RuntimeError("invalid session")
    return payload.get("operator_id")


def revoke_session(root: str, token: str) -> None:
    delete_session(root, token)


def revoke_all_sessions(root: str, operator_id: str) -> None:
    from infrastructure.db.connection import use_postgres
    if use_postgres():
        from infrastructure.operator_plane.storage.pg_operator_storage import (
            revoke_all_sessions as _pg_revoke_all,
        )
        _pg_revoke_all(root, operator_id)
        return
    sessions_dir = Path(root) / "sessions"
    if not sessions_dir.exists():
        return
    for path in sessions_dir.glob("*.json"):
        payload = read_session(root, path.stem)
        if payload.get("operator_id") == operator_id:
            delete_session(root, path.stem)
