from __future__ import annotations

import time
from typing import Any, Dict

from infrastructure.operator_plane.auth.password_hasher import (
    dummy_hash,
    hash_password,
    verify_password,
)
from infrastructure.operator_plane.models.operator_models import (
    OperatorAccount,
    validate_operator_account,
)
from infrastructure.operator_plane.storage.pg_operator_storage import (
    read_operators,
    write_operators,
)


DEFAULT_STATUS = "ACTIVE"
DEFAULT_ROLE = "OWNER"
FAILED_AUTH_DELAY_SEC = 1.0


def create_operator(
    root: str,
    operator_id: str,
    email: str,
    password: str,
    created_at_unix_ms: int,
    status: str = DEFAULT_STATUS,
    role: str = DEFAULT_ROLE,
) -> Dict[str, Any]:
    operators = read_operators(root)
    if operator_id in operators:
        raise RuntimeError("operator exists")
    normalized_email = str(email or "").strip().lower()
    for existing in operators.values():
        existing_email = str(existing.get("email", "")).strip().lower()
        if normalized_email and existing_email == normalized_email:
            raise RuntimeError("email already exists")

    password_hash = hash_password(password)
    account = OperatorAccount(
        operator_id=operator_id,
        email=email,
        password_hash=password_hash,
        created_at_unix_ms=int(created_at_unix_ms),
        status=status,
        role=str(role or DEFAULT_ROLE).strip().upper() or DEFAULT_ROLE,
    )
    validate_operator_account(account)

    operators[operator_id] = {
        "operator_id": account.operator_id,
        "email": account.email,
        "password_hash": account.password_hash,
        "created_at_unix_ms": account.created_at_unix_ms,
        "status": account.status,
        "role": account.role,
    }
    write_operators(root, operators)
    return operators[operator_id]


def get_operator(root: str, operator_id: str) -> Dict[str, Any]:
    operators = read_operators(root)
    if operator_id not in operators:
        raise RuntimeError("operator not found")
    return operators[operator_id]


def list_operators(root: str) -> Dict[str, Any]:
    return read_operators(root)


def authenticate_operator(root: str, operator_id: str, password: str) -> Dict[str, Any]:
    operators = read_operators(root)
    record = operators.get(operator_id)
    stored_hash = record.get("password_hash") if record else dummy_hash()
    try:
        valid = verify_password(password, stored_hash)
    except Exception:
        time.sleep(FAILED_AUTH_DELAY_SEC)
        raise RuntimeError("invalid credentials")
    if record is None or not valid:
        time.sleep(FAILED_AUTH_DELAY_SEC)
        raise RuntimeError("invalid credentials")
    return record


def delete_operator_record_only(root: str, operator_id: str) -> None:
    operators = read_operators(root)
    if operator_id not in operators:
        raise RuntimeError("operator not found")
    del operators[operator_id]
    write_operators(root, operators)


def update_operator_email(root: str, operator_id: str, email: str) -> Dict[str, Any]:
    operators = read_operators(root)
    if operator_id not in operators:
        raise RuntimeError("operator not found")

    normalized_email = str(email or "").strip().lower()
    if not normalized_email:
        raise RuntimeError("email cannot be empty")

    for existing_id, existing in operators.items():
        if existing_id == operator_id:
            continue
        existing_email = str(existing.get("email", "")).strip().lower()
        if existing_email == normalized_email:
            raise RuntimeError("email already exists")

    operators[operator_id]["email"] = str(email).strip()
    write_operators(root, operators)
    return operators[operator_id]


def update_operator_password(root: str, operator_id: str, new_password: str) -> Dict[str, Any]:
    operators = read_operators(root)
    if operator_id not in operators:
        raise RuntimeError("operator not found")
    operators[operator_id]["password_hash"] = hash_password(new_password)
    write_operators(root, operators)
    return operators[operator_id]
