from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Tuple


MIN_PASSWORD_LENGTH = 12
ITERATIONS = 200_000
_DUMMY_SALT = b"\x00" * 16
_DUMMY_PASSWORD = b"invalid"
_DUMMY_DIGEST = hashlib.pbkdf2_hmac("sha256", _DUMMY_PASSWORD, _DUMMY_SALT, ITERATIONS)
_DUMMY_HASH = None


def hash_password(password: str) -> str:
    _validate_password(password)
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return _encode_hash(salt, digest)


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, expected = _decode_hash(stored_hash)
    except Exception as exc:
        _ = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), _DUMMY_SALT, ITERATIONS
        )
        raise RuntimeError("invalid credentials") from exc
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return hmac.compare_digest(digest, expected)


def _validate_password(password: str) -> None:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError("password")


def _encode_hash(salt: bytes, digest: bytes) -> str:
    salt_b64 = base64.b64encode(salt).decode("ascii")
    digest_b64 = base64.b64encode(digest).decode("ascii")
    return f"pbkdf2_sha256${ITERATIONS}${salt_b64}${digest_b64}"


def _decode_hash(stored_hash: str) -> Tuple[bytes, bytes]:
    parts = stored_hash.split("$")
    if len(parts) != 4:
        raise ValueError("invalid password hash")
    algo, iterations, salt_b64, digest_b64 = parts
    try:
        iterations_int = int(iterations)
    except Exception as exc:
        raise ValueError("invalid password hash") from exc
    if algo != "pbkdf2_sha256" or iterations_int != ITERATIONS:
        raise ValueError("invalid password hash")
    try:
        salt = base64.b64decode(salt_b64)
        digest = base64.b64decode(digest_b64)
    except Exception as exc:
        raise ValueError("invalid password hash") from exc
    return salt, digest


def dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = _encode_hash(_DUMMY_SALT, _DUMMY_DIGEST)
    return _DUMMY_HASH
