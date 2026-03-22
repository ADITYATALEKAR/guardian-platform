from __future__ import annotations

from typing import Any


def safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def bound_str(value: Any, *, max_len: int) -> str:
    s = safe_str(value)
    if len(s) <= max_len:
        return s
    return s[:max_len]
