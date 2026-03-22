from __future__ import annotations

from typing import Any, Optional


def is_nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def safe_str(value: Any, default: str = "") -> str:
    try:
        out = str(value).strip()
    except Exception:
        return default
    return out if out else default


def safe_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    if value is None:
        return default
    try:
        out = float(value)
    except Exception:
        return default
    if out != out or out in (float("inf"), float("-inf")):
        return default
    return out


def safe_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


def clamp01(value: Any) -> float:
    out = safe_float(value, 0.0)
    assert out is not None
    if out < 0.0:
        return 0.0
    if out > 1.0:
        return 1.0
    return float(out)
