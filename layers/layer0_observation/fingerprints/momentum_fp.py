"""
momentum_fp.py

Layer 0 Fingerprint: Momentum Fingerprint

Purpose:
- Deterministic fingerprint summarizing momentum dynamics (2nd order behavior).
- No risk scoring. No policy. No labels.
- Stable across sessions and comparable over time.
"""

from __future__ import annotations

import json
import math
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Union

from .fingerprint_types import Fingerprint


MOMENTUM_FP_KIND = "momentum_fp_v1"
MOMENTUM_FP_VERSION = 1


# ----------------------------
# Safety / Determinism helpers
# ----------------------------
def _now_ms() -> int:
    import time

    return int(time.time() * 1000)


def _is_finite_number(x: Any) -> bool:
    try:
        v = float(x)
    except Exception:
        return False
    return math.isfinite(v)


def _safe_float(x: Any, default: float = 0.0) -> float:
    if not _is_finite_number(x):
        return float(default)
    return float(x)


def _safe_str(x: Any, default: str = "") -> str:
    if x is None:
        return default
    try:
        s = str(x)
    except Exception:
        return default
    return s


def _clamp01(x: float) -> float:
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    return float(x)


def _quantize(x: float, decimals: int = 6) -> float:
    """
    Deterministic rounding to avoid float noise.
    """
    try:
        return float(round(float(x), decimals))
    except Exception:
        return 0.0


def _stable_json(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _bounded_tanh(x: float) -> float:
    """
    Stable normalization into [-1, 1] while preserving sign.
    """
    return float(math.tanh(float(x)))


def _normalize_signed(x: float, scale: float = 1.0) -> float:
    """
    Maps (-inf, +inf) -> (-1, +1), then to [0,1].
    """
    if scale <= 0:
        scale = 1.0
    t = _bounded_tanh(float(x) / float(scale))
    return float(0.5 * (t + 1.0))


# ----------------------------
# Input model (optional)
# ----------------------------
@dataclass(frozen=True, kw_only=True)
class MomentumFingerprintInput:
    """
    Optional typed input.
    """

    entity_id: str = ""

    momentum: Optional[float] = None
    momentum_zscore: Optional[float] = None
    acceleration: Optional[float] = None

    window_size: Optional[int] = None


def build_momentum_fingerprint(
    *,
    entity_id: str,
    physics_signals: Optional[Dict[str, Any]] = None,
    inp: Optional[Union[MomentumFingerprintInput, Dict[str, Any]]] = None,
    created_ms: Optional[int] = None,
) -> Fingerprint:
    """
    Build momentum fingerprint from physics outputs.

    NOTE:
    - This fingerprint remains PURE momentum.
    - We do NOT couple coherence_score here.
    """

    raw: Dict[str, Any] = {}
    if physics_signals:
        raw.update(dict(physics_signals))

    if inp is not None:
        if isinstance(inp, MomentumFingerprintInput):
            raw.update(
                {
                    "entity_id": inp.entity_id,
                    "momentum": inp.momentum,
                    "momentum_zscore": inp.momentum_zscore,
                    "acceleration": inp.acceleration,
                    "window_size": inp.window_size,
                }
            )
        elif isinstance(inp, dict):
            raw.update(dict(inp))

    entity_id = _safe_str(entity_id) or _safe_str(raw.get("entity_id"))

    # ----------------------------
    # Extract signals
    # ----------------------------
    momentum = _safe_float(raw.get("momentum", 0.0), 0.0)
    momentum_zscore = _safe_float(raw.get("momentum_zscore", 0.0), 0.0)
    acceleration = _safe_float(raw.get("acceleration", 0.0), 0.0)

    window_size = raw.get("window_size", None)

    # ----------------------------
    # Normalize into stable [0,1]
    # ----------------------------
    # momentum is typically >= 0
    momentum_norm = _clamp01(1.0 - math.exp(-max(0.0, momentum)))

    # momentum_zscore signed-ish -> [0,1]
    momentum_zscore_norm = _normalize_signed(momentum_zscore, scale=3.0)

    # acceleration can be signed -> [0,1]
    acceleration_norm = _normalize_signed(acceleration, scale=1.0)

    vector: Tuple[float, ...] = (
        _quantize(momentum_norm, 6),
        _quantize(momentum_zscore_norm, 6),
        _quantize(acceleration_norm, 6),
        _quantize(1.0 if momentum > 0 else 0.0, 6),  # presence/stability bit
    )

    # ----------------------------
    # Quality scoring (completeness)
    # ----------------------------
    quality = 1.0

    if not _is_finite_number(raw.get("momentum", None)) and not _is_finite_number(
        raw.get("acceleration", None)
    ):
        quality = min(quality, 0.55)

    if window_size is not None:
        try:
            ws = int(window_size)
            if ws < 3:
                quality = min(quality, 0.75)
        except Exception:
            quality = min(quality, 0.85)
    else:
        quality = min(quality, 0.90)

    quality = _clamp01(quality)

    # ----------------------------
    # Hash material (entity-bound)
    # ----------------------------
    hash_material = {
        "kind": MOMENTUM_FP_KIND,
        "version": MOMENTUM_FP_VERSION,
        "entity_id": entity_id,
        "vector": vector,
    }

    fp_hash = _sha256_hex(_stable_json(hash_material))

    created_ms = int(created_ms) if created_ms is not None else _now_ms()

    source_fields = {
        "momentum": _quantize(momentum, 6),
        "momentum_zscore": _quantize(momentum_zscore, 6),
        "acceleration": _quantize(acceleration, 6),
        "window_size": window_size,
    }

    return Fingerprint(
        fingerprint_id=f"{MOMENTUM_FP_KIND}_{fp_hash[:12]}",
        entity_id=entity_id,
        kind=MOMENTUM_FP_KIND,
        version=MOMENTUM_FP_VERSION,
        created_ms=created_ms,
        hash=fp_hash,
        vector=vector,
        quality=quality,
        source_fields=source_fields,
    )


def compute_momentum_fingerprint(*args, **kwargs):
    """
    Canonical Layer-0 public function.

    Delegates to build_momentum_fingerprint for compatibility.
    """
    impl = globals().get("build_momentum_fingerprint")
    if callable(impl):
        return impl(*args, **kwargs)
    raise ImportError("momentum_fp.py must define build_momentum_fingerprint(...)")
