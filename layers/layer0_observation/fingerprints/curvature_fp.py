"""
curvature_fp.py

Layer 0 temporal fingerprint:
Drift curvature fingerprint (2nd derivative / jerkiness signature).

Final hardening:
- bias preserves sign (tanh -> [-1..1] -> [0..1])
- signal_name optional (defaults to "global")
- avoid over-compression for already [0..1] metrics
- hash strengthened with n_bucket + window_bucket
"""

from __future__ import annotations

import math
from typing import Any, Dict, Optional, Sequence, Tuple

from .fingerprint_types import Fingerprint


def _require_nonempty_str(name: str, value: str) -> str:
    v = str(value or "").strip()
    if not v:
        raise ValueError(f"{name} must be non-empty")
    return v


def _safe_str(value: Any, default: str) -> str:
    v = str(value or "").strip()
    return v if v else default


def _safe_float(x: Any) -> float:
    try:
        f = float(x)
        if f != f:  # NaN
            return 0.0
        if f == float("inf") or f == float("-inf"):
            return 0.0
        return f
    except Exception:
        return 0.0


def _clamp01(x: float) -> float:
    x = _safe_float(x)
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def _compress_pos01(x: float) -> float:
    """
    Compress non-negative unbounded metric to [0, 1).
    """
    x = abs(_safe_float(x))
    return x / (1.0 + x)


def _signed_to_01(x: float) -> float:
    """
    Preserve sign via tanh compression:
    maps (-inf..inf) -> (-1..1) -> (0..1)
    """
    x = _safe_float(x)
    t = math.tanh(x)
    return (t + 1.0) / 2.0


def _bucketize01(x01: float, edges: Sequence[float]) -> int:
    x = _clamp01(x01)
    for i, e in enumerate(edges):
        if x <= e:
            return i
    return len(edges)


def _finite_series(values: Optional[Sequence[float]]) -> Tuple[float, ...]:
    if not values:
        return ()
    return tuple(_safe_float(v) for v in values)


def _bucket_n(n: int) -> int:
    """
    Bounded identity stabilizer.
    """
    if n <= 0:
        return 0
    if n < 5:
        return 1
    if n < 10:
        return 2
    if n < 20:
        return 3
    if n < 50:
        return 4
    return 5


def _bucket_window_ms(window_ms: Optional[int]) -> int:
    """
    Bounded window stabilizer bucket.
    """
    if not window_ms or window_ms <= 0:
        return 0
    if window_ms <= 250:
        return 1
    if window_ms <= 1000:
        return 2
    if window_ms <= 5000:
        return 3
    if window_ms <= 30000:
        return 4
    return 5


def _compute_curvature_metrics(values: Sequence[float]) -> Dict[str, float]:
    x = _finite_series(values)
    if len(x) < 4:
        return {
            "curvature_energy": 0.0,
            "curvature_jerkiness": 0.0,
            "curvature_bias": 0.0,
        }

    dx = [x[i] - x[i - 1] for i in range(1, len(x))]
    ddx = [dx[i] - dx[i - 1] for i in range(1, len(dx))]

    abs_ddx = [abs(v) for v in ddx]
    abs_dx = [abs(v) for v in dx]

    mean_abs_dx = sum(abs_dx) / max(1, len(abs_dx))
    mean_abs_ddx = sum(abs_ddx) / max(1, len(abs_ddx))

    curvature_energy = mean_abs_ddx / (1e-9 + mean_abs_dx)

    sign_flips = 0
    for i in range(1, len(ddx)):
        if ddx[i - 1] == 0 or ddx[i] == 0:
            continue
        if (ddx[i - 1] > 0) != (ddx[i] > 0):
            sign_flips += 1
    curvature_jerkiness = sign_flips / max(1, len(ddx) - 1)

    curvature_bias = sum(ddx) / max(1, len(ddx))

    return {
        "curvature_energy": float(curvature_energy),
        "curvature_jerkiness": float(curvature_jerkiness),
        "curvature_bias": float(curvature_bias),
    }


def compute_curvature_fingerprint(
    *,
    entity_id: str,
    signal_name: str = "",
    signal_values: Optional[Sequence[float]] = None,
    physics_signals: Optional[Dict[str, Any]] = None,
    window_ms: Optional[int] = None,
) -> Fingerprint:
    entity_id = _require_nonempty_str("entity_id", entity_id)
    signal_name = _safe_str(signal_name, "global")

    physics_signals = dict(physics_signals or {})
    used_physics = False

    energy = physics_signals.get("curvature_energy", None)
    jerk = physics_signals.get("curvature_jerkiness", None)
    bias = physics_signals.get("curvature_bias", None)

    if energy is not None or jerk is not None or bias is not None:
        used_physics = True
        metrics = {
            "curvature_energy": _safe_float(energy),
            "curvature_jerkiness": _safe_float(jerk),
            "curvature_bias": _safe_float(bias),
        }
    else:
        metrics = _compute_curvature_metrics(signal_values or ())

    # energy is unbounded -> compress
    energy01 = _compress_pos01(metrics["curvature_energy"])

    # jerkiness is naturally [0..1] -> clamp, not compress
    jerk01 = _clamp01(metrics["curvature_jerkiness"])

    # bias is signed -> preserve sign
    bias01 = _signed_to_01(metrics["curvature_bias"])

    energy_bucket = _bucketize01(energy01, edges=[0.05, 0.15, 0.30, 0.50, 0.70, 0.85])
    jerk_bucket = _bucketize01(jerk01, edges=[0.02, 0.05, 0.10, 0.20, 0.35, 0.55, 0.75])
    bias_bucket = _bucketize01(bias01, edges=[0.10, 0.30, 0.45, 0.55, 0.70, 0.90])

    n = len(signal_values or ())
    n_bucket = _bucket_n(n)
    w_bucket = _bucket_window_ms(window_ms)

    hash_payload = {
        "entity_id": entity_id,
        "signal_name": signal_name,
        "n_bucket": n_bucket,
        "window_bucket": w_bucket,
        "energy_bucket": energy_bucket,
        "jerk_bucket": jerk_bucket,
        "bias_bucket": bias_bucket,
    }

    fp_hash = Fingerprint.stable_hash_from_payload(hash_payload)

    vec = Fingerprint.make_vector(
        [
            energy01,
            jerk01,
            bias01,
            float(energy_bucket),
            float(jerk_bucket),
            float(bias_bucket),
            float(n_bucket),
            float(w_bucket),
        ],
        quantize_decimals=4,
    )

    base_q = 0.9 if used_physics else 0.65
    size_q = min(1.0, n / 20.0) if n > 0 else 0.0
    quality = Fingerprint.safe_quality(base_q * (0.6 + 0.4 * size_q) if n > 0 else base_q * 0.25)

    source_fields = {
        "signal_name": signal_name,
        "window_ms": int(window_ms) if window_ms is not None else None,
        "used_physics_signals": used_physics,
        "n": n,
        "curvature_energy": float(metrics["curvature_energy"]),
        "curvature_jerkiness": float(metrics["curvature_jerkiness"]),
        "curvature_bias": float(metrics["curvature_bias"]),
        "energy_bucket": energy_bucket,
        "jerk_bucket": jerk_bucket,
        "bias_bucket": bias_bucket,
        "n_bucket": n_bucket,
        "window_bucket": w_bucket,
    }

    return Fingerprint(
        entity_id=entity_id,
        kind="curvature_fp_v1",
        version=1,
        hash=fp_hash,
        vector=vec,
        quality=quality,
        source_fields=source_fields,
    )
