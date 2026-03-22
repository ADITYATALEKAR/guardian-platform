"""
decay_fp.py

Layer 0 temporal fingerprint:
Decay trend signature fingerprint.

Final hardening:
- signal_name optional (defaults to "global")
- decay_strength compressed (unbounded), monotonicity clamped (0..1)
- hash strengthened with n_bucket + window_bucket
"""

from __future__ import annotations

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
        if f != f:
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
    x = abs(_safe_float(x))
    return x / (1.0 + x)


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


def _compute_decay_metrics(values: Sequence[float]) -> Dict[str, float]:
    x = _finite_series(values)
    if len(x) < 3:
        return {"decay_strength": 0.0, "decay_monotonicity": 0.0}

    deltas = [x[i] - x[i - 1] for i in range(1, len(x))]
    neg = sum(1 for d in deltas if d < 0)
    monotonicity = neg / max(1, len(deltas))

    mean_abs = sum(abs(v) for v in x) / max(1, len(x))
    slope = (x[-1] - x[0]) / max(1e-9, mean_abs)

    decay_strength = max(0.0, -slope)

    return {"decay_strength": float(decay_strength), "decay_monotonicity": float(monotonicity)}


def compute_decay_fingerprint(
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

    strength = physics_signals.get("decay_strength", physics_signals.get("decay"))
    monotonicity = physics_signals.get("decay_monotonicity")

    if strength is not None or monotonicity is not None:
        used_physics = True
        metrics = {
            "decay_strength": _safe_float(strength),
            "decay_monotonicity": _safe_float(monotonicity),
        }
    else:
        metrics = _compute_decay_metrics(signal_values or ())

    strength01 = _compress_pos01(metrics["decay_strength"])
    mono01 = _clamp01(metrics["decay_monotonicity"])

    strength_bucket = _bucketize01(strength01, edges=[0.02, 0.05, 0.10, 0.20, 0.35, 0.55, 0.75])
    mono_bucket = _bucketize01(mono01, edges=[0.10, 0.25, 0.40, 0.55, 0.70, 0.85, 0.95])

    n = len(signal_values or ())
    n_bucket = _bucket_n(n)
    w_bucket = _bucket_window_ms(window_ms)

    hash_payload = {
        "entity_id": entity_id,
        "signal_name": signal_name,
        "n_bucket": n_bucket,
        "window_bucket": w_bucket,
        "strength_bucket": strength_bucket,
        "mono_bucket": mono_bucket,
    }

    fp_hash = Fingerprint.stable_hash_from_payload(hash_payload)

    vec = Fingerprint.make_vector(
        [
            strength01,
            mono01,
            float(strength_bucket),
            float(mono_bucket),
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
        "decay_strength": float(metrics["decay_strength"]),
        "decay_monotonicity": float(metrics["decay_monotonicity"]),
        "strength_bucket": strength_bucket,
        "mono_bucket": mono_bucket,
        "n_bucket": n_bucket,
        "window_bucket": w_bucket,
    }

    return Fingerprint(
        entity_id=entity_id,
        kind="decay_fp_v1",
        version=1,
        hash=fp_hash,
        vector=vec,
        quality=quality,
        source_fields=source_fields,
    )
