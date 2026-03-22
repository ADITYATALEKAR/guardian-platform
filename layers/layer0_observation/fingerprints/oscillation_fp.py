"""
oscillation_fp.py

Layer 0 temporal fingerprint:
Oscillation signature fingerprint.

Final hardening:
- signal_name optional (defaults to "global")
- only compress unbounded energy; flip_rate is clamped
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


def _compute_oscillation_metrics(values: Sequence[float]) -> Dict[str, float]:
    x = _finite_series(values)
    if len(x) < 5:
        return {"oscillation_energy": 0.0, "oscillation_flip_rate": 0.0}

    dx = [x[i] - x[i - 1] for i in range(1, len(x))]
    abs_dx = [abs(v) for v in dx]

    mean_abs = sum(abs_dx) / max(1, len(abs_dx))
    var = sum((v - mean_abs) ** 2 for v in abs_dx) / max(1, len(abs_dx))
    std = var**0.5

    flips = 0
    for i in range(1, len(dx)):
        if dx[i - 1] == 0 or dx[i] == 0:
            continue
        if (dx[i - 1] > 0) != (dx[i] > 0):
            flips += 1
    flip_rate = flips / max(1, len(dx) - 1)

    energy = std / (1e-9 + mean_abs)
    return {"oscillation_energy": float(energy), "oscillation_flip_rate": float(flip_rate)}


def compute_oscillation_fingerprint(
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

    energy = physics_signals.get("oscillation_energy", physics_signals.get("oscillation_score"))
    flip_rate = physics_signals.get("oscillation_flip_rate", physics_signals.get("oscillation_flip"))

    if energy is not None or flip_rate is not None:
        used_physics = True
        metrics = {
            "oscillation_energy": _safe_float(energy),
            "oscillation_flip_rate": _safe_float(flip_rate),
        }
    else:
        metrics = _compute_oscillation_metrics(signal_values or ())

    energy01 = _compress_pos01(metrics["oscillation_energy"])
    flip01 = _clamp01(metrics["oscillation_flip_rate"])

    energy_bucket = _bucketize01(energy01, edges=[0.05, 0.15, 0.30, 0.50, 0.70, 0.85])
    flip_bucket = _bucketize01(flip01, edges=[0.02, 0.05, 0.10, 0.20, 0.35, 0.55, 0.75])

    n = len(signal_values or ())
    n_bucket = _bucket_n(n)
    w_bucket = _bucket_window_ms(window_ms)

    hash_payload = {
        "entity_id": entity_id,
        "signal_name": signal_name,
        "n_bucket": n_bucket,
        "window_bucket": w_bucket,
        "energy_bucket": energy_bucket,
        "flip_bucket": flip_bucket,
    }

    fp_hash = Fingerprint.stable_hash_from_payload(hash_payload)

    vec = Fingerprint.make_vector(
        [
            energy01,
            flip01,
            float(energy_bucket),
            float(flip_bucket),
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
        "oscillation_energy": float(metrics["oscillation_energy"]),
        "oscillation_flip_rate": float(metrics["oscillation_flip_rate"]),
        "energy_bucket": energy_bucket,
        "flip_bucket": flip_bucket,
        "n_bucket": n_bucket,
        "window_bucket": w_bucket,
    }

    return Fingerprint(
        entity_id=entity_id,
        kind="oscillation_fp_v1",
        version=1,
        hash=fp_hash,
        vector=vec,
        quality=quality,
        source_fields=source_fields,
    )
