"""
coherence_fp.py

Layer 0 Fingerprint: coherence stability signature (coherence_fp_v1)

Mission
-------
Capture *structural stability* of a timing signal without leaking raw timings.

Design goals
------------
- Deterministic + stable across refactors.
- Hash is bucketized (no float churn).
- Vector is bounded and similarity-friendly.
- Robust to partial/missing physics_signals and small-N noise.
- DOES NOT recompute expensive physics if already provided.
- No raw sequence content in hash or source_fields.

Hashing
-------
- Include entity_id (Option A separation).
- Include signal_name bucket + window bucket + n bucket + score bucket + dispersion bucket.
- Never include raw floats in hash payload.

Vector
------
- score01, disp01, buckets, n_bucket, window_bucket
- quantized to avoid churn in downstream clustering.

Notes
-----
If physics_signals contains coherence metrics, we trust them.
Otherwise we compute a small, robust approximation (median+MAD).


System “self-consistency”

Breaks under deception
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Sequence, Tuple

from .fingerprint_types import Fingerprint


# ----------------------------
# Core safety helpers
# ----------------------------
def _require_nonempty_str(name: str, value: Any) -> str:
    v = str(value or "").strip()
    if not v:
        raise ValueError(f"{name} must be non-empty")
    return v


def _safe_str(value: Any, default: str) -> str:
    v = str(value or "").strip()
    return v if v else default


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        f = float(x)
        if f != f or f in (float("inf"), float("-inf")):
            return default
        return f
    except Exception:
        return default


def _clamp01(x: Any) -> float:
    v = _safe_float(x, 0.0)
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


def _compress_pos01(x: Any) -> float:
    """
    Compress positive unbounded values into [0..1).
    Stable monotonic mapping: x / (1 + x).
    """
    v = abs(_safe_float(x, 0.0))
    return v / (1.0 + v)


def _bucketize01(x01: float, edges: Sequence[float]) -> int:
    x = _clamp01(x01)
    for i, e in enumerate(edges):
        if x <= e:
            return i
    return len(edges)


def _finite_series(values: Optional[Sequence[float]]) -> Tuple[float, ...]:
    if not values:
        return ()
    return tuple(_safe_float(v, 0.0) for v in values)


def _bucket_n(n: int) -> int:
    """
    Small cardinality buckets for stable identity.
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
    if n < 100:
        return 5
    return 6


def _bucket_window_ms(window_ms: Optional[int]) -> int:
    """
    Bucket window size to prevent hash churn when users vary frame sizes.
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
    if window_ms <= 120000:
        return 5
    return 6


# ----------------------------
# Local robust coherence approx
# ----------------------------
def _compute_robust_coherence(values: Sequence[float]) -> Dict[str, float]:
    """
    Robust coherence proxy:
      - median absolute deviation (MAD)
      - dispersion = MAD / (mean_abs + eps)
      - coherence_score = 1 / (1 + dispersion)

    Output:
      {"coherence_score": [0..1], "coherence_dispersion": >=0}
    """
    x = _finite_series(values)
    if len(x) < 3:
        return {"coherence_score": 0.0, "coherence_dispersion": 0.0}

    abs_x = [abs(v) for v in x]
    mean_abs = sum(abs_x) / max(1, len(abs_x))

    xs = sorted(x)
    mid = len(xs) // 2
    med = (xs[mid - 1] + xs[mid]) / 2.0 if len(xs) % 2 == 0 else xs[mid]

    deviations = sorted(abs(v - med) for v in x)
    mid2 = len(deviations) // 2
    mad = (
        (deviations[mid2 - 1] + deviations[mid2]) / 2.0
        if len(deviations) % 2 == 0
        else deviations[mid2]
    )

    dispersion = mad / (1e-9 + mean_abs)
    coherence_score = 1.0 / (1.0 + dispersion)

    return {
        "coherence_score": float(coherence_score),
        "coherence_dispersion": float(dispersion),
    }


# ----------------------------
# Public API
# ----------------------------
def compute_coherence_fingerprint(
    *,
    entity_id: str,
    signal_name: str = "",
    signal_values: Optional[Sequence[float]] = None,
    physics_signals: Optional[Dict[str, Any]] = None,
    window_ms: Optional[int] = None,
) -> Fingerprint:
    """
    Produce coherence_fp_v1.

    physics_signals may contain:
      - coherence_score or coherence
      - coherence_dispersion
    """
    eid = _require_nonempty_str("entity_id", entity_id)
    sname = _safe_str(signal_name, "global")

    ps = dict(physics_signals or {})
    used_physics = False

    # Prefer canonical physics key names; accept minimal aliasing safely.
    score_raw = ps.get("coherence_score", ps.get("coherence"))
    disp_raw = ps.get("coherence_dispersion")

    if score_raw is not None or disp_raw is not None:
        used_physics = True
        metrics = {
            "coherence_score": _safe_float(score_raw, 0.0),
            "coherence_dispersion": _safe_float(disp_raw, 0.0),
        }
    else:
        metrics = _compute_robust_coherence(signal_values or ())

    # score is naturally in [0..1], dispersion is unbounded
    score01 = _clamp01(metrics["coherence_score"])
    disp01 = _compress_pos01(metrics["coherence_dispersion"])

    # buckets stabilize identity hashing
    score_b = _bucketize01(score01, edges=[0.10, 0.25, 0.40, 0.55, 0.70, 0.85, 0.95])
    disp_b = _bucketize01(disp01, edges=[0.02, 0.05, 0.10, 0.20, 0.35, 0.55, 0.75])

    n = len(signal_values or ())
    n_b = _bucket_n(n)
    w_b = _bucket_window_ms(window_ms)

    # bounded payload (no raw floats)
    hash_payload = {
        "entity_id": eid,
        "signal_name": sname,
        "n_bucket": n_b,
        "window_bucket": w_b,
        "score_bucket": score_b,
        "disp_bucket": disp_b,
    }

    fp_hash = Fingerprint.stable_hash_from_payload(hash_payload)

    # similarity vector (bounded; safe)
    vec = Fingerprint.make_vector(
        [
            score01,
            disp01,
            float(score_b),
            float(disp_b),
            float(n_b),
            float(w_b),
        ],
        quantize_decimals=4,
    )

    # quality:
    # - physics-derived coherence is more reliable
    # - small-n coherence is fragile
    base = 0.92 if used_physics else 0.70
    n_factor = min(1.0, float(n) / 20.0) if n > 0 else 0.0
    quality = Fingerprint.safe_quality(base * (0.55 + 0.45 * n_factor) if n > 0 else base * 0.25)

    source_fields = {
        "signal_name": sname,
        "window_ms": int(window_ms) if window_ms is not None else None,
        "used_physics_signals": used_physics,
        "n": int(n),
        "coherence_score": float(metrics["coherence_score"]),
        "coherence_dispersion": float(metrics["coherence_dispersion"]),
        "score_bucket": int(score_b),
        "disp_bucket": int(disp_b),
        "n_bucket": int(n_b),
        "window_bucket": int(w_b),
    }

    return Fingerprint(
        entity_id=eid,
        kind="coherence_fp_v1",
        version=1,
        hash=fp_hash,
        vector=vec,
        quality=quality,
        source_fields=source_fields,
    )
