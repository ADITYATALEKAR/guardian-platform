"""
drift_acceleration_fp.py

Layer 0 high-resolution temporal fingerprint:
Drift-acceleration fingerprint (curvature of drift trajectory).

Summarizes:
- acceleration magnitude (2nd difference energy)
- sign-flip rate in acceleration
- persistence ratio (late vs early accel magnitude)

Rules:
- Canonical Fingerprint only
- Stable identity hash uses bucketized values only
- window_bucket stored as INT everywhere
- Physics-first, fallback-safe
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional, Sequence, Tuple

from .fingerprint_types import Fingerprint


def _safe_float(x: Any) -> float:
    try:
        f = float(x)
        if f != f or f in (float("inf"), float("-inf")):
            return 0.0
        return f
    except Exception:
        return 0.0


def _safe_int(x: Any) -> int:
    try:
        return int(x)
    except Exception:
        return 0


def _clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


def _compress_pos01(x: float) -> float:
    v = abs(_safe_float(x))
    return v / (1.0 + v)


def _bucketize01(x01: float, edges: Sequence[float]) -> int:
    x = _clamp01(_safe_float(x01))
    for i, e in enumerate(edges):
        if x <= e:
            return i
    return len(edges)


def _finite_series(values: Optional[Iterable[Any]]) -> Tuple[float, ...]:
    if not values:
        return ()
    out = []
    for v in values:
        f = _safe_float(v)
        # IMPORTANT: don’t include NaN/Inf-replaced-zero artifacts
        # _safe_float returns 0.0 on bad inputs, but that's ambiguous.
        # Here we accept 0.0 only if input was actually numeric 0.
        # Since we cannot recover that reliably, we keep it simple:
        out.append(f)
    return tuple(out)


def _diff(xs: Sequence[float]) -> Tuple[float, ...]:
    if len(xs) < 2:
        return ()
    return tuple(xs[i] - xs[i - 1] for i in range(1, len(xs)))


def _mean_abs(xs: Sequence[float]) -> float:
    if not xs:
        return 0.0
    return sum(abs(x) for x in xs) / float(len(xs))


def _window_bucket(window_ms: Optional[int]) -> int:
    if not window_ms or window_ms <= 0:
        return 0
    w = int(window_ms)
    if w <= 250:
        return 1
    if w <= 1000:
        return 2
    if w <= 5000:
        return 3
    if w <= 30000:
        return 4
    return 5


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


def _infer_n_from_physics(physics_signals: Dict[str, Any]) -> int:
    """
    Best-effort inference for sample size when physics_signals exist
    but raw series is missing.

    Accepted keys:
    - sample_count (int-ish)
    - n (int-ish)
    - sample_count_norm (0..1) (approx maps to n<=64)
    """
    sc = physics_signals.get("sample_count", None)
    if sc is not None:
        return max(0, _safe_int(sc))

    n = physics_signals.get("n", None)
    if n is not None:
        return max(0, _safe_int(n))

    scn = physics_signals.get("sample_count_norm", None)
    if scn is not None:
        # Our standard normalization is roughly n/64
        scn01 = _clamp01(_safe_float(scn))
        return max(0, int(round(scn01 * 64.0)))

    return 0


def _compute_from_series(values: Sequence[float]) -> Dict[str, float]:
    x = tuple(values)
    if len(x) < 6:
        return {
            "accel_energy": 0.0,
            "accel_flip_rate": 0.0,
            "accel_persistence": 0.0,
        }

    d1 = _diff(x)
    d2 = _diff(d1)

    accel_energy = _mean_abs(d2) / (1e-9 + _mean_abs(d1))

    flips = 0
    valid = 0
    for i in range(1, len(d2)):
        a = d2[i - 1]
        b = d2[i]
        if abs(a) < 1e-12 or abs(b) < 1e-12:
            continue
        valid += 1
        if (a > 0) != (b > 0):
            flips += 1
    accel_flip_rate = flips / max(1, valid)

    mid = len(d2) // 2
    early_mag = _mean_abs(d2[:mid])
    late_mag = _mean_abs(d2[mid:])
    ratio = late_mag / (early_mag + 1e-9)
    accel_persistence = ratio / (1.0 + ratio)

    return {
        "accel_energy": float(accel_energy),
        "accel_flip_rate": float(accel_flip_rate),
        "accel_persistence": float(accel_persistence),
    }


def compute_drift_acceleration_fingerprint(
    *,
    entity_id: str,
    drift_values: Optional[Iterable[Any]] = None,
    physics_signals: Optional[Dict[str, Any]] = None,
    window_ms: Optional[int] = None,
) -> Fingerprint:
    entity_id_s = str(entity_id or "").strip()
    if not entity_id_s:
        raise ValueError("entity_id must be non-empty")

    physics_signals = dict(physics_signals or {})
    used_physics = False

    e = physics_signals.get("drift_accel_energy", None)
    f = physics_signals.get("drift_accel_flip_rate", None)
    p = physics_signals.get("drift_accel_persistence", None)

    if e is not None or f is not None or p is not None:
        used_physics = True
        metrics = {
            "accel_energy": _safe_float(e),
            "accel_flip_rate": _safe_float(f),
            "accel_persistence": _safe_float(p),
        }
    else:
        series = _finite_series(drift_values)
        metrics = _compute_from_series(series)

    # accel_energy is unbounded -> compress
    energy01 = _compress_pos01(metrics["accel_energy"])
    # flip_rate and persistence are naturally [0..1] -> clamp
    flip01 = _clamp01(metrics["accel_flip_rate"])
    pers01 = _clamp01(metrics["accel_persistence"])

    # ✅ FIX: n_bucket must not collapse when physics is used
    if used_physics:
        inferred_n = _infer_n_from_physics(physics_signals)
        # If physics exists but no sample hints, choose a conservative "mid" bucket
        # so we don't artificially down-rank quality.
        n_bucket = _bucket_n(inferred_n) if inferred_n > 0 else 3
        n = inferred_n if inferred_n > 0 else 0
    else:
        n = len(_finite_series(drift_values))
        n_bucket = _bucket_n(n)

    w_bucket = _window_bucket(window_ms)

    energy_b = _bucketize01(energy01, edges=[0.05, 0.15, 0.30, 0.50, 0.70, 0.85])
    flip_b = _bucketize01(flip01, edges=[0.02, 0.05, 0.10, 0.20, 0.35, 0.55, 0.75])
    pers_b = _bucketize01(pers01, edges=[0.10, 0.25, 0.40, 0.55, 0.70, 0.85, 0.95])

    hash_payload = {
        "entity_id": entity_id_s,
        "window_bucket": int(w_bucket),
        "n_bucket": int(n_bucket),
        "energy_b": int(energy_b),
        "flip_b": int(flip_b),
        "pers_b": int(pers_b),
    }

    fp_hash = Fingerprint.stable_hash_from_payload(hash_payload)

    vector = Fingerprint.make_vector(
        [
            energy01,
            flip01,
            pers01,
            float(energy_b) / 6.0,
            float(w_bucket) / 5.0,
            float(n_bucket) / 5.0,
        ],
        quantize_decimals=4,
    )

    # ✅ FIX: quality should not collapse when physics exists
    base_q = 0.9 if used_physics else 0.65
    size_q = 0.35 + 0.65 * (float(n_bucket) / 5.0)
    quality = Fingerprint.safe_quality(base_q * size_q)

    source_fields = {
        "used_physics_signals": used_physics,
        "accel_energy": float(metrics["accel_energy"]),
        "accel_flip_rate": float(metrics["accel_flip_rate"]),
        "accel_persistence": float(metrics["accel_persistence"]),
        "energy01": float(energy01),
        "flip01": float(flip01),
        "persistence01": float(pers01),
        "energy_bucket": int(energy_b),
        "flip_bucket": int(flip_b),
        "persistence_bucket": int(pers_b),
        "n": int(n),
        "n_bucket": int(n_bucket),
        "window_bucket": int(w_bucket),
    }

    return Fingerprint(
        entity_id=entity_id_s,
        kind="drift_acceleration_fp_v1",
        version=1,
        hash=fp_hash,
        vector=vector,
        quality=quality,
        source_fields=source_fields,
    )
