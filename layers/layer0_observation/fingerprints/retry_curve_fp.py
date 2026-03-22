"""
retry_curve_fp.py

Layer 0 temporal fingerprint:
Retry-curve fingerprint (attempt spacing / retry rhythm signature).

This is raw behavior shape ONLY (no risk meaning).
It fingerprints the structure of retry timings across a small window.

Inputs:
- attempt_times_ms: sequence of attempt timestamps (epoch ms or relative ms)
- OR physics_signals providing derived retry metrics

Rules:
- Canonical Fingerprint only
- Stable hash uses bucketized identity features
- Vector is bounded similarity sketch
- window_bucket stored as INT everywhere
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional, Sequence, Tuple

from .fingerprint_types import Fingerprint


# ----------------------------
# Helpers
# ----------------------------

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
    # compress non-negative unbounded -> [0,1)
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
        out.append(_safe_float(v))
    return tuple(out)


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
    if n < 2:
        return 1
    if n < 4:
        return 2
    if n < 8:
        return 3
    if n < 16:
        return 4
    return 5


def _mean(xs: Sequence[float]) -> float:
    return sum(xs) / float(len(xs)) if xs else 0.0


def _median(xs: Sequence[float]) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    m = len(s) // 2
    return s[m] if len(s) % 2 else 0.5 * (s[m - 1] + s[m])


def _mad(xs: Sequence[float], med: float) -> float:
    if not xs:
        return 0.0
    dev = [abs(x - med) for x in xs]
    return _median(dev) or 1e-9


# ----------------------------
# Fingerprint
# ----------------------------

def compute_retry_curve_fingerprint(
    *,
    entity_id: str,
    attempt_times_ms: Optional[Iterable[Any]] = None,
    physics_signals: Optional[Dict[str, Any]] = None,
    window_ms: Optional[int] = None,
) -> Fingerprint:
    entity_id_s = str(entity_id or "").strip()
    if not entity_id_s:
        raise ValueError("entity_id must be non-empty")

    physics_signals = dict(physics_signals or {})

    # Prefer physics_signals if provided
    # expected keys (optional/aliases):
    # - retry_count
    # - retry_mean_gap_ms
    # - retry_gap_mad_ms
    # - retry_burstiness (0..1)
    # - retry_monotone (0..1)
    used_physics = False

    retry_count = physics_signals.get("retry_count", None)
    mean_gap_ms = physics_signals.get("retry_mean_gap_ms", None)
    gap_mad_ms = physics_signals.get("retry_gap_mad_ms", None)
    burstiness = physics_signals.get("retry_burstiness", None)
    monotone = physics_signals.get("retry_monotone", None)

    if (
        retry_count is not None
        or mean_gap_ms is not None
        or gap_mad_ms is not None
        or burstiness is not None
        or monotone is not None
    ):
        used_physics = True

        retry_count_i = max(0, _safe_int(retry_count))
        mean_gap = max(0.0, _safe_float(mean_gap_ms))
        mad_gap = max(0.0, _safe_float(gap_mad_ms))

        # burstiness/monotone are expected [0..1], clamp
        burst01 = _clamp01(_safe_float(burstiness))
        mono01 = _clamp01(_safe_float(monotone))

    else:
        # Fallback compute from attempt times
        t = _finite_series(attempt_times_ms)
        t = tuple(sorted(t))
        retry_count_i = max(0, len(t) - 1)

        if len(t) < 2:
            mean_gap = 0.0
            mad_gap = 0.0
            burst01 = 0.0
            mono01 = 0.0
        else:
            gaps = [max(0.0, t[i] - t[i - 1]) for i in range(1, len(t))]
            mean_gap = _mean(gaps)
            med_gap = _median(gaps)
            mad_gap = _mad(gaps, med_gap)

            # burstiness proxy: dispersion / mean
            burst_raw = mad_gap / (mean_gap + 1e-9)
            burst01 = _clamp01(_compress_pos01(burst_raw))

            # monotone proxy: are gaps increasing (backoff-ish)?
            inc = 0
            valid = 0
            for i in range(1, len(gaps)):
                valid += 1
                if gaps[i] >= gaps[i - 1]:
                    inc += 1
            mono01 = _clamp01(inc / max(1, valid))

    # Normalize scalars for vector
    retry_count_bucket = _bucket_n(retry_count_i)
    w_bucket = _window_bucket(window_ms)

    gap_mean01 = _compress_pos01(mean_gap / 1000.0)  # 1s scaling anchor
    gap_disp01 = _compress_pos01(mad_gap / (mean_gap + 1e-9))

    # Identity buckets (stable)
    gap_mean_b = _bucketize01(gap_mean01, edges=[0.02, 0.05, 0.10, 0.20, 0.35, 0.55, 0.75])
    gap_disp_b = _bucketize01(gap_disp01, edges=[0.02, 0.05, 0.10, 0.20, 0.35, 0.55, 0.75])
    burst_b = _bucketize01(burst01, edges=[0.10, 0.25, 0.40, 0.55, 0.70, 0.85, 0.95])
    mono_b = _bucketize01(mono01, edges=[0.10, 0.25, 0.40, 0.55, 0.70, 0.85, 0.95])

    hash_payload = {
        "entity_id": entity_id_s,
        "window_bucket": int(w_bucket),
        "retry_count_b": int(retry_count_bucket),
        "gap_mean_b": int(gap_mean_b),
        "gap_disp_b": int(gap_disp_b),
        "burst_b": int(burst_b),
        "mono_b": int(mono_b),
    }

    fp_hash = Fingerprint.stable_hash_from_payload(hash_payload)

    # Vector (bounded similarity sketch)
    vector = Fingerprint.make_vector(
        [
            float(retry_count_bucket) / 5.0,
            gap_mean01,
            gap_disp01,
            burst01,
            mono01,
            float(w_bucket) / 5.0,
        ],
        quantize_decimals=4,
    )

    base_q = 0.9 if used_physics else 0.65
    size_q = 0.3 + 0.7 * (float(retry_count_bucket) / 5.0) if retry_count_i > 0 else 0.25
    quality = Fingerprint.safe_quality(base_q * size_q)

    source_fields = {
        "used_physics_signals": used_physics,
        "retry_count": int(retry_count_i),
        "retry_count_bucket": int(retry_count_bucket),
        "gap_mean_ms": float(mean_gap),
        "gap_mad_ms": float(mad_gap),
        "gap_mean01": float(gap_mean01),
        "gap_disp01": float(gap_disp01),
        "burstiness01": float(burst01),
        "monotone01": float(mono01),
        "window_bucket": int(w_bucket),  # ✅ INT (fixed)
    }

    return Fingerprint(
        entity_id=entity_id_s,
        kind="retry_curve_fp_v1",
        version=1,
        hash=fp_hash,
        vector=vector,
        quality=quality,
        source_fields=source_fields,
    )
