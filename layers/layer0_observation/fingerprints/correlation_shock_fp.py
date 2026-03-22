"""
correlation_shock_fp.py

Layer 0 temporal fingerprint:
Correlation-shock fingerprint.

What it captures (numeric-only, semantics-free):
- how much correlation structure shifts across a window
- early vs late correlation delta magnitude (shock)
- bounded + bucketized identity (no float churn)

Rules:
- Emits canonical Fingerprint only
- Relative imports only
- Hash payload bucketizes coarse identity
- Vector is bounded similarity sketch
- window_bucket stored as INT everywhere in metadata
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


def _clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


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


def _mean(xs: Sequence[float]) -> float:
    return sum(xs) / float(len(xs)) if xs else 0.0


def _corr(xs: Sequence[float], ys: Sequence[float]) -> float:
    """
    Pearson correlation in [-1,1] with guards.
    """
    n = min(len(xs), len(ys))
    if n < 4:
        return 0.0

    x = xs[:n]
    y = ys[:n]

    mx = _mean(x)
    my = _mean(y)

    num = 0.0
    dx2 = 0.0
    dy2 = 0.0

    for i in range(n):
        dx = x[i] - mx
        dy = y[i] - my
        num += dx * dy
        dx2 += dx * dx
        dy2 += dy * dy

    den = (dx2 * dy2) ** 0.5
    if den <= 1e-12:
        return 0.0

    r = num / den
    # hard clamp to avoid numerical creep
    if r < -1.0:
        return -1.0
    if r > 1.0:
        return 1.0
    return r


def _window_bucket(window_ms: Optional[int]) -> int:
    """
    Stable discrete bucket (0..5). Store as int to avoid schema drift.
    """
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
    """
    Stable sample bucket (0..5).
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


# ----------------------------
# Fingerprint
# ----------------------------

def compute_correlation_shock_fingerprint(
    *,
    entity_id: str,
    a_values: Optional[Iterable[Any]] = None,
    b_values: Optional[Iterable[Any]] = None,
    physics_signals: Optional[Dict[str, Any]] = None,
    window_ms: Optional[int] = None,
) -> Fingerprint:
    """
    correlation shock between a_values and b_values.

    Physics-first:
      If physics_signals provides early_corr/late_corr/shock, we summarize those.
      Otherwise fallback computes early/late correlation using halves.
    """
    entity_id_s = str(entity_id or "").strip()
    if not entity_id_s:
        raise ValueError("entity_id must be non-empty")

    physics_signals = dict(physics_signals or {})

    # ---- Prefer physics_signals if present ----
    early_corr = physics_signals.get("early_corr")
    late_corr = physics_signals.get("late_corr")
    shock_raw = physics_signals.get("correlation_shock")

    used_physics = False

    if early_corr is not None or late_corr is not None or shock_raw is not None:
        used_physics = True
        early = _safe_float(early_corr)
        late = _safe_float(late_corr)

        # If shock not provided, derive it
        if shock_raw is None:
            shock_raw_f = abs(late - early)
        else:
            shock_raw_f = abs(_safe_float(shock_raw))

    else:
        # ---- Fallback compute from windows ----
        a = _finite_series(a_values)
        b = _finite_series(b_values)

        n = min(len(a), len(b))
        a = a[:n]
        b = b[:n]

        if n < 8:
            early = 0.0
            late = 0.0
            shock_raw_f = 0.0
        else:
            mid = n // 2
            early = _corr(a[:mid], b[:mid])
            late = _corr(a[mid:], b[mid:])
            shock_raw_f = abs(late - early)

    # ---- Correct normalization (FIXED) ----
    # abs(delta_corr) ∈ [0..2], so normalize by 2.0, not clamp directly.
    shock01 = _clamp01(shock_raw_f / 2.0)

    # encode correlations into [0..1] for vector space
    early01 = _clamp01((early + 1.0) / 2.0)
    late01 = _clamp01((late + 1.0) / 2.0)

    n_fallback = 0
    if not used_physics:
        n_fallback = min(len(_finite_series(a_values)), len(_finite_series(b_values)))
    n_bucket = _bucket_n(n_fallback)
    w_bucket = _window_bucket(window_ms)

    # ---- Buckets for stable identity ----
    shock_b = _bucketize01(shock01, edges=[0.02, 0.05, 0.10, 0.20, 0.35, 0.55, 0.75])
    early_b = _bucketize01(early01, edges=[0.10, 0.25, 0.40, 0.55, 0.70, 0.85, 0.95])
    late_b = _bucketize01(late01, edges=[0.10, 0.25, 0.40, 0.55, 0.70, 0.85, 0.95])

    hash_payload = {
        "entity_id": entity_id_s,
        "window_bucket": int(w_bucket),
        "n_bucket": int(n_bucket),
        "shock_b": int(shock_b),
        "early_b": int(early_b),
        "late_b": int(late_b),
    }

    fp_hash = Fingerprint.stable_hash_from_payload(hash_payload)

    # ---- Vector (bounded similarity sketch) ----
    # Keep stable dims and make it useful for clustering:
    vector = Fingerprint.make_vector(
        [
            shock01,
            early01,
            late01,
            float(shock_b) / 7.0,
            float(w_bucket) / 5.0,
            float(n_bucket) / 5.0,
        ],
        quantize_decimals=4,
    )

    # ---- Quality ----
    base_q = 0.9 if used_physics else 0.65
    size_q = 0.3 + 0.7 * (float(n_bucket) / 5.0) if n_bucket > 0 else 0.25
    quality = Fingerprint.safe_quality(base_q * size_q)

    source_fields = {
        "used_physics_signals": used_physics,
        "window_bucket": int(w_bucket),  # ✅ INT (fixed)
        "n_bucket": int(n_bucket),        # ✅ INT
        "early_corr": float(early),
        "late_corr": float(late),
        "correlation_shock_raw": float(shock_raw_f),
        "shock01": float(shock01),
        "shock_bucket": int(shock_b),
    }

    return Fingerprint(
        entity_id=entity_id_s,
        kind="correlation_shock_fp_v1",
        version=1,
        hash=fp_hash,
        vector=vector,
        quality=quality,
        source_fields=source_fields,
    )
