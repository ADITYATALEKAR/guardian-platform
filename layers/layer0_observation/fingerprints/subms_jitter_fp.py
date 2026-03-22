"""
subms_jitter_fp.py

Layer 0 high-resolution temporal fingerprint:
Sub-millisecond jitter fingerprint.

Goal:
Capture high-frequency timing irregularity shape without interpretation.

Inputs:
- jitter_values_ms: jitter samples in milliseconds (can be sub-ms)
OR physics_signals for already-computed jitter metrics.

Summarizes:
- jitter_energy (unbounded -> compressed)
- jitter_spikiness (0..1 clamped)
- jitter_coherence (0..1 clamped)
- sample/window buckets for identity stability

Rules:
- Canonical Fingerprint only
- stable identity is bucketized, no float churn
- window_bucket stored as INT everywhere
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
        out.append(_safe_float(v))
    return tuple(out)


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


def _compute_from_series(values_ms: Sequence[float]) -> Dict[str, float]:
    x = list(values_ms)
    if len(x) < 6:
        return {
            "jitter_energy": 0.0,
            "jitter_spikiness": 0.0,
            "jitter_coherence": 0.0,
        }

    med = _median(x)
    mad = _mad(x, med)

    # energy proxy: MAD / (|median| + eps)
    energy = mad / (abs(med) + 1e-9)

    # spikiness: fraction of samples beyond 3*MAD
    thr = 3.0 * mad
    spikes = sum(1 for v in x if abs(v - med) > thr)
    spikiness = spikes / max(1, len(x))

    # coherence proxy: inverse of energy
    coherence = 1.0 / (1.0 + energy)

    return {
        "jitter_energy": float(energy),
        "jitter_spikiness": float(_clamp01(spikiness)),
        "jitter_coherence": float(_clamp01(coherence)),
    }


def compute_subms_jitter_fingerprint(
    *,
    entity_id: str,
    jitter_values_ms: Optional[Iterable[Any]] = None,
    physics_signals: Optional[Dict[str, Any]] = None,
    window_ms: Optional[int] = None,
) -> Fingerprint:
    entity_id_s = str(entity_id or "").strip()
    if not entity_id_s:
        raise ValueError("entity_id must be non-empty")

    physics_signals = dict(physics_signals or {})
    used_physics = False

    e = physics_signals.get("subms_jitter_energy", None)
    s = physics_signals.get("subms_jitter_spikiness", None)
    c = physics_signals.get("subms_jitter_coherence", None)

    if e is not None or s is not None or c is not None:
        used_physics = True
        energy = _safe_float(e)
        spikiness01 = _clamp01(_safe_float(s))
        coherence01 = _clamp01(_safe_float(c))
    else:
        series = _finite_series(jitter_values_ms)
        metrics = _compute_from_series(series)
        energy = metrics["jitter_energy"]
        spikiness01 = _clamp01(metrics["jitter_spikiness"])
        coherence01 = _clamp01(metrics["jitter_coherence"])

    energy01 = _compress_pos01(energy)

    n = len(_finite_series(jitter_values_ms))
    n_bucket = _bucket_n(n)
    w_bucket = _window_bucket(window_ms)

    energy_b = _bucketize01(energy01, edges=[0.02, 0.05, 0.10, 0.20, 0.35, 0.55, 0.75])
    spiky_b = _bucketize01(spikiness01, edges=[0.02, 0.05, 0.10, 0.20, 0.35, 0.55, 0.75])
    coh_b = _bucketize01(coherence01, edges=[0.10, 0.25, 0.40, 0.55, 0.70, 0.85, 0.95])

    hash_payload = {
        "entity_id": entity_id_s,
        "window_bucket": int(w_bucket),
        "n_bucket": int(n_bucket),
        "energy_b": int(energy_b),
        "spiky_b": int(spiky_b),
        "coh_b": int(coh_b),
    }

    fp_hash = Fingerprint.stable_hash_from_payload(hash_payload)

    vector = Fingerprint.make_vector(
        [
            energy01,
            spikiness01,
            coherence01,
            float(energy_b) / 7.0,
            float(w_bucket) / 5.0,
            float(n_bucket) / 5.0,
        ],
        quantize_decimals=4,
    )

    base_q = 0.9 if used_physics else 0.65
    size_q = 0.35 + 0.65 * (float(n_bucket) / 5.0) if n > 0 else 0.25
    quality = Fingerprint.safe_quality(base_q * size_q)

    source_fields = {
        "used_physics_signals": used_physics,
        "jitter_energy": float(energy),
        "energy01": float(energy01),
        "spikiness01": float(spikiness01),
        "coherence01": float(coherence01),
        "energy_bucket": int(energy_b),
        "spikiness_bucket": int(spiky_b),
        "coherence_bucket": int(coh_b),
        "n_bucket": int(n_bucket),
        "window_bucket": int(w_bucket),  # ✅ INT (fixed)
    }

    return Fingerprint(
        entity_id=entity_id_s,
        kind="subms_jitter_fp_v1",
        version=1,
        hash=fp_hash,
        vector=vector,
        quality=quality,
        source_fields=source_fields,
    )
