"""
entropy_histogram_fp.py

Layer 0 structural fingerprint:
Window-based entropy distribution shape fingerprint.

MERGE-SAFE REQUIREMENTS:
- Hash must be stable across small window-size changes.
- Therefore: hash coarse ratios (0..100) not raw counts.

Vector:
- normalized ratios (0..1) per bin

Input values are expected to be in [0..1] or will be clamped.

Distributional entropy over time

Strong against stealth attacks
"""

from __future__ import annotations

from typing import Iterable, List, Tuple

from .fingerprint_types import Fingerprint


BINS = 8
RATIO_QUANT = 100  # coarse 0..100 ratio buckets


def _require_nonempty(entity_id: str) -> str:
    v = str(entity_id or "").strip()
    if not v:
        raise ValueError("entity_id must be non-empty")
    return v


def _safe_01(x) -> float:
    try:
        f = float(x)
        if f != f:
            return 0.0
        if f < 0.0:
            return 0.0
        if f > 1.0:
            return 1.0
        return f
    except Exception:
        return 0.0


def _bucket_total(n: int) -> int:
    if n <= 0:
        return 0
    if n <= 5:
        return 1
    if n <= 20:
        return 2
    if n <= 100:
        return 3
    return 4


def _hist_counts(values01: Tuple[float, ...]) -> Tuple[int, ...]:
    bins = [0] * BINS
    for v in values01:
        idx = min(BINS - 1, int(v * BINS))
        bins[idx] += 1
    return tuple(bins)


def _ratio_quantized(hist: Tuple[int, ...]) -> Tuple[int, ...]:
    total = sum(hist)
    if total <= 0:
        return tuple(0 for _ in hist)
    out: List[int] = []
    for c in hist:
        r = c / total  # 0..1
        out.append(int(round(r * RATIO_QUANT)))
    return tuple(out)


def compute_entropy_histogram_fingerprint(
    *,
    entity_id: str,
    entropy_values: Iterable[float],
) -> Fingerprint:
    entity_id = _require_nonempty(entity_id)

    values01 = tuple(_safe_01(v) for v in (entropy_values or ()))
    n = len(values01)

    n_bucket = _bucket_total(n)
    hist = _hist_counts(values01)
    ratio_q = _ratio_quantized(hist)  # stable identity representation

    # Stable identity hash: ratios not raw counts
    hash_payload = {
        "entity_id": entity_id,
        "n_bucket": n_bucket,
        "ratio_q": ratio_q,
    }
    fp_hash = Fingerprint.stable_hash_from_payload(hash_payload)

    # Vector: normalized ratios (0..1)
    total = sum(hist) or 1
    ratios = [c / total for c in hist]
    vector = Fingerprint.make_vector(ratios, quantize_decimals=4)

    # Quality: window size based (structural completeness only)
    quality = Fingerprint.safe_quality(0.9 if n >= 10 else 0.4 if n > 0 else 0.1)

    source_fields = {
        "sample_count": n,
        "n_bucket": n_bucket,
        "hist_counts": hist,
        "ratio_quantized_0_100": ratio_q,
        "bins": BINS,
        "vector_dim": len(vector),
    }

    return Fingerprint(
        entity_id=entity_id,
        kind="entropy_histogram_fp_v1",
        version=1,
        hash=fp_hash,
        vector=vector,
        quality=quality,
        source_fields=source_fields,
    )
