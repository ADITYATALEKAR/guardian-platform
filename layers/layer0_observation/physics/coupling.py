"""
coupling.py

Layer 0 second-order coupling physics.

Computes numeric coupling descriptors between two signals.
No semantics, no state, no interpretation.


What it measures

Back-and-forth instability

Metaphor

A system that can’t settle.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Sequence

# Robust-z MAD calibration constant (Gaussian-consistent)
_MAD_GAUSS = 1.4826

# Near-zero threshold for derivative sign decisions
_DIFF_EPS = 1e-9


def _safe_float(x) -> float:
    try:
        f = float(x)
        if f != f or f in (float("inf"), float("-inf")):
            return 0.0
        return f
    except Exception:
        return 0.0


def _clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


def _median(xs: Sequence[float]) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    m = len(s) // 2
    return s[m] if len(s) % 2 else 0.5 * (s[m - 1] + s[m])


def _mad(xs: Sequence[float], med: float) -> float:
    dev = [abs(x - med) for x in xs]
    return _median(dev) or 1e-9


def _standardize(xs: Sequence[float]) -> List[float]:
    if not xs:
        return []
    med = _median(xs)
    mad = _mad(xs, med)
    scale = (_MAD_GAUSS * mad) or 1e-9
    return [(x - med) / scale for x in xs]


def _diff(xs: Sequence[float]) -> List[float]:
    return [xs[i] - xs[i - 1] for i in range(1, len(xs))]


def _corr(xs: Sequence[float], ys: Sequence[float]) -> float:
    n = min(len(xs), len(ys))
    if n < 3:
        return 0.0
    mx = sum(xs[:n]) / n
    my = sum(ys[:n]) / n
    num = dx2 = dy2 = 0.0
    for i in range(n):
        dx = xs[i] - mx
        dy = ys[i] - my
        num += dx * dy
        dx2 += dx * dx
        dy2 += dy * dy
    den = (dx2 * dy2) ** 0.5
    return 0.0 if den <= 1e-12 else num / den


def compute_coupling_signals(
    *,
    a_values: Iterable[float],
    b_values: Iterable[float],
    max_lag: int = 3,
    shock_z: float = 2.5,
) -> Dict[str, float]:
    a = [_safe_float(x) for x in a_values or []]
    b = [_safe_float(x) for x in b_values or []]

    n = min(len(a), len(b))
    a = a[:n]
    b = b[:n]

    if n < 4:
        return {
            "coupling_strength": 0.0,
            "coupling_direction_agreement": 0.0,
            "coupling_best_lag": 0.5,
            "coupling_lag_strength": 0.0,
            "coupling_shock_alignment": 0.0,
            "sample_count_norm": _clamp01(n / 64.0),
        }

    az = _standardize(a)
    bz = _standardize(b)

    # 1) Magnitude coupling
    r0 = _corr(az, bz)
    coupling_strength = _clamp01(abs(r0))

    # 2) Direction agreement (with near-zero handling)
    da = _diff(az)
    db = _diff(bz)

    agree = 0
    valid = 0
    for x, y in zip(da, db):
        if abs(x) < _DIFF_EPS or abs(y) < _DIFF_EPS:
            continue
        valid += 1
        if (x > 0) == (y > 0):
            agree += 1

    coupling_direction_agreement = _clamp01(agree / max(1, valid))

    # 3) Lag coupling (explicit alignment)
    best_lag = 0
    best_r = r0

    for lag in range(-max_lag, max_lag + 1):
        if lag == 0:
            continue

        # lag > 0 aligns az[lag:] with bz[:-lag]
        if lag > 0:
            if n - lag < 3:
                continue
            x = az[lag:]
            y = bz[:-lag]
        else:
            # lag < 0 aligns az[:lag] with bz[-lag:]
            if n + lag < 3:
                continue
            x = az[:lag]
            y = bz[-lag:]

        r = _corr(x, y)
        if abs(r) > abs(best_r):
            best_r = r
            best_lag = lag

    coupling_best_lag = (best_lag + max_lag) / float(2 * max_lag) if max_lag else 0.5
    coupling_best_lag = _clamp01(coupling_best_lag)
    coupling_lag_strength = _clamp01(abs(best_r))

    # 4) Shock alignment (shockless case => perfect calm alignment)
    shock_thr = max(0.5, float(shock_z))
    shock_a = [abs(x) > shock_thr for x in az]
    shock_b = [abs(x) > shock_thr for x in bz]

    any_a = sum(1 for s in shock_a if s)
    any_b = sum(1 for s in shock_b if s)

    if any_a == 0 and any_b == 0:
        coupling_shock_alignment = 1.0
    else:
        both = sum(1 for i in range(n) if shock_a[i] and shock_b[i])
        denom = any_a + any_b - both
        coupling_shock_alignment = _clamp01(both / max(1, denom))

    return {
        "coupling_strength": coupling_strength,
        "coupling_direction_agreement": coupling_direction_agreement,
        "coupling_best_lag": coupling_best_lag,
        "coupling_lag_strength": coupling_lag_strength,
        "coupling_shock_alignment": coupling_shock_alignment,
        "sample_count_norm": _clamp01(n / 64.0),
    }
