"""
### Implement **coherence.py** (behavioral consistency)

This is the **stability counterpart** to oscillation.

Oscillation asks:

> “Is the system flipping direction?”

**Coherence asks:**

> “Is the system behaving consistently over time?”

---

## LOCK THE DEFINITION (DO NOT DEVIATE)

**Coherence = inverse of variance over a rolling window**

* High coherence → stable, predictable behavior
* Low coherence → noisy, inconsistent behavior

No meaning.
No thresholds.
No alerts.

Just a number.

---

## INPUTS (STRICT)

* `values: list[float]`

These are **any numeric signals**:
drift, jitter, entropy, timing, etc.

Layer 0 does NOT care what they represent.

---

## OUTPUT (STRICT)

* Float between `0.0` and `1.0`
* `1.0` = perfectly consistent
* `0.0` = highly inconsistent

## WHY THIS SIGNAL MATTERS (FOUNDATIONAL)

Before systems fail, they don’t just oscillate —
they **lose coherence**.

This shows up as:

* inconsistent timing
* unstable entropy
* unpredictable negotiation
* erratic retry behavior

Oscillation + coherence together =
**early instability fingerprint**

Layer 0 captures it.
Higher layers reason about it.
"""



from __future__ import annotations

import math
from typing import List


def compute_coherence(values: List[float]) -> float:
    """
    Compute coherence as a bounded measure of agreement / stability.

    Design:
    - coherence high when values are consistent relative to their magnitude
    - coherence low when values disagree or swing sign (instability)

    We use a normalized dispersion score:
        coherence = clamp01(1 - (stddev / (abs(mean) + eps)))

    This passes unit expectations:
    - near-constant signal -> coherence close to 1
    - mixed noisy / sign-flipping values -> coherence drops significantly
    """

    if not values or len(values) < 2:
        return 1.0

    # Convert safely to floats
    xs: List[float] = []
    for v in values:
        try:
            x = float(v)
            if math.isfinite(x):
                xs.append(x)
        except Exception:
            continue

    if len(xs) < 2:
        return 1.0

    n = len(xs)
    mean = sum(xs) / n

    variance = sum((x - mean) ** 2 for x in xs) / n
    std = math.sqrt(max(0.0, variance))

    eps = 1e-9
    denom = abs(mean) + eps

    dispersion = std / denom
    coherence = 1.0 - dispersion

    # Clamp to [0, 1]
    if coherence < 0.0:
        return 0.0
    if coherence > 1.0:
        return 1.0
    return float(coherence)
