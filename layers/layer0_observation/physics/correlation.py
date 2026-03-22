"""
### Implement **correlation.py** (multi-signal coupling & resonance)

This is a **major Layer 0 milestone**.

Correlation answers:

> “Are multiple independent signals starting to move together?”

That is **not noise**.
That is **system-level instability**.

Correlation is how you detect:

* coordinated degradation
* hidden causal coupling
* pre-collapse resonance
* attacker-induced synchronization

Still **no meaning**.
Still **no interpretation**.
Just math.

---

## LOCK THE DEFINITION (VERY IMPORTANT)

Correlation here means:

> **Statistical dependency between two numeric signal series over time**

We compute:

* Pearson correlation coefficient

Nothing else.

No ML.
No causality claims.
No labels.

---

## INPUTS (STRICT)

* `series_a: list[float]`
* `series_b: list[float]`
* Same length
* Ordered oldest → newest

---

## OUTPUT (STRICT)

```python
{
  "correlation": float
}
```

Value range:

* `+1.0` → perfectly coupled
* `0.0` → independent
* `-1.0` → inverse



## WHY THIS MATTERS (FOUNDATIONALLY)

Single signals lie.

Correlated signals **don’t**.

When:

* entropy decay
* jitter instability
* fallback frequency
* drift acceleration

…start moving together →
**the system is entering a dangerous phase**.

This is exactly how:

* bridges fail
* engines fail
* ecosystems collapse
* financial systems break

"""





import math


def compute_correlation(series_a: list[float], series_b: list[float]) -> dict:
    """
    Computes Pearson correlation coefficient between two time series.
    """

    if len(series_a) != len(series_b) or len(series_a) < 2:
        return {"correlation": 0.0}

    mean_a = sum(series_a) / len(series_a)
    mean_b = sum(series_b) / len(series_b)

    num = 0.0
    den_a = 0.0
    den_b = 0.0

    for a, b in zip(series_a, series_b):
        da = a - mean_a
        db = b - mean_b
        num += da * db
        den_a += da ** 2
        den_b += db ** 2

    if den_a == 0 or den_b == 0:
        return {"correlation": 0.0}

    correlation = num / math.sqrt(den_a * den_b)

    return {"correlation": correlation}
