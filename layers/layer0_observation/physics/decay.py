"""
### Implement **decay.py** (long-term degradation / half-life)

This measures **slow trust degradation** — not spikes, not oscillations.

Decay answers:

> “Is this signal losing strength over time, even if it looks stable short-term?”

This is critical for:

* entropy decay
* key fatigue
* long-lived identity rot
* silent pre-failure states

---

## LOCK THE DEFINITION (NON-NEGOTIABLE)

**Decay = exponential degradation rate across time**

We do **not** assume cause.
We do **not** label meaning.

We compute:

* decay rate
* half-life

Pure math.

---

## INPUTS (STRICT)

* `values: list[float]`
* Ordered from **oldest → newest**

---

## OUTPUT (STRICT)

Return a dictionary:

```python
{
  "decay_rate": float,
  "half_life": float | None
}
```

* `decay_rate > 0` → degradation
* `half_life = time units until value halves`
* If no decay → `half_life = None`



WHY THIS IS FOUNDATIONAL

Decay captures slow failures:

harvested-now-decrypt-later prep

entropy exhaustion

long-lived cert fatigue

quiet downgrade creep

These never spike.
They rot.

"""


import math


def compute_decay(values: list[float]) -> dict:
    """
    Computes exponential decay rate and half-life.
    """

    n = len(values)
    if n < 2:
        return {"decay_rate": 0.0, "half_life": None}

    start = values[0]
    end = values[-1]

    if start <= 0 or end <= 0:
        return {"decay_rate": 0.0, "half_life": None}

    # decay rate lambda
    decay_rate = math.log(start / end) / n

    if decay_rate <= 0:
        return {"decay_rate": 0.0, "half_life": None}

    half_life = math.log(2) / decay_rate

    return {
        "decay_rate": decay_rate,
        "half_life": half_life
    }
