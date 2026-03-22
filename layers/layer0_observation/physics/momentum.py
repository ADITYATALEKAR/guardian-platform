"""
### Implement **momentum.py** (second-order temporal physics)

This is the **first second-order signal** in Layer 0.

If drift answers:

> “Is the signal changing?”

Momentum answers:

> “Is the *change itself* accelerating or slowing down?”

This is where Layer 0 quietly becomes powerful.

---

## LOCK THE DEFINITION (DO NOT DEVIATE)

**Momentum = rate of change of drift over time**

Nothing more.

---

## INPUTS (STRICT)

Momentum operates on **drift values**, not raw signals.

You will pass:

* `previous_drift`
* `current_drift`
* `time_delta_seconds`

---

## OUTPUT (STRICT)

* One float
* Positive = accelerating change
* Negative = decelerating change

## WHY THIS STEP IS CRITICAL (CONCEPTUAL, SHORT)

* Drift tells you **movement**
* Momentum tells you **directional force**

This is how later layers will detect:

* escalation
* stabilization
* slow-burn attacks
* pre-failure behavior

But **Layer 0 still does not interpret**.

It only reports numbers.

"""



def compute_momentum(
        previous_drift: float,
        current_drift: float,
        time_delta_seconds: float
) -> float:
    if time_delta_seconds <=0:
        return 0.0
    
    return(current_drift - previous_drift)/ time_delta_seconds