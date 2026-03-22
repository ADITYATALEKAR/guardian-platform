"""
Implement oscillation.py (instability detection)

This is the first instability detector in Layer 0.

Drift = movement
Momentum = acceleration
Oscillation = instability

Oscillation answers:

“Is the system repeatedly changing direction instead of converging?”

Oscillation = frequency of sign changes in drift over time

WHY THIS SIGNAL MATTERS (SHORT, FOUNDATIONAL)

Stable systems converge.
Unstable systems oscillate before failure.

This is true in:

bridges

engines

markets

nervous systems

cryptographic trust systems

Oscillation is the warning tremor before collapse.

Layer 0 captures it.
Later layers decide what it means.

"""



def compute_oscillation(drift_history: list[float]) -> float:
    """
    Computes oscillation index as ratio of sign changes in drift.
    """

    if len(drift_history) < 3:
        return 0.0

    sign_changes = 0
    total_transitions = 0

    for i in range(1, len(drift_history)):
        prev = drift_history[i - 1]
        curr = drift_history[i]

        if prev == 0:
            continue

        total_transitions += 1

        if (prev > 0 and curr < 0) or (prev < 0 and curr > 0):
            sign_changes += 1

    if total_transitions == 0:
        return 0.0

    return sign_changes / total_transitions
