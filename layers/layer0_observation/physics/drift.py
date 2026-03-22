"""
WHY THIS STEP MATTERS (VERY IMPORTANT)

With jitter you can say:

“Something is unstable right now.”

With drift you can say:

“Instability is increasing or decreasing.”

This is the first brick of prediction later


What it measures

Slow deviation over time

Special

Detects long-game attacks

ML usually misses this

Metaphor

Continental drift, not earthquakes.
"""


def compute_drift(
        previous_value: float,
        current_value: float,
        time_delta_seconds:float
) -> float:
    
    if time_delta_seconds <= 0:
        return 0.0
    
    return (current_value - previous_value)/ time_delta_seconds