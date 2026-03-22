"""
NEXT IMMEDIATE ACTION — STEP 13
Implement resonance.py (third-order physics)
This is the highest-order signal in Layer 0.
Resonance answers one question only:
“Are multiple independent signals amplifying together beyond normal variance?”
This is how real systems fail.
Not because one thing goes wrong —
but because many small instabilities synchronize.
Still:
•	no meaning
•	no risk
•	no prediction
•	no Guardian logic
Pure physics.
________________________________________
LOCK THE DEFINITION (CRITICAL)
Resonance here means:
Multiple normalized signals simultaneously exceeding their historical baseline by a threshold.
This is not correlation.
Correlation = relationship over time.
Resonance = simultaneous amplification.
________________________________________
INPUTS (STRICT)
signals: dict[str, list[float]]
threshold: float  # default = 2.0
Each signal list:
•	numeric
•	same length
•	normalized beforehand
________________________________________
OUTPUT (STRICT)
{
  "resonance_score": float,
  "active_signals": int
}
Where:
•	resonance_score ∈ [0.0, 1.0]
•	active_signals = number of signals exceeding threshold


WHY THIS MATTERS (FOUNDATIONALLY)

Single spikes = noise
Correlation = relationship
Resonance = system instability

This is how you detect:

coordinated attacker probing

cascading cryptographic failure

pre-compromise system stress

trust collapse before any explicit break

No scanner in the market does this.
"""




def compute_resonance(signals: dict[str, list[float]], threshold: float = 2.0) -> dict:
    """
    Detects multi-signal resonance by checking how many signals
    exceed a normalized threshold at the same timestep.
    """

    if not signals:
        return {"resonance_score": 0.0, "active_signals": 0}

    signal_names = list(signals.keys())
    length = len(signals[signal_names[0]])

    if any(len(v) != length for v in signals.values()):
        return {"resonance_score": 0.0, "active_signals": 0}

    resonance_events = 0
    total_events = length * len(signals)

    for t in range(length):
        active = 0
        for series in signals.values():
            if abs(series[t]) >= threshold:
                active += 1

        if active >= 2:
            resonance_events += active

    resonance_score = resonance_events / total_events if total_events > 0 else 0.0

    return {
        "resonance_score": resonance_score,
        "active_signals": resonance_events
    }
