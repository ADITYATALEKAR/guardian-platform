#Batch 1 → Timing & Motion
# inputs: timestamp, rtt, spacing
"""
For Batch 1: Timing & Motion Physics, you are modeling motion over time.

To do that, you need exactly three things:

Input	Why it is required
timestamp_ms	Defines time axis (without time, no motion exists)
rtt_ms	The position of the system at that time
packet_spacing_ms	The micro-motion inside the event

This maps cleanly to physics:

timestamp → time (t)

RTT → position (x)

packet spacing → micro-velocity / vibration

From these three, you can derive:

jitter (variance)

drift (dx/dt)

momentum (d²x/dt²)

oscillation (frequency)

coherence (stability)




Importance: Primary sensor

What it does

Captures latency, ordering, timing jitter

No interpretation

What’s special

Time is your core primitive

Timing lies are the earliest signal of compromise

Metaphor

A high-speed camera, not an image classifier
"""


from typing import Dict, List


class TimingCollectorError(Exception):
    pass


def collect_timing_event(raw: Dict) -> Dict:
    """
    Collects and validates raw timing metadata.
    This function performs NO interpretation or physics.
    """

    required_fields = ["timestamp_ms", "rtt_ms", "packet_spacing_ms"]

    for field in required_fields:
        if field not in raw:
            raise TimingCollectorError(f"Missing required field: {field}")

    timestamp_ms = raw["timestamp_ms"]
    rtt_ms = raw["rtt_ms"]
    packet_spacing_ms = raw["packet_spacing_ms"]

    if not isinstance(timestamp_ms, int):
        raise TimingCollectorError("timestamp_ms must be int")

    if not isinstance(rtt_ms, (int, float)):
        raise TimingCollectorError("rtt_ms must be numeric")

    if not isinstance(packet_spacing_ms, list):
        raise TimingCollectorError("packet_spacing_ms must be a list")

    if not all(isinstance(x, (int, float)) for x in packet_spacing_ms):
        raise TimingCollectorError("packet_spacing_ms must contain only numbers")

    return {
        "timestamp_ms": int(timestamp_ms),
        "rtt_ms": float(rtt_ms),
        "packet_spacing_ms": [float(x) for x in packet_spacing_ms],
    }
