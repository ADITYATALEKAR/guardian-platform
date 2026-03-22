"""
What it measures

Variance at micro and macro scales

Special

Jitter ≠ noise

Jitter = intent + instability

Metaphor

Hand tremor under stress
"""

import math
from typing import List

def compute_jitter(packet_spacing_ms: List[float]) -> float:
    if not packet_spacing_ms or len(packet_spacing_ms) < 2:
        return 0.0
    
    mean = sum(packet_spacing_ms) / len(packet_spacing_ms)

    variance = sum(
        (x - mean) ** 2 for x in packet_spacing_ms
    ) / len(packet_spacing_ms)

    return math.sqrt(variance)