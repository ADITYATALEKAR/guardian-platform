"""
Layer 0 Acquisition Module

Sensor layer for Layer 0.
Provides raw network observations and bridge into physics engine.

No mock generation.
No entropy calculation.
No physics logic.
"""

from .protocol_observer import (
    observe_endpoint,
    observe_endpoints,
)

from .observation_bridge import (
    ObservationBridge,
)




__all__ = [
    "observe_endpoint",
    "observe_endpoints",
    "ObservationBridge",
]
