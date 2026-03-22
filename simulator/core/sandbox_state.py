"""
Simulation Sandbox State
========================

Immutable container for baseline snapshots and staged deltas.
"""

from dataclasses import dataclass
from typing import Dict, Any, Optional, List


@dataclass(frozen=True, slots=True)
class BaselineBundle:
    layer0_snapshot: Dict[str, Any]
    trust_graph_snapshot: Dict[str, Any]
    layer3_snapshot: Optional[Dict[str, Any]] = None


@dataclass(frozen=True, slots=True)
class SimulationSandboxState:
    baseline: BaselineBundle
    deltas: List[Dict[str, Any]]
