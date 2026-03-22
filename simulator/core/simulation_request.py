"""
Simulation Request Contract (v1)
================================

Deterministic simulation request schema.
Frozen until Layer 5 UI integration.
"""

from dataclasses import dataclass
from typing import Dict, Any, Optional, List, Literal

SCHEMA_VERSION = "v1"


@dataclass(frozen=True, slots=True)
class SimulationRequest:
    tenant_id: str
    baseline_cycle_id: str
    cycle_number: int
    scenario_id: str
    scenario_params: Dict[str, Any]
    critical_entities: Optional[List[Any]] = None
    mitigation: Optional[Dict[str, Any]] = None
    replay_cycles: int = 1
    path_mode: Literal["SAFE", "EXTENDED", "DEEP"] = "SAFE"
    max_paths: int = 50
    max_mitigations: int = 1
    severity_threshold: float = 0.55
