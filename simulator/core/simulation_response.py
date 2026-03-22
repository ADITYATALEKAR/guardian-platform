"""
Simulation Response Contract (v1)
=================================

Deterministic simulation response schema.
Frozen until Layer 5 UI integration.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = "v1"


@dataclass(frozen=True, slots=True)
class SimulationResponse:
    simulation_id: str
    tenant_id: str
    baseline_cycle_id: str
    scenario_id: str
    scenario_params: Dict[str, Any]
    baseline_guardian: Dict[str, Any]
    simulated_guardian: Dict[str, Any]
    mitigation_guardian: Optional[Dict[str, Any]]
    deltas: Dict[str, Dict[str, float]]
    blast_radius: Dict[str, Any]
    attack_paths: List[Dict[str, Any]]
    critical_impact_summary: Dict[str, Any]
    critical_entity_deltas: Dict[str, Dict[str, float]]
    concentration_metrics: Dict[str, Any]
    mitigation_analysis: Dict[str, Any]
    multi_cycle_projection: Dict[str, Any]
    narrative: Dict[str, Any]
    scenario_progression: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "simulation_id": self.simulation_id,
            "tenant_id": self.tenant_id,
            "baseline_cycle_id": self.baseline_cycle_id,
            "scenario_id": self.scenario_id,
            "scenario_params": dict(self.scenario_params),
            "baseline_guardian": dict(self.baseline_guardian),
            "simulated_guardian": dict(self.simulated_guardian),
            "mitigation_guardian": dict(self.mitigation_guardian) if self.mitigation_guardian else None,
            "deltas": {k: dict(v) for k, v in self.deltas.items()},
            "blast_radius": dict(self.blast_radius),
            "attack_paths": list(self.attack_paths),
            "critical_impact_summary": dict(self.critical_impact_summary),
            "critical_entity_deltas": {k: dict(v) for k, v in self.critical_entity_deltas.items()},
            "concentration_metrics": dict(self.concentration_metrics),
            "mitigation_analysis": dict(self.mitigation_analysis),
            "multi_cycle_projection": dict(self.multi_cycle_projection),
            "narrative": dict(self.narrative),
            "scenario_progression": list(self.scenario_progression),
        }
