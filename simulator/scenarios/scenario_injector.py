"""
Scenario Injector
=================

Deterministic injection of synthetic deltas into baseline observations.

No runtime layer imports.
No storage access.
"""

from typing import Any, Dict, List

from simulator.scenarios.scenario_catalog import AttackScenario
from simulator.core.observation_mutation import (
    apply_field_updates,
    clone_observations,
    select_targets,
)


class ScenarioInjector:
    """
    Applies deterministic injection payloads to baseline observations.

    Observations are cloned before modification to avoid mutating
    production data structures.
    """

    def inject(self, baseline_observations: List[Any], scenario: AttackScenario) -> List[Any]:
        if baseline_observations is None:
            raise ValueError("baseline_observations cannot be None")

        cloned = clone_observations(baseline_observations)
        targets = select_targets(cloned, scenario.target_selector)

        for obs in targets:
            apply_field_updates(obs, scenario.injection_payload)

        return cloned
