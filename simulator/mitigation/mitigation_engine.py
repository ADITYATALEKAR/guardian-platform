"""
Mitigation Engine
=================

Applies deterministic mitigation deltas to synthetic observations.

No storage access.
No runtime layer imports.
"""

from typing import Any, Dict, List

from simulator.mitigation.mitigation_actions import MitigationAction
from simulator.core.observation_mutation import (
    apply_field_updates,
    clone_observations,
    select_targets,
)


class MitigationEngine:
    """
    Apply mitigation deltas in a sandbox only.
    """

    def apply(self, observations: List[Any], action: MitigationAction) -> List[Any]:
        if observations is None:
            raise ValueError("observations cannot be None")

        cloned = clone_observations(observations)
        targets = select_targets(cloned, action.target)

        for obs in targets:
            apply_field_updates(obs, action.delta)

        return cloned
