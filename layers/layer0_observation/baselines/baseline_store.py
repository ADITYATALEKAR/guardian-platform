"""
baseline_store.py

Layer 0 baseline learning store.

Purpose:
- Maintain rolling baseline statistics per entity_id
- Allow calibrator to read baseline snapshots
- Accept either:
  (a) already-computed metrics dicts, OR
  (b) raw events and extract baseline learning signals

Rules:
- Layer-0 only, deterministic updates
- No semantics / risk interpretation
- No filesystem persistence here (in-memory store)


Importance: Long-term memory

What it does:

Stores historical norms

Supports cold start and long horizon learning

What’s special:

Append-only behavior

Deterministic reads

No overwrites = no memory poisoning

Metaphor:

The black box recorder of normal behavior.
"""

# baseline_store.py
# -------------------------------------------------------------------
# Layer 0 Baseline State Container
#
# Responsibility:
#   - Hold all EntityBaseline objects in memory.
#   - Provide controlled mutation via replace().
#   - Provide deterministic snapshot export for persistence.
#
# This file does NOT:
#   - Compute statistics
#   - Apply EWMA
#   - Access filesystem
#   - Contain business logic
#
# BaselineStore is pure state.
# -------------------------------------------------------------------

from typing import Dict, Optional
from layers.layer0_observation.baselines.baseline_types import EntityBaseline


class BaselineStore:
    """
    In-memory baseline registry scoped to a single tenant.

    Keyed by entity_id.
    """

    def __init__(self) -> None:
        # entity_id -> EntityBaseline
        self._entities: Dict[str, EntityBaseline] = {}

    # ------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------

    def get(self, entity_id: str) -> Optional[EntityBaseline]:
        return self._entities.get(entity_id)

    def replace(self, entity_id: str, baseline: EntityBaseline) -> None:
        """
        Replace baseline for entity.
        Mutation is controlled and explicit.
        """
        self._entities[entity_id] = baseline

    # ------------------------------------------------------------
    # Hydration / Snapshot
    # ------------------------------------------------------------

    def hydrate(self, baselines: Dict[str, EntityBaseline]) -> None:
        """
        Load from persisted state.
        """
        self._entities = dict(baselines)

    def snapshot(self) -> Dict[str, EntityBaseline]:
        """
        Return full snapshot for persistence.
        """
        return dict(self._entities)
