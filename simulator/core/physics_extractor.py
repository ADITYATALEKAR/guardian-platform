"""
Physics Signal Extractor
========================

Deterministic extraction of physics_signals from Layer0 fingerprints.
Delegates to shared runtime helper used by orchestrator + simulator.
"""

from __future__ import annotations

from typing import Any, Dict, Sequence

from infrastructure.unified_discovery_v2.weakness_inputs import (
    extract_physics_signals as _extract_shared_physics_signals,
)


def extract_physics_signals(fps: Sequence[Any]) -> Dict[str, float]:
    return _extract_shared_physics_signals(fps)
