"""
Observation Mutation Utilities
==============================

Shared deterministic selector/get/set helpers for scenario injection and
mitigation application.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List


def clone_observations(observations: List[Any]) -> List[Any]:
    return [deepcopy(o) for o in observations]


def select_targets(observations: List[Any], selector: Dict[str, Any]) -> List[Any]:
    if not selector:
        return []

    if selector.get("all") is True:
        return list(observations)

    if "index" in selector:
        idx = int(selector["index"])
        if idx < 0 or idx >= len(observations):
            return []
        return [observations[idx]]

    if "entity_id" in selector:
        target = selector["entity_id"]
        return [o for o in observations if get_field(o, "entity_id") == target or get_field(o, "endpoint") == target]

    return []


def apply_field_updates(obs: Any, updates: Dict[str, Any]) -> None:
    for key, value in updates.items():
        set_field(obs, key, value)


def get_field(obs: Any, key: str) -> Any:
    if isinstance(obs, dict):
        return obs.get(key)
    return getattr(obs, key, None)


def set_field(obs: Any, key: str, value: Any) -> None:
    if isinstance(obs, dict):
        obs[key] = value
        return
    if hasattr(obs, key):
        try:
            setattr(obs, key, value)
            return
        except Exception as exc:
            raise TypeError(f"Cannot set attribute '{key}' on observation object") from exc
    if hasattr(obs, "__dict__"):
        obs.__dict__[key] = value
        return
    raise TypeError("Unsupported observation type for mutation")

