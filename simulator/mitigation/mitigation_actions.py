"""
Mitigation Actions
==================

Deterministic mitigation action definitions.
"""

from dataclasses import dataclass
from typing import Dict, Any


@dataclass(frozen=True, slots=True)
class MitigationAction:
    action_type: str
    target: Dict[str, Any]
    delta: Dict[str, Any]
    description: str
