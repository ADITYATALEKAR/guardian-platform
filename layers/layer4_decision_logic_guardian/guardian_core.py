"""
Compatibility shim.

GuardianCore has moved to core/guardian_core.py.
This module preserves the legacy import path:
  layers.layer4_decision_logic_guardian.guardian_core.GuardianCore
"""

from .core.guardian_core import GuardianCore

__all__ = ["GuardianCore"]
