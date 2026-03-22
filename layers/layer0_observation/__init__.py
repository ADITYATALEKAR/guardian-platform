"""
Importance: Structural

What it does:

Exposes Layer 0 as a clean module

Prevents accidental imports from deeper layers

Metaphor:

The sealed lab door

"""

# layers/layer0_observation/__init__.py

from .observe import observe_timing_batch

__all__ = ["observe_timing_batch"]
