"""
Layer 0 fingerprints package.

IMPORTANT:
- Keep this module intentionally minimal.
- Do not eagerly import every fingerprint builder because missing/renamed functions
  would break Layer-0 import at runtime (and during test collection).
"""

from .fingerprint_types import Fingerprint

__all__ = ["Fingerprint"]
