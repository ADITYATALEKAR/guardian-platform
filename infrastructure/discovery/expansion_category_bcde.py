"""
Category BCDE compatibility facade.

Primary implementation moved to:
  infrastructure.discovery.expansion_bcde.impl
"""

from infrastructure.discovery.expansion_bcde.impl import *  # noqa: F401,F403
from infrastructure.discovery.expansion_a.impl import (  # backward-compatible exports
    NodeType,
    PassiveDiscoveryGraph,
)
