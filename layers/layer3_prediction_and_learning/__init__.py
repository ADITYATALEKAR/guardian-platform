"""
Layer 3 — Prediction & Learning

Exports:
- Layer3Engine + config
- PredictionBundle / PredictionSignal contracts

This keeps import paths stable for tests and downstream layers.
"""

from .layer3_engine import Layer3Engine, Layer3EngineConfig
from .prediction_contracts import PredictionBundle, PredictionSignal

__all__ = [
    "Layer3Engine",
    "Layer3EngineConfig",
    "PredictionBundle",
    "PredictionSignal",
]
