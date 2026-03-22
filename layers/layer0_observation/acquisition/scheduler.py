"""
Layer 0 Acquisition Scheduler
--------------------------------

Executes periodic endpoint observation.

STRICT RULES:
- No tenant awareness
- No storage logic
- No Layer 1–4 interaction
- Only acquisition → bridge → fingerprints

Pure orchestration.
"""

import asyncio
from typing import List

from .protocol_observer import observe_endpoint
from .observation_bridge import ObservationBridge


class Scheduler:
    """
    Executes endpoint observation sweep at fixed cadence.

    Designed for acquisition-only runtime.
    """

    def __init__(
        self,
        endpoints: List[str],
        cadence_seconds: int = 3600,
        max_eps: int = 200,
    ):
        self.endpoints = endpoints
        self.cadence_seconds = cadence_seconds
        self.max_eps = max_eps
        self.bridge = ObservationBridge()

    # =========================================================
    # Single Sweep
    # =========================================================

    async def sweep_once(self):
        """
        Perform one full observation sweep.

        Concurrency limited via semaphore.
        """

        semaphore = asyncio.Semaphore(self.max_eps)

        async def observe_one(endpoint: str):
            async with semaphore:
                # observe_endpoint is synchronous
                # run in thread pool to avoid blocking event loop
                loop = asyncio.get_running_loop()
                raw = await loop.run_in_executor(
                    None,
                    observe_endpoint,
                    endpoint
                )

                fps = self.bridge.process(raw)
                return fps

        tasks = [observe_one(ep) for ep in self.endpoints]
        results = await asyncio.gather(*tasks)

        return results

    # =========================================================
    # Continuous Mode
    # =========================================================

    async def run_forever(self):
        """
        Continuous scheduled sweep.
        """
        while True:
            await self.sweep_once()
            await asyncio.sleep(self.cadence_seconds)