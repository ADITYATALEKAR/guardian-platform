from __future__ import annotations

import threading
import time


class HealthState:
    """
    Tracks system liveness and readiness.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.healthy = True
        self.ready = False
        self.last_successful_cycle: int | None = None
        self.last_failure_timestamp: int | None = None

    def mark_ready(self):
        with self._lock:
            self.ready = True

    def mark_cycle_success(self, cycle_number: int):
        with self._lock:
            self.last_successful_cycle = cycle_number
            self.healthy = True

    def mark_cycle_failure(self):
        with self._lock:
            self.healthy = False
            self.last_failure_timestamp = int(time.time())