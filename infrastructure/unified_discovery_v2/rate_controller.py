from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Optional
from threading import Lock

from .models import RateControllerStats




# ============================================================
# CONFIGURATION
# ============================================================

@dataclass(frozen=True)
class RateControllerConfig:
    max_failures_before_circuit_break: int = 10
    backoff_base_seconds: float = 1.0
    backoff_max_seconds: float = 30.0
    max_rate_limit_retries: int = 10
    enable_circuit_breaker: bool = True


# ============================================================
# INTERNAL TARGET STATE
# ============================================================

class _TargetState:
    """
    Internal per-target state tracking failures and backoff.
    Not exposed outside RateController.
    """

    def __init__(self):
        self.failure_count: int = 0
        self.circuit_open_until: Optional[float] = None
        self.backoff_until: Optional[float] = None


# ============================================================
# RATE CONTROLLER
# ============================================================

class RateController:
    """
    Cycle-scoped deterministic rate controller.

    Responsibilities:
    - Track attempts and outcomes
    - Enforce circuit breaker per target
    - Apply exponential backoff
    - Freeze stats at end of cycle
    - Provide deterministic stats output

    Does NOT:
    - Perform network calls
    - Sleep or block
    - Spawn threads
    """

    def __init__(self, config: Optional[RateControllerConfig] = None):
        self._config = config or RateControllerConfig()

        # Global counters
        self._total_attempts = 0
        self._successful = 0
        self._rate_limited = 0
        self._timeout = 0
        self._errors = 0
        self._backoff_events = 0
        self._circuit_breaker_trips = 0

        # Per-target tracking
        self._targets: Dict[str, _TargetState] = {}

        # Deterministic freeze guard
        self._frozen = False
        self._lock = Lock()

    # ============================================================
    # PUBLIC API
    # ============================================================

    def allow_request(self, target_id: str) -> bool:
        """
        Check whether a request is allowed for this target.

        Does not increment attempt counters.
        """
        with self._lock:
            self._ensure_not_frozen()

            state = self._targets.get(target_id)
            if not state:
                return True

            now = time.time()

            if state.circuit_open_until and now < state.circuit_open_until:
                return False

            if state.backoff_until and now < state.backoff_until:
                return False

            return True

    def max_rate_limit_retries(self) -> int:
        with self._lock:
            return max(0, int(self._config.max_rate_limit_retries))

    def suggested_retry_delay(
        self,
        *,
        attempt: int,
        retry_after_seconds: Optional[float] = None,
    ) -> float:
        attempt_n = max(1, int(attempt))
        if retry_after_seconds is not None:
            try:
                delay = float(retry_after_seconds)
            except Exception:
                delay = self._config.backoff_base_seconds
        else:
            delay = self._config.backoff_base_seconds * (2 ** (attempt_n - 1))
        delay = max(0.0, delay)
        return min(delay, self._config.backoff_max_seconds)

    def register_attempt(self):
        with self._lock:
            self._ensure_not_frozen()
            self._total_attempts += 1

    def register_success(self, target_id: str):
        with self._lock:
            self._ensure_not_frozen()
            self._successful += 1

            state = self._get_or_create_target(target_id)
            state.failure_count = 0
            state.backoff_until = None

    def register_timeout(self, target_id: str):
        with self._lock:
            self._ensure_not_frozen()
            self._timeout += 1
            self._handle_failure(target_id)

    def register_error(self, target_id: str):
        with self._lock:
            self._ensure_not_frozen()
            self._errors += 1
            self._handle_failure(target_id)

    def register_rate_limited(
        self,
        target_id: str,
        retry_after_seconds: Optional[float] = None,
        *,
        attempt: Optional[int] = None,
    ) -> float:
        with self._lock:
            self._ensure_not_frozen()
            self._rate_limited += 1
            self._backoff_events += 1

            state = self._get_or_create_target(target_id)

            delay = self.suggested_retry_delay(
                attempt=max(1, int(attempt or 1)),
                retry_after_seconds=retry_after_seconds,
            )

            state.backoff_until = time.time() + delay
            return delay

    def finalize(self) -> RateControllerStats:
        """
        Freeze and return immutable stats.
        After finalize(), controller cannot be mutated.
        """
        with self._lock:
            if self._frozen:
                raise RuntimeError("RateController already finalized.")

            self._frozen = True

            return RateControllerStats(
                total_attempts=self._total_attempts,
                successful=self._successful,
                rate_limited=self._rate_limited,
                timeout=self._timeout,
                errors=self._errors,
                backoff_events=self._backoff_events,
                circuit_breaker_trips=self._circuit_breaker_trips,
            )

    # ============================================================
    # INTERNAL FAILURE LOGIC
    # ============================================================

    def _handle_failure(self, target_id: str):
        state = self._get_or_create_target(target_id)
        state.failure_count += 1

        # Exponential backoff
        delay = min(
            self._config.backoff_base_seconds * (2 ** (state.failure_count - 1)),
            self._config.backoff_max_seconds,
        )

        state.backoff_until = time.time() + delay
        self._backoff_events += 1

        # Circuit breaker
        if (
            self._config.enable_circuit_breaker
            and state.failure_count >= self._config.max_failures_before_circuit_break
        ):
            state.circuit_open_until = time.time() + self._config.backoff_max_seconds
            self._circuit_breaker_trips += 1

    # ============================================================
    # INTERNAL HELPERS
    # ============================================================

    def _get_or_create_target(self, target_id: str) -> _TargetState:
        if target_id not in self._targets:
            self._targets[target_id] = _TargetState()
        return self._targets[target_id]

    def _ensure_not_frozen(self):
        if self._frozen:
            raise RuntimeError("RateController is frozen after finalize().")
