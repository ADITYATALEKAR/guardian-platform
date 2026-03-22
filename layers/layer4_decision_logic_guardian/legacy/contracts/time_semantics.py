from dataclasses import dataclass

@dataclass(frozen=True)
class ObservationWindow:
    """
    Defines the temporal scope of observations.
    """
    start_utc: str               # ISO 8601
    end_utc: str                 # ISO 8601
    duration_days: int           # exact 24h days
