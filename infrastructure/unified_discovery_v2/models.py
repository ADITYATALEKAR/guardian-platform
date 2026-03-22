from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Dict, Optional
from enum import Enum


# ============================================================
# ENUMS
# ============================================================

class CycleStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ============================================================
# RAW OBSERVATION (PRE-CANONICAL INPUT)
# ============================================================

@dataclass(frozen=True)
class RawObservation:
    endpoint_str: str
    observed_at_unix_ms: int

    tls_handshake_success: bool
    tls_version: Optional[str]

    ports_open: List[int]
    services: List[str]

    certificate_sha256: Optional[str]
    certificate_expiry_unix_ms: Optional[int]

    source_method: str
    confidence: float

    error: Optional[str] = None


# ============================================================
# CANONICAL ENDPOINT (IMMUTABLE SNAPSHOT RECORD)
# ============================================================

@dataclass(frozen=True)
class CanonicalEndpoint:
    hostname: str
    port: int

    tls_version: Optional[str]
    certificate_sha256: Optional[str]
    certificate_expiry_unix_ms: Optional[int]

    ports_responding: List[int]
    services_detected: List[str]

    discovered_by: List[str]
    confidence: float

    tls_jarm: Optional[str]

    ip: Optional[str] = None
    asn: Optional[str] = None
    cipher: Optional[str] = None
    cert_issuer: Optional[str] = None
    entropy_score: Optional[float] = None
    observation_state: str = "observed"
    last_observed_cycle: Optional[int] = None
    last_observed_unix_ms: Optional[int] = None

    def endpoint_id(self) -> str:
        return f"{self.hostname}:{self.port}"

    def to_dict(self) -> Dict:
        return {
            "hostname": self.hostname,
            "port": self.port,
            "tls_version": self.tls_version,
            "certificate_sha256": self.certificate_sha256,
            "certificate_expiry_unix_ms": self.certificate_expiry_unix_ms,
            "ip": self.ip,
            "asn": self.asn,
            "cipher": self.cipher,
            "cert_issuer": self.cert_issuer,
            "entropy_score": self.entropy_score,
            "observation_state": self.observation_state,
            "last_observed_cycle": self.last_observed_cycle,
            "last_observed_unix_ms": self.last_observed_unix_ms,
            "ports_responding": sorted(set(self.ports_responding)),
            "services_detected": sorted(set(self.services_detected)),
            "discovered_by": sorted(set(self.discovered_by)),
            "confidence": round(self.confidence, 4) if self.confidence is not None else None,
            "tls_jarm": self.tls_jarm,
        }


# ============================================================
# SNAPSHOT DIFF STRUCTURES
# ============================================================

@dataclass(frozen=True)
class EndpointChange:
    endpoint_id: str
    changes: Dict[str, Dict[str, object]]  # field -> {old, new}


@dataclass(frozen=True)
class SnapshotDiff:
    new_endpoints: List[str]
    removed_endpoints: List[str]
    changed_endpoints: List[EndpointChange]
    unchanged_endpoints: List[str]


# ============================================================
# SNAPSHOT BUILD STATS
# ============================================================

@dataclass(frozen=True)
class SnapshotBuildStats:
    total_observations: int
    successful_observations: int
    failed_observations: int
    duplicates_merged: int
    endpoints_canonical: int
    duration_ms: int
    discovered_related_endpoints: int = 0
    observation_attempts: int = 0
    observation_successes: int = 0
    observation_failures: int = 0
    recorded_endpoints: int = 0
    unverified_historical_endpoints: int = 0
    surface_endpoints: int = 0
    stale_endpoints: int = 0
    total_discovered_domains: int = 0
    total_successful_observations: int = 0
    total_failed_observations: int = 0
    posture_summary: Dict[str, Any] = field(default_factory=dict)
    expansion_summary: Dict[str, Any] = field(default_factory=dict)


# ============================================================
# DISCOVERY SNAPSHOT (IMMUTABLE + HASHED)
# ============================================================

@dataclass(frozen=True)
class DiscoverySnapshot:
    schema_version: str
    cycle_id: str
    cycle_number: int
    timestamp_unix_ms: int

    endpoints: List[CanonicalEndpoint]

    snapshot_hash_sha256: str
    endpoint_count: int

    def to_dict(self) -> Dict:
        return {
            "schema_version": self.schema_version,
            "cycle_id": self.cycle_id,
            "cycle_number": self.cycle_number,
            "timestamp_unix_ms": self.timestamp_unix_ms,
            "snapshot_hash_sha256": self.snapshot_hash_sha256,
            "endpoint_count": self.endpoint_count,
            "endpoints": [e.to_dict() for e in self.endpoints],
        }


# ============================================================
# TEMPORAL CHANGE RECORDS (FULL HISTORY)
# ============================================================

@dataclass
class TLSChangeRecord:
    cycle_number: int
    timestamp_unix_ms: int
    old_value: Optional[str]
    new_value: Optional[str]


@dataclass
class PortChangeRecord:
    cycle_number: int
    timestamp_unix_ms: int
    old_ports: List[int]
    new_ports: List[int]


@dataclass
class CertificateChangeRecord:
    cycle_number: int
    timestamp_unix_ms: int
    old_sha256: Optional[str]
    new_sha256: Optional[str]


@dataclass
class PresenceRecord:
    cycle_number: int
    timestamp_unix_ms: int
    present: bool


# ============================================================
# TEMPORAL ENDPOINT STATE (STRICTLY OBSERVATION-ONLY)
# ============================================================

@dataclass
class TemporalEndpointState:
    endpoint_id: str

    first_observed_cycle: int
    last_observed_cycle: int

    # Full presence history (no bitmap truncation)
    presence_history: List[PresenceRecord] = field(default_factory=list)

    # Full change histories
    tls_change_history: List[TLSChangeRecord] = field(default_factory=list)
    port_change_history: List[PortChangeRecord] = field(default_factory=list)
    certificate_change_history: List[CertificateChangeRecord] = field(default_factory=list)

    # Derived observation metrics (NOT RISK)
    consecutive_absence: int = 0
    volatility_score: float = 0.0
    visibility_score: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "endpoint_id": self.endpoint_id,
            "first_observed_cycle": self.first_observed_cycle,
            "last_observed_cycle": self.last_observed_cycle,
            "presence_history": [vars(p) for p in self.presence_history],
            "tls_change_history": [vars(c) for c in self.tls_change_history],
            "port_change_history": [vars(c) for c in self.port_change_history],
            "certificate_change_history": [vars(c) for c in self.certificate_change_history],
            "consecutive_absence": self.consecutive_absence,
            "volatility_score": round(self.volatility_score, 6),
            "visibility_score": round(self.visibility_score, 6),
        }


# ============================================================
# TEMPORAL STATE (SINGLE MUTABLE FILE)
# ============================================================

@dataclass
class TemporalState:
    schema_version: str
    last_cycle_id: str
    last_cycle_number: int
    endpoints: Dict[str, TemporalEndpointState] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "schema_version": self.schema_version,
            "last_cycle_id": self.last_cycle_id,
            "last_cycle_number": self.last_cycle_number,
            "endpoints": {
                endpoint_id: state.to_dict()
                for endpoint_id, state in self.endpoints.items()
            },
        }


# ============================================================
# RATE CONTROLLER STATS
# ============================================================

@dataclass(frozen=True)
class RateControllerStats:
    total_attempts: int
    successful: int
    rate_limited: int
    timeout: int
    errors: int
    backoff_events: int
    circuit_breaker_trips: int


# ============================================================
# CYCLE METADATA (APPEND-ONLY)
# ============================================================

@dataclass(frozen=True)
class CycleMetadata:
    schema_version: str
    cycle_id: str
    cycle_number: int
    timestamp_unix_ms: int
    duration_ms: int
    status: CycleStatus

    endpoints_scanned: int
    new_endpoints: int
    removed_endpoints: int

    snapshot_hash: str

    rate_limited_events: int
    error_messages: List[str]


# ============================================================
# CYCLE RESULT WRAPPER (IN-MEMORY ARTIFACT)
# ============================================================

@dataclass(frozen=True)
class CycleResult:
    metadata: CycleMetadata
    snapshot: DiscoverySnapshot
    previous_snapshot_hash: Optional[str]
    diff: SnapshotDiff
    rate_controller_stats: RateControllerStats
    build_stats: SnapshotBuildStats
