"""
Observation Adapter
===================

Deterministic reconstruction of RawObservation inputs for SnapshotBuilder.

No runtime mutations.
No storage access.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, List
import hashlib

from infrastructure.unified_discovery_v2.models import RawObservation as SnapshotRawObservation
from layers.layer0_observation.acquisition.protocol_observer import (
    RawObservation as ProtocolRawObservation,
    DNSObservation,
    TCPObservation,
    TLSObservation,
    HTTPObservation,
)


@dataclass(frozen=True, slots=True)
class ObservationRecord:
    endpoint: str
    entity_id: str
    timestamp_ms: int
    tls_version: str | None
    certificate_sha256: str | None
    certificate_expiry_unix_ms: int | None
    ip: str | None
    cipher: str | None
    cert_issuer: str | None
    entropy_score: float | None
    confidence: float
    ports_open: List[int]
    services: List[str]
    source_method: str
    success: bool


class ObservationAdapter:
    """
    Build deterministic RawObservation inputs from baseline snapshots.
    """

    def observations_from_snapshot(self, snapshot: Dict[str, Any]) -> List[ObservationRecord]:
        endpoints = snapshot.get("endpoints", [])
        ts_ms = int(snapshot.get("timestamp_unix_ms", 0))

        out: List[ObservationRecord] = []
        for e in endpoints:
            if not isinstance(e, dict):
                continue
            hostname = str(e.get("hostname", ""))
            port = int(e.get("port", 0)) if e.get("port") is not None else 0
            endpoint = f"{hostname}:{port}"

            discovered_by = e.get("discovered_by", [])
            if isinstance(discovered_by, list) and discovered_by:
                source_method = str(sorted(discovered_by)[0])
            else:
                source_method = "snapshot"

            confidence = float(e.get("confidence", 0.0)) if e.get("confidence") is not None else 0.0
            tls_version = e.get("tls_version", None)
            cert_sha = e.get("certificate_sha256", None)
            cert_exp = e.get("certificate_expiry_unix_ms", None)

            ports_open = list(e.get("ports_responding", []) or [])
            services = list(e.get("services_detected", []) or [])

            success = bool(confidence > 0.0 or tls_version or cert_sha)

            out.append(
                ObservationRecord(
                    endpoint=endpoint,
                    entity_id=endpoint,
                    timestamp_ms=ts_ms,
                    tls_version=tls_version,
                    certificate_sha256=cert_sha,
                    certificate_expiry_unix_ms=cert_exp,
                    ip=e.get("ip", None),
                    cipher=e.get("cipher", None),
                    cert_issuer=e.get("cert_issuer", None),
                    entropy_score=e.get("entropy_score", None),
                    confidence=confidence,
                    ports_open=ports_open,
                    services=services,
                    source_method=source_method,
                    success=success,
                )
            )

        return out

    def to_dict(self, record: ObservationRecord) -> Dict[str, Any]:
        return asdict(record)

    def from_dict(self, data: Dict[str, Any]) -> ObservationRecord:
        return ObservationRecord(
            endpoint=str(data.get("endpoint", "")),
            entity_id=str(data.get("entity_id", "")),
            timestamp_ms=int(data.get("timestamp_ms", 0)),
            tls_version=data.get("tls_version", None),
            certificate_sha256=data.get("certificate_sha256", None),
            certificate_expiry_unix_ms=data.get("certificate_expiry_unix_ms", None),
            ip=data.get("ip", None),
            cipher=data.get("cipher", None),
            cert_issuer=data.get("cert_issuer", None),
            entropy_score=data.get("entropy_score", None),
            confidence=float(data.get("confidence", 0.0)),
            ports_open=list(data.get("ports_open", []) or []),
            services=list(data.get("services", []) or []),
            source_method=str(data.get("source_method", "snapshot")),
            success=bool(data.get("success", False)),
        )

    def to_protocol_raw(self, record: ObservationRecord) -> ProtocolRawObservation:
        obs_id = self._stable_observation_id(record.endpoint, record.timestamp_ms)

        dns = DNSObservation(
            resolved_ip=record.ip,
            resolution_time_ms=0.0,
            error=None,
        )
        tcp = TCPObservation(
            connected=True if record.success else False,
            connect_time_ms=0.0,
            error=None,
        )
        tls = TLSObservation(
            handshake_time_ms=0.0 if record.tls_version else None,
            tls_version=record.tls_version,
            cipher_suite=record.cipher,
            cipher_suites=[record.cipher] if record.cipher else [],
            cert_extension_hints=[],
            supported_groups=[],
            signature_algorithms=[],
            cert_subject=None,
            cert_issuer=record.cert_issuer,
            cert_not_before=None,
            cert_not_after=record.certificate_expiry_unix_ms,
            cert_serial=None,
            cert_fingerprint_sha256=record.certificate_sha256,
            cert_san=[],
            alpn_protocol=None,
            session_resumed=False,
            error=None,
        )

        raw = ProtocolRawObservation(
            endpoint=record.endpoint,
            entity_id=record.entity_id,
            observation_id=obs_id,
            timestamp_ms=int(record.timestamp_ms),
            dns=dns,
            tcp=tcp,
            tls=tls,
            http=None,
            packet_spacing_ms=[],
            rtt_ms=None,
            attempt_protocols=[],
            attempt_path="",
            attempt_count=0,
            probe_duration_ms=0.0,
            success=record.success,
            error=None,
        )

        # Attach entropy_score for SnapshotBuilder enrichment if present
        if record.entropy_score is not None:
            setattr(raw, "entropy_score", float(record.entropy_score))

        return raw

    def to_snapshot_raw(self, record: ObservationRecord) -> SnapshotRawObservation:
        return SnapshotRawObservation(
            endpoint_str=record.endpoint,
            observed_at_unix_ms=int(record.timestamp_ms),
            tls_handshake_success=bool(record.success),
            tls_version=record.tls_version,
            ports_open=list(record.ports_open),
            services=list(record.services),
            certificate_sha256=record.certificate_sha256,
            certificate_expiry_unix_ms=record.certificate_expiry_unix_ms,
            source_method=record.source_method,
            confidence=float(record.confidence),
            error=None,
        )

    def _stable_observation_id(self, endpoint: str, ts_ms: int) -> str:
        payload = f"{endpoint}|{int(ts_ms)}"
        return "simobs_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
