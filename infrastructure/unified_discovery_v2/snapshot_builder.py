from __future__ import annotations

import json
import hashlib
import time
from typing import List, Dict, Optional, Any
from collections import defaultdict
from urllib.parse import urlparse

from .models import (
    RawObservation,
    CanonicalEndpoint,
    DiscoverySnapshot,
    SnapshotDiff,
    EndpointChange,
    SnapshotBuildStats,
    TemporalState,
)

from layers.layer0_observation.acquisition.protocol_observer import (
    RawObservation as ProtocolRawObservation,
)


class SnapshotBuilder:
    """
    Deterministic Snapshot Builder

    Responsibilities:
    - Canonicalize endpoints (hostname + port)
    - Merge identity + enrichment deterministically
    - Preserve Layer 0 signal richness (without interpreting it)
    - Produce stable snapshot + diff
    """

    SCHEMA_VERSION = "1.2"
    STALE_RETENTION_ABSENCE_THRESHOLD = 2

    # ============================================================
    # PUBLIC ENTRYPOINT
    # ============================================================

    def build_snapshot(
        self,
        cycle_id: str,
        cycle_number: int,
        raw_observations: List[RawObservation],
        previous_snapshot: Optional[DiscoverySnapshot | Dict[str, Any]] = None,
        previous_temporal_state: Optional[TemporalState | Dict[str, Any]] = None,
        reporting_metrics: Optional[Dict[str, int]] = None,
    ) -> tuple[
        DiscoverySnapshot,
        SnapshotDiff,
        SnapshotBuildStats,
    ]:

        # ------------------------------------------------------------
        # Step 0: Explicit adapter (Layer0 protocol -> snapshot model)
        # ------------------------------------------------------------
        canonical_obs: List[RawObservation] = []
        for obs in raw_observations:
            if isinstance(obs, RawObservation):
                canonical_obs.append(obs)
            else:
                canonical_obs.append(self._convert_protocol_raw_to_snapshot_raw(obs))

        total_observations = len(canonical_obs)
        successful_observations = 0
        failed_observations = 0
        duplicates_merged = 0

        # Deterministic time base: derive from observation timestamps
        ts_values = [
            int(getattr(o, "observed_at_unix_ms", 0) or 0)
            for o in canonical_obs
            if int(getattr(o, "observed_at_unix_ms", 0) or 0) > 0
        ]
        snapshot_timestamp = max(ts_values) if ts_values else int(time.time() * 1000)
        duration_ms = max(0, (max(ts_values) - min(ts_values))) if ts_values else 0

        # ------------------------------------------------------------
        # Step 1: Validate + Deduplicate observations
        # ------------------------------------------------------------

        unique_observations: List[RawObservation] = []
        seen_keys = set()

        for obs in canonical_obs:

            self._validate_observation(obs)

            if not getattr(obs, "success", False):
                failed_observations += 1
                continue

            # Deduplication key must include endpoint identity
            obs_key = (obs.endpoint_str, getattr(obs, "entity_id", None))

            if obs_key in seen_keys:
                duplicates_merged += 1
                continue

            seen_keys.add(obs_key)
            unique_observations.append(obs)
            successful_observations += 1

        # ------------------------------------------------------------
        # Step 2: Merge by canonical endpoint
        # ------------------------------------------------------------

        merged: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "hostname": None,
        "port": None,

        "tls_version": None,
        "certificate_sha256": None,
        "certificate_expiry_unix_ms": None,

        "ip": None,
        "asn": None,
        "cipher": None,
        "cert_issuer": None,
        "entropy_score": None,

        "confidence": None,
        "discovered_by": set(),
            }
        )

        for obs in unique_observations:

            hostname, port = self._split_endpoint(obs.endpoint_str)
            endpoint_id = f"{hostname}:{port}"

            record = merged[endpoint_id]

            record["hostname"] = hostname
            record["port"] = port

            # --------------------------------------------------------
            # Confidence (monotonic max)
            # --------------------------------------------------------

            obs_conf = getattr(obs, "confidence", None)
            if obs_conf is not None:
                record["confidence"] = (
                    float(obs_conf)
                    if record["confidence"] is None
                    else max(record["confidence"], float(obs_conf))
                )

            # --------------------------------------------------------
            # Discovery source tracking
            # --------------------------------------------------------

            source = getattr(obs, "source_method", None)
            if source:
                record["discovered_by"].add(str(source))

            # --------------------------------------------------------
            # Optional enrichment projection
            # --------------------------------------------------------

            for field in (
                "tls_version",
                "certificate_sha256",
                "certificate_expiry_unix_ms",
                "ip",
                "cipher",
                "cert_issuer",
                "entropy_score",
            ):
                value = getattr(obs, field, None)
                if value is not None:
                    record[field] = value

            entropy = getattr(obs, "entropy_score", None)
            if entropy is not None:
                entropy = float(entropy)
                record["entropy_score"] = (
                entropy
                if record["entropy_score"] is None
                else max(record["entropy_score"], entropy)
    )

        # ------------------------------------------------------------
        # Step 3: Build CanonicalEndpoint objects
        # ------------------------------------------------------------

        canonical_endpoints: List[CanonicalEndpoint] = []
        observed_endpoint_ids: set[str] = set()

        for endpoint_id, r in merged.items():
            observed_endpoint_ids.add(endpoint_id)

            canonical_endpoints.append(
                CanonicalEndpoint(
                    hostname=r["hostname"],
                    port=r["port"],
                    tls_version=r["tls_version"],
                    certificate_sha256=r["certificate_sha256"],
                    certificate_expiry_unix_ms=r["certificate_expiry_unix_ms"],
                    ip=r["ip"],
                    asn=r["asn"],
                    cipher=r["cipher"],
                    cert_issuer=r["cert_issuer"],
                    entropy_score=r["entropy_score"],
                    
                    
                    ports_responding=[],          # populated later by physics
                    services_detected=[],          # populated later by physics
                    discovered_by=sorted(r["discovered_by"]),
                    confidence=(
                        round(r["confidence"], 4)
                        if r["confidence"] is not None
                        else None
                    ),
                    tls_jarm=None,
                    observation_state="observed",
                    last_observed_cycle=cycle_number,
                    last_observed_unix_ms=snapshot_timestamp,
                )
            )

        previous_snapshot_model = self._coerce_snapshot(previous_snapshot)
        previous_temporal_absence = self._coerce_temporal_absence(previous_temporal_state)
        stale_endpoints = self._carry_forward_stale_endpoints(
            previous_snapshot=previous_snapshot_model,
            previous_temporal_absence=previous_temporal_absence,
            observed_endpoint_ids=observed_endpoint_ids,
            cycle_number=cycle_number,
        )
        canonical_endpoints.extend(stale_endpoints)

        # Deterministic ordering
        canonical_endpoints.sort(key=lambda e: (e.hostname, e.port))

        # ------------------------------------------------------------
        # Step 4: Deterministic Snapshot Hash
        # ------------------------------------------------------------

        canonical_json = json.dumps(
            [e.to_dict() for e in canonical_endpoints],
            sort_keys=True,
            separators=(",", ":"),
        )

        snapshot_hash = hashlib.sha256(
            canonical_json.encode("utf-8")
        ).hexdigest()

        snapshot = DiscoverySnapshot(
            schema_version=self.SCHEMA_VERSION,
            cycle_id=cycle_id,
            cycle_number=cycle_number,
            timestamp_unix_ms=snapshot_timestamp,
            endpoints=canonical_endpoints,
            snapshot_hash_sha256=snapshot_hash,
            endpoint_count=len(canonical_endpoints),
        )

        # ------------------------------------------------------------
        # Step 5: Diff vs previous snapshot
        # ------------------------------------------------------------

        diff = self._compute_diff(
            current=snapshot,
            previous=previous_snapshot_model,
        )

        # ------------------------------------------------------------
        # Step 6: Build stats
        # ------------------------------------------------------------

        stats = SnapshotBuildStats(
            total_observations=total_observations,
            successful_observations=successful_observations,
            failed_observations=failed_observations,
            duplicates_merged=duplicates_merged,
            endpoints_canonical=len(observed_endpoint_ids),
            duration_ms=duration_ms,
            discovered_related_endpoints=int(
                len((reporting_metrics or {}).get("discovered_surface", []) or [])
                or (reporting_metrics or {}).get("total_discovered_domains", total_observations)
            ),
            observation_attempts=total_observations,
            observation_successes=successful_observations,
            observation_failures=failed_observations,
            recorded_endpoints=len(observed_endpoint_ids),
            unverified_historical_endpoints=max(
                0,
                int(
                    len((reporting_metrics or {}).get("discovered_surface", []) or [])
                    or (reporting_metrics or {}).get("total_discovered_domains", total_observations)
                ) - len(observed_endpoint_ids),
            ),
            surface_endpoints=len(canonical_endpoints),
            stale_endpoints=len(stale_endpoints),
            total_discovered_domains=int(
                (reporting_metrics or {}).get("total_discovered_domains", total_observations)
            ),
            total_successful_observations=int(
                (reporting_metrics or {}).get("total_successful_observations", successful_observations)
            ),
            total_failed_observations=int(
                (reporting_metrics or {}).get("total_failed_observations", failed_observations)
            ),
            posture_summary=dict(
                (reporting_metrics or {}).get("posture_summary", {})
            ),
            expansion_summary=dict(
                (reporting_metrics or {}).get("expansion_summary", {})
            ),
        )

        return snapshot, diff, stats

    # ============================================================
    # INTERNAL HELPERS
    # ============================================================

    def _validate_observation(self, obs: RawObservation) -> bool:
        if not getattr(obs, "endpoint_str", None):
            raise ValueError("SnapshotBuilder: endpoint_str missing in RawObservation")

        if not isinstance(obs.endpoint_str, str):
            raise ValueError("SnapshotBuilder: endpoint_str must be str")

        if not obs.endpoint_str.strip():
            raise ValueError("SnapshotBuilder: endpoint_str empty")

        if getattr(obs, "observed_at_unix_ms", 0) <= 0:
            raise ValueError("SnapshotBuilder: observed_at_unix_ms must be positive")

        conf = getattr(obs, "confidence", None)
        if not isinstance(conf, (int, float)):
            raise ValueError("SnapshotBuilder: confidence missing or non-numeric")
        if float(conf) < 0.0 or float(conf) > 1.0:
            raise ValueError("SnapshotBuilder: confidence out of [0,1]")

        return True

    # ============================================================
    # Adapter: protocol RawObservation -> snapshot RawObservation
    # ============================================================

    def _convert_protocol_raw_to_snapshot_raw(
        self,
        protocol_raw: ProtocolRawObservation,
    ) -> RawObservation:
        """
        Convert Layer0 protocol observer RawObservation into snapshot RawObservation.

        Mapping:
          endpoint_str              <- protocol_raw.endpoint
          observed_at_unix_ms       <- protocol_raw.timestamp_ms
          tls_handshake_success     <- protocol_raw.tls.handshake_time_ms (and no tls.error)
          tls_version               <- protocol_raw.tls.tls_version
          certificate_sha256        <- protocol_raw.tls.cert_fingerprint_sha256
          certificate_expiry_unix_ms<- parse(protocol_raw.tls.cert_not_after)
          ip                        <- protocol_raw.dns.resolved_ip
          cipher                    <- protocol_raw.tls.cipher_suite
          cert_issuer               <- protocol_raw.tls.cert_issuer
          entropy_score             <- protocol_raw.entropy_score (if present)
          confidence                <- 1.0 if protocol_raw.success else 0.0
          ports_open                <- [port] derived from endpoint if success else []
          services                  <- [] (not observed here)
          source_method             <- "protocol_observer"
        """

        endpoint = getattr(protocol_raw, "endpoint", None)
        if not isinstance(endpoint, str) or not endpoint.strip():
            raise ValueError("SnapshotBuilder: protocol_raw.endpoint missing")

        ts = getattr(protocol_raw, "timestamp_ms", None)
        if not isinstance(ts, (int, float)) or int(ts) <= 0:
            raise ValueError("SnapshotBuilder: protocol_raw.timestamp_ms missing/invalid")
        ts_ms = int(ts)

        # TLS fields
        tls = getattr(protocol_raw, "tls", None)
        tls_version = getattr(tls, "tls_version", None) if tls else None
        cipher = getattr(tls, "cipher_suite", None) if tls else None
        cert_sha = getattr(tls, "cert_fingerprint_sha256", None) if tls else None
        cert_issuer = getattr(tls, "cert_issuer", None) if tls else None
        cert_exp = getattr(tls, "cert_not_after", None) if tls else None
        cert_expiry_ms = self._parse_cert_expiry(cert_exp)

        tls_success = bool(
            tls
            and getattr(tls, "handshake_time_ms", None) is not None
            and not getattr(tls, "error", None)
        )

        # Endpoint port mapping
        hostname, port = self._split_endpoint(endpoint)
        ports_open = [int(port)] if getattr(protocol_raw, "success", False) else []

        # Confidence reflects contact richness rather than only boolean success.
        if getattr(protocol_raw, "success", False):
            if tls_success:
                confidence = 1.0
            elif getattr(getattr(protocol_raw, "tcp", None), "connected", False):
                confidence = 0.6
            else:
                confidence = 0.5
        else:
            confidence = 0.0
        if confidence < 0.0 or confidence > 1.0:
            raise ValueError("SnapshotBuilder: derived confidence out of [0,1]")

        snapshot_raw = RawObservation(
            endpoint_str=str(endpoint),
            observed_at_unix_ms=ts_ms,
            tls_handshake_success=bool(tls_success),
            tls_version=tls_version,
            ports_open=list(ports_open),
            services=[],
            certificate_sha256=cert_sha,
            certificate_expiry_unix_ms=cert_expiry_ms,
            source_method="protocol_observer",
            confidence=float(confidence),
            error=getattr(protocol_raw, "error", None),
        )

        # Optional enrichments used by SnapshotBuilder
        ip = getattr(getattr(protocol_raw, "dns", None), "resolved_ip", None)
        entropy_score = getattr(protocol_raw, "entropy_score", None)

        if entropy_score is not None:
            try:
                entropy_score = float(entropy_score)
            except Exception:
                raise ValueError("SnapshotBuilder: entropy_score not numeric")

        # Attach extra attributes for SnapshotBuilder enrichment
        object.__setattr__(snapshot_raw, "entity_id", getattr(protocol_raw, "entity_id", None))
        object.__setattr__(snapshot_raw, "endpoint", str(endpoint))
        object.__setattr__(snapshot_raw, "ip", ip)
        object.__setattr__(snapshot_raw, "cipher", cipher)
        object.__setattr__(snapshot_raw, "cert_issuer", cert_issuer)
        object.__setattr__(snapshot_raw, "entropy_score", entropy_score)
        object.__setattr__(snapshot_raw, "success", getattr(protocol_raw, "success", False))

        return snapshot_raw

    def _parse_cert_expiry(self, value: Any) -> Optional[int]:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            v = int(value)
            # Heuristic: seconds vs ms
            if v > 1_000_000_000_000:
                return v
            if v > 1_000_000_000:
                return v * 1000
            return v
        if isinstance(value, str):
            raw = " ".join(value.strip().split())
            for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
                try:
                    import datetime as _dt
                    dt = _dt.datetime.strptime(raw, fmt)
                    # Assume GMT/UTC if timezone missing
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=_dt.timezone.utc)
                    return int(dt.timestamp() * 1000)
                except Exception:
                    continue
        return None

    def _split_endpoint(self, endpoint: str):
        """
        Canonical endpoint normalization.

        Accepts:
        - https://host
        - http://host
        - host
        - host:port
        - IPv6 (bracketed or raw)

        Returns:
        - (hostname, port)
        """

        endpoint = endpoint.strip().lower()

        if "://" not in endpoint:
            parsed = urlparse("//" + endpoint)
            scheme = "https"
        else:
            parsed = urlparse(endpoint)
            scheme = parsed.scheme

        hostname = parsed.hostname
        port = parsed.port

        if hostname is None:
            raise ValueError(f"Invalid endpoint format: {endpoint}")

        if port is None:
            if scheme == "https":
                port = 443
            elif scheme == "http":
                port = 80
            else:
                port = 443

        return hostname, port

    def _compute_diff(
        self,
        current: DiscoverySnapshot,
        previous: Optional[DiscoverySnapshot],
    ) -> SnapshotDiff:

        if previous is None:
            return SnapshotDiff(
                new_endpoints=[e.endpoint_id() for e in current.endpoints],
                removed_endpoints=[],
                changed_endpoints=[],
                unchanged_endpoints=[],
            )

        prev_map = {e.endpoint_id(): e for e in previous.endpoints}
        curr_map = {e.endpoint_id(): e for e in current.endpoints}

        new_endpoints = []
        removed_endpoints = []
        changed_endpoints: List[EndpointChange] = []
        unchanged_endpoints = []

        for endpoint_id, curr in curr_map.items():
            if endpoint_id not in prev_map:
                new_endpoints.append(endpoint_id)
            else:
                prev = prev_map[endpoint_id]
                changes = self._detect_changes(prev, curr)
                if changes:
                    changed_endpoints.append(
                        EndpointChange(
                            endpoint_id=endpoint_id,
                            changes=changes,
                        )
                    )
                else:
                    unchanged_endpoints.append(endpoint_id)

        for endpoint_id in prev_map:
            if endpoint_id not in curr_map:
                removed_endpoints.append(endpoint_id)

        return SnapshotDiff(
            new_endpoints=sorted(new_endpoints),
            removed_endpoints=sorted(removed_endpoints),
            changed_endpoints=changed_endpoints,
            unchanged_endpoints=sorted(unchanged_endpoints),
        )

    def _coerce_snapshot(
        self,
        snapshot: Optional[DiscoverySnapshot | Dict[str, Any]],
    ) -> Optional[DiscoverySnapshot]:
        if snapshot is None:
            return None
        if isinstance(snapshot, DiscoverySnapshot):
            return snapshot
        if not isinstance(snapshot, dict):
            raise TypeError("previous_snapshot must be DiscoverySnapshot, dict, or None")

        endpoints: List[CanonicalEndpoint] = []
        raw_endpoints = snapshot.get("endpoints", [])
        if isinstance(raw_endpoints, list):
            for row in raw_endpoints:
                endpoint = self._coerce_canonical_endpoint(row)
                if endpoint is not None:
                    endpoints.append(endpoint)

        return DiscoverySnapshot(
            schema_version=str(snapshot.get("schema_version", self.SCHEMA_VERSION) or self.SCHEMA_VERSION),
            cycle_id=str(snapshot.get("cycle_id", "")).strip(),
            cycle_number=int(snapshot.get("cycle_number", 0) or 0),
            timestamp_unix_ms=int(snapshot.get("timestamp_unix_ms", 0) or 0),
            endpoints=endpoints,
            snapshot_hash_sha256=str(
                snapshot.get("snapshot_hash_sha256", snapshot.get("snapshot_hash", ""))
            ).strip(),
            endpoint_count=int(snapshot.get("endpoint_count", len(endpoints)) or len(endpoints)),
        )

    @staticmethod
    def _coerce_temporal_absence(
        previous_temporal_state: Optional[TemporalState | Dict[str, Any]],
    ) -> Dict[str, int]:
        if previous_temporal_state is None:
            return {}
        if isinstance(previous_temporal_state, TemporalState):
            return {
                endpoint_id: int(getattr(state, "consecutive_absence", 0) or 0)
                for endpoint_id, state in previous_temporal_state.endpoints.items()
            }
        if not isinstance(previous_temporal_state, dict):
            return {}

        endpoint_rows = previous_temporal_state.get("endpoints", {})
        if not isinstance(endpoint_rows, dict):
            return {}

        result: Dict[str, int] = {}
        for endpoint_id, row in endpoint_rows.items():
            if not isinstance(row, dict):
                continue
            try:
                result[str(endpoint_id)] = int(row.get("consecutive_absence", 0) or 0)
            except Exception:
                result[str(endpoint_id)] = 0
        return result

    def _carry_forward_stale_endpoints(
        self,
        *,
        previous_snapshot: Optional[DiscoverySnapshot],
        previous_temporal_absence: Dict[str, int],
        observed_endpoint_ids: set[str],
        cycle_number: int,
    ) -> List[CanonicalEndpoint]:
        if previous_snapshot is None:
            return []

        carried: List[CanonicalEndpoint] = []
        for endpoint in previous_snapshot.endpoints:
            endpoint_id = endpoint.endpoint_id()
            if endpoint_id in observed_endpoint_ids:
                continue

            previous_absence = int(previous_temporal_absence.get(endpoint_id, 0) or 0)
            if (previous_absence + 1) >= self.STALE_RETENTION_ABSENCE_THRESHOLD:
                continue

            carried.append(
                CanonicalEndpoint(
                    hostname=endpoint.hostname,
                    port=endpoint.port,
                    tls_version=endpoint.tls_version,
                    certificate_sha256=endpoint.certificate_sha256,
                    certificate_expiry_unix_ms=endpoint.certificate_expiry_unix_ms,
                    ports_responding=list(endpoint.ports_responding),
                    services_detected=list(endpoint.services_detected),
                    discovered_by=list(endpoint.discovered_by),
                    confidence=endpoint.confidence,
                    tls_jarm=endpoint.tls_jarm,
                    ip=endpoint.ip,
                    asn=endpoint.asn,
                    cipher=endpoint.cipher,
                    cert_issuer=endpoint.cert_issuer,
                    entropy_score=endpoint.entropy_score,
                    observation_state="stale",
                    last_observed_cycle=(
                        endpoint.last_observed_cycle
                        if endpoint.last_observed_cycle is not None
                        else previous_snapshot.cycle_number
                    ),
                    last_observed_unix_ms=(
                        endpoint.last_observed_unix_ms
                        if endpoint.last_observed_unix_ms is not None
                        else previous_snapshot.timestamp_unix_ms
                    ),
                )
            )
        return carried

    @staticmethod
    def _coerce_canonical_endpoint(row: Any) -> Optional[CanonicalEndpoint]:
        if isinstance(row, CanonicalEndpoint):
            return row
        if not isinstance(row, dict):
            return None

        hostname = str(row.get("hostname", "")).strip().lower()
        try:
            port = int(row.get("port", 0) or 0)
        except Exception:
            return None
        if not hostname or port <= 0:
            return None

        ports_responding = row.get("ports_responding", [])
        services_detected = row.get("services_detected", [])
        discovered_by = row.get("discovered_by", [])
        try:
            confidence = float(row.get("confidence", 0.0) or 0.0)
        except Exception:
            confidence = 0.0

        return CanonicalEndpoint(
            hostname=hostname,
            port=port,
            tls_version=row.get("tls_version"),
            certificate_sha256=row.get("certificate_sha256"),
            certificate_expiry_unix_ms=row.get("certificate_expiry_unix_ms"),
            ports_responding=list(ports_responding) if isinstance(ports_responding, list) else [],
            services_detected=list(services_detected) if isinstance(services_detected, list) else [],
            discovered_by=list(discovered_by) if isinstance(discovered_by, list) else [],
            confidence=max(0.0, min(confidence, 1.0)),
            tls_jarm=row.get("tls_jarm"),
            ip=row.get("ip"),
            asn=row.get("asn"),
            cipher=row.get("cipher"),
            cert_issuer=row.get("cert_issuer"),
            entropy_score=row.get("entropy_score"),
            observation_state=str(row.get("observation_state", "observed") or "observed"),
            last_observed_cycle=(
                int(row.get("last_observed_cycle"))
                if row.get("last_observed_cycle") is not None
                else None
            ),
            last_observed_unix_ms=(
                int(row.get("last_observed_unix_ms"))
                if row.get("last_observed_unix_ms") is not None
                else None
            ),
        )

    def _detect_changes(
        self,
        previous: CanonicalEndpoint,
        current: CanonicalEndpoint,
    ) -> Dict[str, Dict[str, object]]:

        changes: Dict[str, Dict[str, object]] = {}

        fields = [
            "tls_version",
            "certificate_sha256",
            "certificate_expiry_unix_ms",
            "ports_responding",
            "services_detected",
        ]

        for field in fields:
            old_val = getattr(previous, field)
            new_val = getattr(current, field)
            if old_val != new_val:
                changes[field] = {
                    "old": old_val,
                    "new": new_val,
                }

        return changes
