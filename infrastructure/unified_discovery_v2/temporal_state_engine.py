from __future__ import annotations

from typing import Any, Optional, Dict

from .models import (
    DiscoverySnapshot,
    TemporalState,
    TemporalEndpointState,
    PresenceRecord,
    TLSChangeRecord,
    PortChangeRecord,
    CertificateChangeRecord,
)


class TemporalStateEngine:
    """
    Observational behavioral memory engine.

    Guarantees:
        - Deterministic
        - Idempotent
        - Does NOT mutate input state
        - Stores full change history
        - Performs no risk scoring
        - Performs no Guardian logic
    """

    SCHEMA_VERSION = "1.0"

    # ============================================================
    # PUBLIC ENTRYPOINT
    # ============================================================

    def update_state(
        self,
        current_snapshot: DiscoverySnapshot,
        previous_state: Optional[TemporalState | Dict[str, Any]],
    ) -> TemporalState:

        self._validate_snapshot(current_snapshot)

        cycle_number = current_snapshot.cycle_number
        timestamp = current_snapshot.timestamp_unix_ms

        previous_state_model = self._coerce_temporal_state(previous_state)
        if previous_state_model is None:
            previous_state = TemporalState(
                schema_version=self.SCHEMA_VERSION,
                last_cycle_id=current_snapshot.cycle_id,
                last_cycle_number=cycle_number,
                endpoints={}
            )
        else:
            previous_state = previous_state_model

        previous_endpoints = previous_state.endpoints

        current_map = {
            f"{e.hostname}:{e.port}": e
            for e in current_snapshot.endpoints
        }

        all_endpoint_ids = sorted(
            set(previous_endpoints.keys()) | set(current_map.keys())
        )

        updated_endpoints: Dict[str, TemporalEndpointState] = {}

        for endpoint_id in all_endpoint_ids:

            current_endpoint = current_map.get(endpoint_id)
            previous_endpoint_state = previous_endpoints.get(endpoint_id)

            if previous_endpoint_state is None:
                state = self._initialize_new_endpoint(
                    endpoint_id,
                    current_endpoint,
                    cycle_number,
                    timestamp
                )
            else:
                state = self._update_existing_endpoint(
                    previous_endpoint_state,
                    current_endpoint,
                    cycle_number,
                    timestamp
                )

            updated_endpoints[endpoint_id] = state

        return TemporalState(
            schema_version=self.SCHEMA_VERSION,
            last_cycle_id=current_snapshot.cycle_id,
            last_cycle_number=cycle_number,
            endpoints=updated_endpoints
        )

    def _coerce_temporal_state(
        self,
        previous_state: Optional[TemporalState | Dict[str, Any]],
    ) -> Optional[TemporalState]:
        if previous_state is None:
            return None
        if isinstance(previous_state, TemporalState):
            return previous_state
        if not isinstance(previous_state, dict):
            raise TypeError("previous_state must be TemporalState, dict, or None")

        endpoint_rows = previous_state.get("endpoints", {})
        endpoints: Dict[str, TemporalEndpointState] = {}
        if isinstance(endpoint_rows, dict):
            for endpoint_id, row in endpoint_rows.items():
                coerced = self._coerce_temporal_endpoint_state(endpoint_id, row)
                if coerced is not None:
                    endpoints[endpoint_id] = coerced

        return TemporalState(
            schema_version=str(previous_state.get("schema_version", self.SCHEMA_VERSION) or self.SCHEMA_VERSION),
            last_cycle_id=str(previous_state.get("last_cycle_id", "")).strip(),
            last_cycle_number=int(previous_state.get("last_cycle_number", 0) or 0),
            endpoints=endpoints,
        )

    @staticmethod
    def _coerce_temporal_endpoint_state(
        endpoint_id: str,
        row: Any,
    ) -> Optional[TemporalEndpointState]:
        if isinstance(row, TemporalEndpointState):
            return row
        if not isinstance(row, dict):
            return None

        state = TemporalEndpointState(
            endpoint_id=str(row.get("endpoint_id", endpoint_id)).strip() or str(endpoint_id),
            first_observed_cycle=int(row.get("first_observed_cycle", 0) or 0),
            last_observed_cycle=int(row.get("last_observed_cycle", 0) or 0),
            consecutive_absence=int(row.get("consecutive_absence", 0) or 0),
            volatility_score=float(row.get("volatility_score", 0.0) or 0.0),
            visibility_score=float(row.get("visibility_score", 0.0) or 0.0),
        )

        presence_history = row.get("presence_history", [])
        if isinstance(presence_history, list):
            state.presence_history = [
                PresenceRecord(
                    cycle_number=int(item.get("cycle_number", 0) or 0),
                    timestamp_unix_ms=int(item.get("timestamp_unix_ms", 0) or 0),
                    present=bool(item.get("present", False)),
                )
                for item in presence_history
                if isinstance(item, dict)
            ]

        tls_changes = row.get("tls_change_history", [])
        if isinstance(tls_changes, list):
            state.tls_change_history = [
                TLSChangeRecord(
                    cycle_number=int(item.get("cycle_number", 0) or 0),
                    timestamp_unix_ms=int(item.get("timestamp_unix_ms", 0) or 0),
                    old_value=item.get("old_value"),
                    new_value=item.get("new_value"),
                )
                for item in tls_changes
                if isinstance(item, dict)
            ]

        port_changes = row.get("port_change_history", [])
        if isinstance(port_changes, list):
            state.port_change_history = [
                PortChangeRecord(
                    cycle_number=int(item.get("cycle_number", 0) or 0),
                    timestamp_unix_ms=int(item.get("timestamp_unix_ms", 0) or 0),
                    old_ports=list(item.get("old_ports", [])) if isinstance(item.get("old_ports"), list) else [],
                    new_ports=list(item.get("new_ports", [])) if isinstance(item.get("new_ports"), list) else [],
                )
                for item in port_changes
                if isinstance(item, dict)
            ]

        cert_changes = row.get("certificate_change_history", [])
        if isinstance(cert_changes, list):
            state.certificate_change_history = [
                CertificateChangeRecord(
                    cycle_number=int(item.get("cycle_number", 0) or 0),
                    timestamp_unix_ms=int(item.get("timestamp_unix_ms", 0) or 0),
                    old_sha256=item.get("old_sha256"),
                    new_sha256=item.get("new_sha256"),
                )
                for item in cert_changes
                if isinstance(item, dict)
            ]

        return state

    # ============================================================
    # VALIDATION
    # ============================================================

    def _validate_snapshot(self, snapshot: DiscoverySnapshot) -> None:
        if snapshot.cycle_number < 1:
            raise ValueError("Invalid snapshot: cycle_number must be >= 1")
        if snapshot.timestamp_unix_ms <= 0:
            raise ValueError("Invalid snapshot: timestamp_unix_ms must be positive")

    # ============================================================
    # NEW ENDPOINT
    # ============================================================

    def _initialize_new_endpoint(
        self,
        endpoint_id: str,
        current_endpoint,
        cycle_number: int,
        timestamp: int,
    ) -> TemporalEndpointState:
        present_now = (
            current_endpoint is not None
            and str(getattr(current_endpoint, "observation_state", "observed") or "observed").lower() == "observed"
        )
        first_observed_cycle = int(
            getattr(current_endpoint, "last_observed_cycle", cycle_number) or cycle_number
        )

        state = TemporalEndpointState(
            endpoint_id=endpoint_id,
            first_observed_cycle=first_observed_cycle,
            last_observed_cycle=first_observed_cycle,
        )

        state.presence_history.append(
            PresenceRecord(
                cycle_number=cycle_number,
                timestamp_unix_ms=timestamp,
                present=present_now
            )
        )

        if present_now:
            state.visibility_score = current_endpoint.confidence
        else:
            state.consecutive_absence = 1
            state.visibility_score = 0.0
        state.volatility_score = 0.0

        return state

    # ============================================================
    # EXISTING ENDPOINT (CRITICAL FIX APPLIED)
    # ============================================================

    def _update_existing_endpoint(
        self,
        previous_state: TemporalEndpointState,
        current_endpoint,
        cycle_number: int,
        timestamp: int,
    ) -> TemporalEndpointState:
        """
        Creates NEW state object.
        Never mutates previous_state.
        """

        # --- Deep copy list fields to preserve immutability ---
        state = TemporalEndpointState(
            endpoint_id=previous_state.endpoint_id,
            first_observed_cycle=previous_state.first_observed_cycle,
            last_observed_cycle=previous_state.last_observed_cycle,
            presence_history=previous_state.presence_history.copy(),
            tls_change_history=previous_state.tls_change_history.copy(),
            port_change_history=previous_state.port_change_history.copy(),
            certificate_change_history=previous_state.certificate_change_history.copy(),
            consecutive_absence=previous_state.consecutive_absence,
            volatility_score=previous_state.volatility_score,
            visibility_score=previous_state.visibility_score,
        )

        present_now = (
            current_endpoint is not None
            and str(getattr(current_endpoint, "observation_state", "observed") or "observed").lower() == "observed"
        )

        # --------------------------------------------------------
        # Presence Tracking
        # --------------------------------------------------------

        state.presence_history.append(
            PresenceRecord(
                cycle_number=cycle_number,
                timestamp_unix_ms=timestamp,
                present=present_now
            )
        )

        if present_now:
            state.consecutive_absence = 0
        else:
            state.consecutive_absence += 1

        # --------------------------------------------------------
        # Change Tracking
        # --------------------------------------------------------

        if present_now:
            state.last_observed_cycle = cycle_number
            self._track_tls_change(state, current_endpoint, cycle_number, timestamp)
            self._track_port_change(state, current_endpoint, cycle_number, timestamp)
            self._track_certificate_change(state, current_endpoint, cycle_number, timestamp)

        # --------------------------------------------------------
        # Metrics Update
        # --------------------------------------------------------

        presence_rate = self._compute_presence_rate(state)
        endpoint_confidence = current_endpoint.confidence if present_now else 0.0

        state.visibility_score = round(
            endpoint_confidence * presence_rate,
            6
        )

        state.volatility_score = round(
            self._compute_volatility(state),
            6
        )

        return state

    # ============================================================
    # CHANGE TRACKING
    # ============================================================

    def _track_tls_change(self, state, current_endpoint, cycle_number, timestamp):

        previous_tls = state.tls_change_history[-1].new_value if state.tls_change_history else None

        if previous_tls != current_endpoint.tls_version:
            state.tls_change_history.append(
                TLSChangeRecord(
                    cycle_number=cycle_number,
                    timestamp_unix_ms=timestamp,
                    old_value=previous_tls,
                    new_value=current_endpoint.tls_version
                )
            )

    def _track_port_change(self, state, current_endpoint, cycle_number, timestamp):

        previous_ports = state.port_change_history[-1].new_ports if state.port_change_history else []

        current_ports = sorted(current_endpoint.ports_responding)

        if previous_ports != current_ports:
            state.port_change_history.append(
                PortChangeRecord(
                    cycle_number=cycle_number,
                    timestamp_unix_ms=timestamp,
                    old_ports=previous_ports,
                    new_ports=current_ports
                )
            )

    def _track_certificate_change(self, state, current_endpoint, cycle_number, timestamp):

        previous_cert = state.certificate_change_history[-1].new_sha256 if state.certificate_change_history else None

        if previous_cert != current_endpoint.certificate_sha256:
            state.certificate_change_history.append(
                CertificateChangeRecord(
                    cycle_number=cycle_number,
                    timestamp_unix_ms=timestamp,
                    old_sha256=previous_cert,
                    new_sha256=current_endpoint.certificate_sha256
                )
            )

    # ============================================================
    # METRICS
    # ============================================================

    def _compute_presence_rate(self, state: TemporalEndpointState) -> float:
        if not state.presence_history:
            return 0.0

        total = len(state.presence_history)
        present = sum(1 for p in state.presence_history if p.present)

        return present / total

    def _compute_volatility(self, state: TemporalEndpointState) -> float:
        """
        Volatility = absence_ratio + change_ratio

        absence_ratio:
            How often endpoint is missing.

        change_ratio:
            How often endpoint changes TLS/ports/cert.

        Equal weighting is intentional.
        Volatility is capped at 1.0.
        """

        total_cycles = len(state.presence_history)
        if total_cycles == 0:
            return 0.0

        absence_ratio = (
            sum(1 for p in state.presence_history if not p.present)
            / total_cycles
        )

        change_events = (
            len(state.tls_change_history)
            + len(state.port_change_history)
            + len(state.certificate_change_history)
        )

        change_ratio = change_events / total_cycles

        return min(absence_ratio + change_ratio, 1.0)
