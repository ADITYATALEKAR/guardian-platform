# observation_bridge.py
# ------------------------------------------------------------
# Layer 0 Acquisition → Physics Bridge
#
# Responsibility:
#   Convert RawObservation (from protocol_observer)
#   into timing events compatible with Layer 0 physics engine.
#
# This file does NOT:
#   - Generate fake data
#   - Calculate entropy
#   - Mutate Layer 0 contracts
#   - Perform physics logic
#
# It only transforms acquisition output into collector input.
# ------------------------------------------------------------

from dataclasses import asdict
from typing import Any, Dict, List, Tuple

from layers.layer0_observation.observe import observe_timing_batch
from layers.layer0_observation.acquisition.protocol_observer import RawObservation
from layers.layer0_observation.collectors.timing_collector import (
    collect_timing_event,
    TimingCollectorError,
)
from layers.layer0_observation.collectors.handshake_collector import (
    collect_single_handshake_observation,
)


class ObservationBridge:
    """
    Bridge between Acquisition layer and Layer 0 physics engine.
    """

    def process(self, raw: RawObservation) -> List:
        """
        Accept RawObservation and forward into Layer 0 pipeline.

        Returns:
            List[Fingerprint]
        """

        # Ensure success
        if not raw.success:
            return []

        # Convert RawObservation → timing event dict
        timing_event = self._convert_to_timing_event(raw)

        # Feed into Layer 0 canonical pipeline
        fingerprints = observe_timing_batch([timing_event])

        return fingerprints

    def process_series(self, raws: List[RawObservation]) -> List:
        """
        Accept a list of RawObservation objects and forward into Layer 0 pipeline.

        Returns:
            List[Fingerprint]
        """
        if not raws:
            return []

        # Filter to successful observations only
        series = [r for r in raws if getattr(r, "success", False)]
        if not series:
            return []

        timing_events = [self._convert_to_timing_event(r) for r in series]

        # Best-effort window duration
        timestamps = [e.get("event_time_ms") for e in timing_events if isinstance(e.get("event_time_ms"), int)]
        window_ms = None
        if len(timestamps) >= 2:
            window_ms = max(0, timestamps[-1] - timestamps[0])

        fingerprints = observe_timing_batch(
            timing_events,
            window_ms=window_ms,
        )

        return fingerprints

    # --------------------------------------------------------
    # Internal Conversion Logic
    # --------------------------------------------------------

    def _convert_to_timing_event(self, raw: RawObservation) -> dict:
        """
        Convert structured RawObservation into
        canonical timing event expected by collectors.
        """

        rtt_ms = raw.rtt_ms
        if rtt_ms is None:
            parts = [
                raw.dns.resolution_time_ms if raw.dns else None,
                raw.tcp.connect_time_ms if raw.tcp else None,
                raw.tls.handshake_time_ms if raw.tls else None,
                raw.http.response_time_ms if raw.http else None,
            ]
            rtt_ms = sum(v for v in parts if isinstance(v, (int, float)))

        packet_gaps_us = []
        for ms in raw.packet_spacing_ms or []:
            try:
                packet_gaps_us.append(float(ms) * 1000.0)
            except Exception:
                continue

        entropy_values = self._compute_entropy_series(raw.packet_spacing_ms or [])
        subms_jitter_samples = [
            float(v)
            for v in (raw.packet_spacing_ms or [])[:512]
            if isinstance(v, (int, float)) and float(v) < 1.0
        ]

        cert_fields = self._extract_cert_fields(raw)

        timing_event: Dict[str, Any] = {
            "endpoint": raw.endpoint,
            "entity_id": raw.entity_id,
            "observation_id": raw.observation_id,
            "timestamp_ms": raw.timestamp_ms,
            "event_time_ms": raw.timestamp_ms,
            "received_time_ms": raw.timestamp_ms,
            "rtt_ms": rtt_ms,
            "handshake_ms": raw.tls.handshake_time_ms if raw.tls else None,
            "dns_time_ms": raw.dns.resolution_time_ms if raw.dns else None,
            "tcp_time_ms": raw.tcp.connect_time_ms if raw.tcp else None,
            "tls_time_ms": raw.tls.handshake_time_ms if raw.tls else None,
            "http_time_ms": None,  # You currently don't have HTTP observation
            "packet_spacing_ms": raw.packet_spacing_ms,
            "packet_gaps_us": packet_gaps_us,
            "probe_duration_ms": raw.probe_duration_ms,
            "tls_version": raw.tls.tls_version if raw.tls else None,
            "alpn": [raw.tls.alpn_protocol] if raw.tls and raw.tls.alpn_protocol else [],
            "cipher": raw.tls.cipher_suite if raw.tls else None,
            "cipher_suites": raw.tls.cipher_suites if raw.tls else [],
            "cert_extension_hints": raw.tls.cert_extension_hints if raw.tls else [],
            "supported_groups": raw.tls.supported_groups if raw.tls else [],
            "signature_algorithms": raw.tls.signature_algorithms if raw.tls else [],
            "cert_subject": raw.tls.cert_subject if raw.tls else None,
            "cert_issuer": raw.tls.cert_issuer if raw.tls else None,
            "cert_serial": raw.tls.cert_serial if raw.tls else None,
            "cert_fingerprint_sha256": raw.tls.cert_fingerprint_sha256 if raw.tls else None,
            "cert_fields": cert_fields,
            "attempt_protocols": raw.attempt_protocols or [],
            "attempt_path": raw.attempt_path or "",
            "attempt_count": raw.attempt_count or 0,
            "entropy_values": entropy_values,
            "subms_jitter_samples": subms_jitter_samples,
            "signature_tokens": [
                x for x in [
                    raw.tls.tls_version if raw.tls else None,
                    raw.tls.cipher_suite if raw.tls else None,
                    raw.tls.alpn_protocol if raw.tls else None,
                ] if x
            ],
            "success": raw.success,
            "sni": raw.endpoint.split(":")[0] if raw.endpoint else "",
        }

        # Ensure cipher_suites is populated if only a single cipher is known
        if not timing_event.get("cipher_suites") and timing_event.get("cipher"):
            timing_event["cipher_suites"] = [timing_event.get("cipher")]

        # Invoke timing collector (best-effort) without overwriting canonical fields
        try:
            timing_core = collect_timing_event(
                {
                    "timestamp_ms": timing_event.get("timestamp_ms"),
                    "rtt_ms": timing_event.get("rtt_ms"),
                    "packet_spacing_ms": timing_event.get("packet_spacing_ms"),
                }
            )
            for k, v in timing_core.items():
                if timing_event.get(k) in (None, "", [], (), {}):
                    timing_event[k] = v
        except TimingCollectorError:
            pass

        # Invoke handshake collector (best-effort) without clobbering TLS/cert fields
        try:
            handshake_obs = collect_single_handshake_observation(timing_event)
            handshake_dict = asdict(handshake_obs)
            for k, v in handshake_dict.items():
                if timing_event.get(k) in (None, "", [], (), {}):
                    timing_event[k] = v
        except Exception:
            pass

        return timing_event

    def _compute_entropy_series(self, values: List[float]) -> List[float]:
        """
        Best-effort entropy estimate from packet spacing (ms).
        Returns a list to align with entropy_* fingerprint expectations.
        """
        if not values:
            return []
        buckets = [0] * 8
        for v in values[:512]:
            try:
                fv = float(v)
            except Exception:
                continue
            idx = 0
            if fv <= 0.1:
                idx = 0
            elif fv <= 0.5:
                idx = 1
            elif fv <= 1.0:
                idx = 2
            elif fv <= 2.0:
                idx = 3
            elif fv <= 5.0:
                idx = 4
            elif fv <= 10.0:
                idx = 5
            elif fv <= 50.0:
                idx = 6
            else:
                idx = 7
            buckets[idx] += 1

        total = sum(buckets)
        if total <= 0:
            return []
        import math

        entropy = 0.0
        for c in buckets:
            if c <= 0:
                continue
            p = c / total
            entropy -= p * math.log(p, 2)
        return [float(entropy)]

    def _extract_cert_fields(self, raw: RawObservation) -> Dict[str, Any]:
        """
        Build shape-only cert fields from available TLS metadata.
        """
        fields: Dict[str, Any] = {}
        tls = raw.tls
        if not tls:
            return fields

        def _parse_dn(s: str) -> Dict[str, str]:
            out: Dict[str, str] = {}
            for part in s.split(","):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    out[k.strip()] = v.strip()
            return out

        if tls.cert_subject:
            fields["subject"] = _parse_dn(tls.cert_subject)
        if tls.cert_issuer:
            fields["issuer"] = _parse_dn(tls.cert_issuer)
        if tls.cert_san:
            fields["san_count"] = len(tls.cert_san)
        if tls.cert_serial:
            fields["serial_len"] = len(str(tls.cert_serial))
        if tls.cert_fingerprint_sha256:
            fields["fingerprint_present"] = True
        fields["tls_version"] = tls.tls_version
        fields["cipher"] = tls.cipher_suite
        return fields
