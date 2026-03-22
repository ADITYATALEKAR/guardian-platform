from __future__ import annotations

from pathlib import Path

from infrastructure.layer5_api.bootstrap import _validate_runtime_path
from infrastructure.unified_discovery_v2.models import RawObservation
from infrastructure.unified_discovery_v2.snapshot_builder import SnapshotBuilder
from infrastructure.unified_discovery_v2.temporal_state_engine import TemporalStateEngine


def test_phase8_snapshot_builder_accepts_stored_previous_snapshot_dict() -> None:
    builder = SnapshotBuilder()
    current_observations = [
        RawObservation(
            endpoint_str="api.example.com:443",
            observed_at_unix_ms=1_710_000_000_123,
            tls_handshake_success=True,
            tls_version="TLSv1.3",
            ports_open=[443],
            services=["https"],
            certificate_sha256="sha256-current",
            certificate_expiry_unix_ms=1_760_000_000_000,
            source_method="protocol_observer",
            confidence=1.0,
            error=None,
        )
    ]
    object.__setattr__(current_observations[0], "success", True)
    previous_snapshot = {
        "schema_version": "1.2",
        "cycle_id": "cycle_000001",
        "cycle_number": 1,
        "timestamp_unix_ms": 1_709_000_000_000,
        "snapshot_hash_sha256": "old",
        "endpoint_count": 1,
        "endpoints": [
            {
                "hostname": "api.example.com",
                "port": 443,
                "tls_version": "TLSv1.3",
                "certificate_sha256": "sha256-current",
                "certificate_expiry_unix_ms": 1_760_000_000_000,
                "ports_responding": [],
                "services_detected": [],
                "discovered_by": ["protocol_observer"],
                "confidence": 1.0,
                "tls_jarm": None,
            }
        ],
    }

    snapshot, diff, _ = builder.build_snapshot(
        cycle_id="cycle_000002",
        cycle_number=2,
        raw_observations=current_observations,
        previous_snapshot=previous_snapshot,
    )

    assert snapshot.endpoint_count == 1
    assert diff.new_endpoints == []
    assert diff.removed_endpoints == []
    assert diff.changed_endpoints == []
    assert diff.unchanged_endpoints == ["api.example.com:443"]


def test_phase8_bootstrap_runtime_path_validation_is_repeatable(tmp_path: Path) -> None:
    target = tmp_path / "runtime_root"

    first = _validate_runtime_path(str(target), "runtime_root")
    second = _validate_runtime_path(str(target), "runtime_root")

    assert Path(first).exists()
    assert Path(second).exists()


def test_phase8_temporal_engine_accepts_stored_previous_state_dict() -> None:
    builder = SnapshotBuilder()
    engine = TemporalStateEngine()
    current_observations = [
        RawObservation(
            endpoint_str="api.example.com:443",
            observed_at_unix_ms=1_710_000_000_123,
            tls_handshake_success=True,
            tls_version="TLSv1.3",
            ports_open=[443],
            services=["https"],
            certificate_sha256="sha256-current",
            certificate_expiry_unix_ms=1_760_000_000_000,
            source_method="protocol_observer",
            confidence=1.0,
            error=None,
        )
    ]
    object.__setattr__(current_observations[0], "success", True)
    current_snapshot, _, _ = builder.build_snapshot(
        cycle_id="cycle_000002",
        cycle_number=2,
        raw_observations=current_observations,
        previous_snapshot=None,
    )
    previous_state = {
        "schema_version": "1.0",
        "last_cycle_id": "cycle_000001",
        "last_cycle_number": 1,
        "endpoints": {
            "api.example.com:443": {
                "endpoint_id": "api.example.com:443",
                "first_observed_cycle": 1,
                "last_observed_cycle": 1,
                "presence_history": [
                    {
                        "cycle_number": 1,
                        "timestamp_unix_ms": 1_709_000_000_000,
                        "present": True,
                    }
                ],
                "tls_change_history": [],
                "port_change_history": [],
                "certificate_change_history": [],
                "consecutive_absence": 0,
                "volatility_score": 0.0,
                "visibility_score": 1.0,
            }
        },
    }

    updated = engine.update_state(
        current_snapshot=current_snapshot,
        previous_state=previous_state,
    )

    assert updated.last_cycle_id == "cycle_000002"
    assert "api.example.com:443" in updated.endpoints
    assert updated.endpoints["api.example.com:443"].last_observed_cycle == 2
