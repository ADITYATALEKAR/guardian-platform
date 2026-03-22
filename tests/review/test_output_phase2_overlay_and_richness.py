from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any

from infrastructure.aggregation.global_identity import cycle_gid, endpoint_gid, tenant_gid
from infrastructure.storage_manager.storage_manager import StorageManager
from infrastructure.unified_discovery_v2.models import CanonicalEndpoint


def _new_storage(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    return storage


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, sort_keys=True, indent=2)


def test_phase2_snapshot_read_overlay_is_idempotent_and_non_mutating(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    tenant_path = storage.get_tenant_path("tenant_a")
    snapshot_path = tenant_path / "snapshots" / "cycle_000001.json"
    raw_snapshot = {
        "schema_version": "1.2",
        "cycle_id": "cycle_000001",
        "cycle_number": 1,
        "timestamp_unix_ms": 111,
        "snapshot_hash_sha256": "h",
        "endpoint_count": 1,
        "endpoints": [
            {
                "hostname": "api.bank.com",
                "port": 443,
                "tls_version": "TLS1.2",
                "certificate_sha256": "abc",
                "certificate_expiry_unix_ms": 0,
                "ports_responding": [443],
                "services_detected": ["https"],
                "discovered_by": ["snapshot"],
                "confidence": 0.9,
                "tls_jarm": None,
            }
        ],
    }
    _write_json(snapshot_path, raw_snapshot)
    before = snapshot_path.read_text(encoding="utf-8")

    loaded = storage.load_latest_snapshot("tenant_a")
    assert loaded is not None
    assert loaded["tenant_id"] == "tenant_a"
    assert loaded["tenant_gid"] == tenant_gid("tenant_a")
    assert loaded["cycle_gid"] == cycle_gid("tenant_a", "cycle_000001")
    assert loaded["endpoints"][0]["endpoint_gid"] == endpoint_gid("tenant_a", "api.bank.com", 443)

    # historical artifact must remain unchanged
    after = snapshot_path.read_text(encoding="utf-8")
    assert before == after


def test_phase2_telemetry_read_overlay_is_idempotent_and_non_mutating(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    tenant_path = storage.get_tenant_path("tenant_a")
    telemetry_path = tenant_path / "telemetry" / "cycle_000001.jsonl"
    telemetry_path.write_text(
        json.dumps(
            {
                "timestamp_ms": 10,
                "sequence": 1,
                "entity_id": "api.bank.com:443",
                "posture_findings": {
                    "waf_findings": [
                        {"finding_id": "WAF-POSTURE-001", "endpoint_id": "api.bank.com:443"}
                    ],
                    "tls_findings": [],
                    "scores": {},
                },
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    before = telemetry_path.read_text(encoding="utf-8")

    rows = storage.load_telemetry_for_cycle("tenant_a", "cycle_000001")
    assert len(rows) == 1
    row = rows[0]
    assert row["tenant_id"] == "tenant_a"
    assert row["cycle_id"] == "cycle_000001"
    assert row["tenant_gid"] == tenant_gid("tenant_a")
    assert row["cycle_gid"] == cycle_gid("tenant_a", "cycle_000001")
    assert row["endpoint_gid"] == endpoint_gid("tenant_a", "api.bank.com", 443)
    assert row["posture_findings"]["waf_findings"][0]["endpoint_gid"] == endpoint_gid(
        "tenant_a",
        "api.bank.com",
        443,
    )

    after = telemetry_path.read_text(encoding="utf-8")
    assert before == after


def test_phase2_cycle_metadata_and_guardian_read_overlay_non_mutating(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    tenant_path = storage.get_tenant_path("tenant_a")
    metadata_path = tenant_path / "cycle_metadata" / "metadata.jsonl"
    guardian_path = tenant_path / "guardian_records" / "metadata.jsonl"
    metadata_path.write_text(
        json.dumps(
            {
                "schema_version": "v2.6",
                "cycle_id": "cycle_000001",
                "cycle_number": 1,
                "timestamp_unix_ms": 1,
                "duration_ms": 0,
                "status": "completed",
                "endpoints_scanned": 0,
                "new_endpoints": 0,
                "removed_endpoints": 0,
                "snapshot_hash": "",
                "rate_limited_events": 0,
                "error_messages": [],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    guardian_path.write_text(
        json.dumps(
            {
                "timestamp_ms": 1,
                "entity_id": "api.bank.com:443",
                "severity": 0.1,
                "confidence": 0.8,
                "cycle_id": "cycle_000001",
                "cycle_number": 1,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    before_meta = metadata_path.read_text(encoding="utf-8")
    before_guard = guardian_path.read_text(encoding="utf-8")

    metadata = storage.load_cycle_metadata("tenant_a")
    guardians = storage.load_latest_guardian_records("tenant_a")
    assert metadata[0]["tenant_gid"] == tenant_gid("tenant_a")
    assert metadata[0]["cycle_gid"] == cycle_gid("tenant_a", "cycle_000001")
    assert guardians[0]["endpoint_gid"] == endpoint_gid("tenant_a", "api.bank.com", 443)

    assert before_meta == metadata_path.read_text(encoding="utf-8")
    assert before_guard == guardian_path.read_text(encoding="utf-8")


def test_phase2_new_writes_include_identity_overlay_fields(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    tenant_path = storage.get_tenant_path("tenant_a")

    storage.save_snapshot(
        "tenant_a",
        {
            "schema_version": "1.2",
            "cycle_id": "cycle_000002",
            "cycle_number": 2,
            "timestamp_unix_ms": 222,
            "snapshot_hash_sha256": "hh",
            "endpoint_count": 1,
            "endpoints": [
                {
                    "hostname": "api.bank.com",
                    "port": 443,
                    "tls_version": "TLS1.2",
                    "certificate_sha256": "abc",
                    "certificate_expiry_unix_ms": 0,
                    "ports_responding": [443],
                    "services_detected": [],
                    "discovered_by": ["snapshot"],
                    "confidence": 0.9,
                    "tls_jarm": None,
                }
            ],
        },
    )
    snapshot = json.loads((tenant_path / "snapshots" / "cycle_000002.json").read_text(encoding="utf-8"))
    assert snapshot["tenant_id"] == "tenant_a"
    assert snapshot["tenant_gid"] == tenant_gid("tenant_a")
    assert snapshot["cycle_gid"] == cycle_gid("tenant_a", "cycle_000002")
    assert snapshot["endpoints"][0]["endpoint_gid"] == endpoint_gid("tenant_a", "api.bank.com", 443)

    storage.persist_telemetry_record(
        "tenant_a",
        "cycle_000002",
        {
            "timestamp_ms": 2,
            "sequence": 1,
            "entity_id": "api.bank.com:443",
            "posture_findings": {
                "waf_findings": [{"finding_id": "WAF-POSTURE-001", "endpoint_id": "api.bank.com:443"}],
                "tls_findings": [],
                "scores": {},
            },
        },
    )
    telemetry_line = (tenant_path / "telemetry" / "cycle_000002.jsonl").read_text(encoding="utf-8").splitlines()[0]
    telemetry_row = json.loads(telemetry_line)
    assert telemetry_row["tenant_gid"] == tenant_gid("tenant_a")
    assert telemetry_row["cycle_gid"] == cycle_gid("tenant_a", "cycle_000002")
    assert telemetry_row["endpoint_gid"] == endpoint_gid("tenant_a", "api.bank.com", 443)

    storage.append_cycle_metadata(
        "tenant_a",
        {
            "schema_version": "v2.6",
            "cycle_id": "cycle_000002",
            "cycle_number": 2,
            "timestamp_unix_ms": 2,
            "duration_ms": 1,
            "status": "running",
            "endpoints_scanned": 0,
            "new_endpoints": 0,
            "removed_endpoints": 0,
            "snapshot_hash": "",
            "rate_limited_events": 0,
            "error_messages": [],
        },
    )
    meta_line = (tenant_path / "cycle_metadata" / "metadata.jsonl").read_text(encoding="utf-8").splitlines()[0]
    meta_row = json.loads(meta_line)
    assert meta_row["tenant_gid"] == tenant_gid("tenant_a")
    assert meta_row["cycle_gid"] == cycle_gid("tenant_a", "cycle_000002")

    storage.persist_guardian_record(
        "tenant_a",
        {
            "timestamp_ms": 2,
            "entity_id": "api.bank.com:443",
            "severity": 0.2,
            "confidence": 0.9,
            "cycle_id": "cycle_000002",
            "cycle_number": 2,
        },
    )
    guard_line = (tenant_path / "guardian_records" / "metadata.jsonl").read_text(encoding="utf-8").splitlines()[0]
    guard_row = json.loads(guard_line)
    assert guard_row["tenant_gid"] == tenant_gid("tenant_a")
    assert guard_row["cycle_gid"] == cycle_gid("tenant_a", "cycle_000002")
    assert guard_row["endpoint_gid"] == endpoint_gid("tenant_a", "api.bank.com", 443)


def test_phase2_snapshot_to_dict_preserves_existing_rich_fields() -> None:
    endpoint = CanonicalEndpoint(
        hostname="api.bank.com",
        port=443,
        tls_version="TLS1.2",
        certificate_sha256="abc",
        certificate_expiry_unix_ms=0,
        ports_responding=[443],
        services_detected=["https"],
        discovered_by=["snapshot"],
        confidence=0.9,
        tls_jarm=None,
        ip="1.1.1.1",
        asn="AS13335",
        cipher="RSA-AES256-GCM-SHA384",
        cert_issuer="Demo CA",
        entropy_score=0.11,
    )
    payload = endpoint.to_dict()
    assert payload["ip"] == "1.1.1.1"
    assert payload["asn"] == "AS13335"
    assert payload["cipher"] == "RSA-AES256-GCM-SHA384"
    assert payload["cert_issuer"] == "Demo CA"
    assert payload["entropy_score"] == 0.11
