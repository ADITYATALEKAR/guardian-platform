"""
Determinism Matrix Runner
=========================

Runs a deterministic matrix of SimulationService requests and verifies identical
hashes across repeated runs.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Tuple

from simulator.core.simulation_service import SimulationService, _snapshot_hash
from simulator.core.simulation_request import SimulationRequest


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, sort_keys=True, indent=2)


def _hash_payload(payload: Dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _diff(a: Any, b: Any, path: str = "") -> str:
    if type(a) != type(b):
        return f"{path}: type {type(a).__name__} != {type(b).__name__}"
    if isinstance(a, dict):
        keys = sorted(set(a.keys()) | set(b.keys()))
        for k in keys:
            p = f"{path}.{k}" if path else str(k)
            if k not in a:
                return f"{p}: missing in A"
            if k not in b:
                return f"{p}: missing in B"
            d = _diff(a[k], b[k], p)
            if d:
                return d
        return ""
    if isinstance(a, list):
        if len(a) != len(b):
            return f"{path}: len {len(a)} != {len(b)}"
        for i in range(len(a)):
            p = f"{path}[{i}]"
            d = _diff(a[i], b[i], p)
            if d:
                return d
        return ""
    if a != b:
        return f"{path}: {a} != {b}"
    return ""


def _make_snapshot(*, cycle_id: str, cycle_number: int, variant: int) -> Dict[str, Any]:
    # deterministic 3-endpoint snapshot with varied handshake pairs
    endpoints = [
        {
            "hostname": f"a{variant}.example.com",
            "port": 443,
            "tls_version": "TLS1.2" if variant % 2 == 0 else "TLS1.3",
            "certificate_sha256": f"a{variant}",
            "certificate_expiry_unix_ms": 0,
            "ip": f"10.0.0.{variant+1}",
            "cipher": "TLS_AES_128_GCM_SHA256",
            "cert_issuer": f"issuer{variant}A",
            "entropy_score": 0.1,
            "ports_responding": [],
            "services_detected": [],
            "discovered_by": ["snapshot"],
            "confidence": 0.9,
            "tls_jarm": None,
        },
        {
            "hostname": f"b{variant}.example.com",
            "port": 443,
            "tls_version": "TLS1.3",
            "certificate_sha256": f"b{variant}",
            "certificate_expiry_unix_ms": 0,
            "ip": f"10.0.1.{variant+1}",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "cert_issuer": f"issuer{variant}B",
            "entropy_score": 0.1,
            "ports_responding": [],
            "services_detected": [],
            "discovered_by": ["snapshot"],
            "confidence": 0.9,
            "tls_jarm": None,
        },
        {
            "hostname": f"c{variant}.example.com",
            "port": 443,
            "tls_version": "TLS1.3",
            "certificate_sha256": f"c{variant}",
            "certificate_expiry_unix_ms": 0,
            "ip": f"10.0.2.{variant+1}",
            "cipher": "TLS_CHACHA20_POLY1305_SHA256",
            "cert_issuer": f"issuer{variant}C",
            "entropy_score": 0.1,
            "ports_responding": [],
            "services_detected": [],
            "discovered_by": ["snapshot"],
            "confidence": 0.9,
            "tls_jarm": None,
        },
    ]
    snapshot = {
        "schema_version": "1.2",
        "cycle_id": cycle_id,
        "cycle_number": cycle_number,
        "timestamp_unix_ms": cycle_number,
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
    }
    snapshot["snapshot_hash_sha256"] = _snapshot_hash(snapshot)
    return snapshot


def run() -> None:
    tenants = ["tenant_a", "tenant_b", "tenant_c"]
    cycles = ["cycle_000001", "cycle_000002", "cycle_000003"]
    scenarios = ["compromised_endpoint", "certificate_compromise"]
    mitigation_modes = ["single", "multi"]
    path_modes = ["SAFE", "DEEP"]
    replay_cycles = [1, 3]

    total = 0
    passed = 0
    failed = 0

    with tempfile.TemporaryDirectory() as tmp:
        prod_root = Path(tmp) / "prod"
        sim_root = Path(tmp) / "sim"

        # create tenant snapshots
        for t_idx, tenant_id in enumerate(tenants):
            for c_idx, cycle_id in enumerate(cycles):
                snapshot = _make_snapshot(cycle_id=cycle_id, cycle_number=c_idx + 1, variant=t_idx + c_idx)
                tenant_path = prod_root / "tenant_data_storage" / "tenants" / tenant_id
                _write_json(tenant_path / "snapshots" / f"{cycle_id}.json", snapshot)
                _write_json(
                    tenant_path / "trust_graph" / "latest.json",
                    {"version": 1, "created_at_ms": 1, "nodes": [], "edges": []},
                )

        service = SimulationService(production_root=str(prod_root), simulation_root=str(sim_root))

        for tenant_id in tenants:
            for cycle_id in cycles:
                # determine target entity from snapshot naming
                target_entity = f"a{tenants.index(tenant_id) + cycles.index(cycle_id)}.example.com:443"
                for scenario_id in scenarios:
                    for mode in mitigation_modes:
                        for pm in path_modes:
                            for rc in replay_cycles:
                                mitigation = None
                                if mode == "single":
                                    mitigation = {
                                        "action_type": "isolate_endpoint",
                                        "target": {"entity_id": target_entity},
                                        "delta": {"confidence": 0.0},
                                        "description": "isolate",
                                    }
                                else:
                                    mitigation = {
                                        "candidates": [
                                            {
                                                "action_type": "isolate_endpoint",
                                                "target": {"entity_id": target_entity},
                                                "delta": {"confidence": 0.0},
                                                "description": "isolate",
                                            },
                                            {
                                                "action_type": "rotate_certificate",
                                                "target": {"entity_id": target_entity},
                                                "delta": {"certificate_sha256": "rotated"},
                                                "description": "rotate",
                                            },
                                        ]
                                    }

                                req = SimulationRequest(
                                    tenant_id=tenant_id,
                                    baseline_cycle_id=cycle_id,
                                    cycle_number=1,
                                    scenario_id=scenario_id,
                                    scenario_params={"target_selector": {"entity_id": target_entity}},
                                    mitigation=mitigation,
                                    replay_cycles=rc,
                                    path_mode=pm,
                                    max_mitigations=5,
                                )

                                total += 1
                                a = service.run(req).to_dict()
                                b = service.run(req).to_dict()
                                h1 = _hash_payload(a)
                                h2 = _hash_payload(b)
                                if h1 != h2:
                                    failed += 1
                                    print("FAIL:", tenant_id, cycle_id, scenario_id, mode, pm, rc)
                                    print("HASH A:", h1)
                                    print("HASH B:", h2)
                                    diff = _diff(a, b)
                                    print("DIFF:", diff)
                                    return
                                passed += 1

    print("=== Determinism Matrix ===")
    print(f"TOTAL: {total}")
    print(f"PASSED: {passed}")
    print(f"FAILED: {failed}")
    print(f"FREEZE_READY: {failed == 0}")


if __name__ == "__main__":
    run()
