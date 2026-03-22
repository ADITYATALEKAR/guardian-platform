from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable

import pytest

from simulator.core.baseline_loader import BaselineFilesystemLoader
from simulator.core.simulation_request import SimulationRequest
from simulator.core.simulation_service import SimulationService, _snapshot_hash
from simulator.core.validation import SimulationValidator
from simulator.storage.simulation_storage_manager import SimulationStorageManager


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, sort_keys=True, indent=2)


def _hash_tree(root: Path) -> str:
    if not root.exists():
        return ""
    h = hashlib.sha256()
    files = sorted([p for p in root.rglob("*") if p.is_file()], key=lambda p: str(p.relative_to(root)))
    for path in files:
        rel = str(path.relative_to(root)).replace("\\", "/")
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(path.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


def _snapshot(cycle_id: str, cycle_number: int = 1) -> Dict[str, Any]:
    endpoints = [
        {
            "hostname": "api.example.com",
            "port": 443,
            "tls_version": "TLS1.3",
            "certificate_sha256": "cert_a",
            "certificate_expiry_unix_ms": 0,
            "ip": "10.0.0.1",
            "cipher": "TLS_AES_128_GCM_SHA256",
            "cert_issuer": "issuer_a",
            "entropy_score": 0.12,
            "ports_responding": [443],
            "services_detected": ["https"],
            "discovered_by": ["snapshot"],
            "confidence": 0.9,
            "tls_jarm": None,
        },
        {
            "hostname": "edge.example.com",
            "port": 443,
            "tls_version": "TLS1.2",
            "certificate_sha256": "cert_b",
            "certificate_expiry_unix_ms": 0,
            "ip": "10.0.0.2",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "cert_issuer": "issuer_b",
            "entropy_score": 0.2,
            "ports_responding": [443],
            "services_detected": ["https"],
            "discovered_by": ["snapshot"],
            "confidence": 0.8,
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


def _prepare_baseline(production_root: Path, tenant_id: str, cycle_id: str) -> Path:
    tenant_path = production_root / "tenant_data_storage" / "tenants" / tenant_id
    _write_json(tenant_path / "snapshots" / f"{cycle_id}.json", _snapshot(cycle_id))
    _write_json(
        tenant_path / "trust_graph" / "latest.json",
        {"version": 1, "created_at_ms": 1, "nodes": [], "edges": []},
    )
    return tenant_path


def _forbidden_tokens() -> Iterable[str]:
    return (
        "infrastructure.operator_plane",
        "infrastructure.policy_integration",
        "infrastructure.runtime.tenant_lifecycle_manager",
        "infrastructure.unified_discovery_v2.unified_cycle_orchestrator",
        "infrastructure.storage_manager.storage_manager",
    )


def test_phase7_simulator_static_boundary_no_forbidden_runtime_coupling() -> None:
    roots = [
        Path("simulator/core"),
        Path("simulator/storage"),
        Path("simulator/scenarios"),
        Path("simulator/analysis"),
        Path("simulator/mitigation"),
        Path("simulator/narrative"),
    ]
    py_files = []
    for root in roots:
        py_files.extend(sorted(root.glob("*.py")))
    assert py_files

    for path in py_files:
        source = path.read_text(encoding="utf-8")
        for token in _forbidden_tokens():
            assert token not in source, f"forbidden coupling '{token}' found in {path}"


def test_phase7_simulator_validator_allows_sibling_roots() -> None:
    validator = SimulationValidator()
    result = validator.validate_isolation(sim_root="C:/tmp/prod2", prod_root="C:/tmp/prod")
    assert result.ok, result.issues


def test_phase7_simulator_deterministic_isolated_and_bounded(tmp_path: Path) -> None:
    production_root = tmp_path / "prod"
    simulation_root = tmp_path / "sim"
    tenant_id = "tenant_a"
    cycle_id = "cycle_000001"
    _prepare_baseline(production_root, tenant_id, cycle_id)

    service = SimulationService(production_root=str(production_root), simulation_root=str(simulation_root))

    request = SimulationRequest(
        tenant_id=tenant_id,
        baseline_cycle_id=cycle_id,
        cycle_number=1,
        scenario_id="certificate_compromise",
        scenario_params={"target_selector": {"entity_id": "api.example.com:443"}},
        replay_cycles=999,
        path_mode="DEEP",
        max_paths=999,
        max_mitigations=999,
        mitigation={
            "candidates": [
                {
                    "action_type": "isolate_endpoint",
                    "target": {"entity_id": "api.example.com:443"},
                    "delta": {"confidence": 0.0},
                    "description": "isolate",
                },
                {
                    "action_type": "rotate_certificate",
                    "target": {"entity_id": "api.example.com:443"},
                    "delta": {"certificate_sha256": "rotated"},
                    "description": "rotate",
                },
            ]
        },
    )

    prod_hash_before = _hash_tree(production_root)
    response_a = service.run(request).to_dict()
    response_b = service.run(request).to_dict()
    prod_hash_after = _hash_tree(production_root)

    assert response_a == response_b
    assert prod_hash_before == prod_hash_after

    sim_dir = simulation_root / "tenants" / tenant_id / "simulations"
    assert sim_dir.exists()
    assert any(sim_dir.glob("*.json"))

    assert len(response_a.get("attack_paths", [])) <= 100
    mitigation_analysis = response_a.get("mitigation_analysis", {})
    assert int(mitigation_analysis.get("candidates_evaluated", 0)) <= 10
    projection_cycles = response_a.get("multi_cycle_projection", {}).get("cycles", [])
    assert len(projection_cycles) <= 5


def test_phase7_simulator_rejects_nested_simulation_root(tmp_path: Path) -> None:
    production_root = tmp_path / "prod"
    simulation_root = production_root / "nested_sim"
    tenant_id = "tenant_a"
    cycle_id = "cycle_000001"
    _prepare_baseline(production_root, tenant_id, cycle_id)

    service = SimulationService(production_root=str(production_root), simulation_root=str(simulation_root))
    request = SimulationRequest(
        tenant_id=tenant_id,
        baseline_cycle_id=cycle_id,
        cycle_number=1,
        scenario_id="certificate_compromise",
        scenario_params={"target_selector": {"entity_id": "api.example.com:443"}},
    )

    with pytest.raises(RuntimeError, match="Simulation storage isolation violation"):
        service.run(request)


def test_phase7_simulator_fail_loud_on_corrupt_baseline_snapshot(tmp_path: Path) -> None:
    production_root = tmp_path / "prod"
    simulation_root = tmp_path / "sim"
    tenant_id = "tenant_a"
    cycle_id = "cycle_000001"
    tenant_path = _prepare_baseline(production_root, tenant_id, cycle_id)

    snapshot_path = tenant_path / "snapshots" / f"{cycle_id}.json"
    snapshot_path.write_text("{bad-json\n", encoding="utf-8")

    service = SimulationService(production_root=str(production_root), simulation_root=str(simulation_root))
    request = SimulationRequest(
        tenant_id=tenant_id,
        baseline_cycle_id=cycle_id,
        cycle_number=1,
        scenario_id="certificate_compromise",
        scenario_params={"target_selector": {"entity_id": "api.example.com:443"}},
    )

    with pytest.raises(json.JSONDecodeError):
        service.run(request)


def test_phase7_simulator_rejects_path_sequences_for_tenant_and_cycle(tmp_path: Path) -> None:
    storage_mgr = SimulationStorageManager(str(tmp_path / "sim"))
    with pytest.raises(ValueError, match="Invalid tenant_id path sequence"):
        storage_mgr.ensure_tenant_exists("../escape")

    loader = BaselineFilesystemLoader(str(tmp_path / "prod"))
    with pytest.raises(ValueError, match="Invalid tenant_id path sequence"):
        loader.load_baseline("../escape", "cycle_000001")
    with pytest.raises(ValueError, match="Invalid cycle_id path sequence"):
        loader.load_baseline("tenant_a", "../escape")
