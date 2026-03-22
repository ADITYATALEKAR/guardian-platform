from __future__ import annotations

import json
from pathlib import Path

import pytest

from simulator.core.simulation_request import SimulationRequest
from simulator.core.simulation_service import SimulationService, _snapshot_hash


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, sort_keys=True, indent=2)


def _seed_baseline(prod_root: Path, tenant_id: str = "tenant_a", cycle_id: str = "cycle_000001") -> None:
    tenant_path = prod_root / "tenant_data_storage" / "tenants" / tenant_id
    tenant_path.mkdir(parents=True, exist_ok=True)
    endpoints = [
        {
            "hostname": "example.com",
            "port": 443,
            "tls_version": "TLS1.2",
            "certificate_sha256": "abc",
            "certificate_expiry_unix_ms": 0,
            "ip": "1.2.3.4",
            "cipher": "TLS_AES_128_GCM_SHA256",
            "cert_issuer": "issuer",
            "entropy_score": 0.1,
            "ports_responding": [],
            "services_detected": [],
            "discovered_by": ["snapshot"],
            "confidence": 0.9,
            "tls_jarm": None,
        }
    ]
    snapshot = {
        "schema_version": "1.2",
        "cycle_id": cycle_id,
        "cycle_number": 1,
        "timestamp_unix_ms": 1,
        "snapshot_hash_sha256": _snapshot_hash({"endpoints": endpoints}),
        "endpoint_count": 1,
        "endpoints": endpoints,
    }
    _write_json(tenant_path / "snapshots" / f"{cycle_id}.json", snapshot)
    _write_json(
        tenant_path / "trust_graph" / "latest.json",
        {"version": 1, "created_at_ms": 1, "nodes": [], "edges": []},
    )


def _request() -> SimulationRequest:
    return SimulationRequest(
        tenant_id="tenant_a",
        baseline_cycle_id="cycle_000001",
        cycle_number=1,
        scenario_id="certificate_compromise",
        scenario_params={"target_selector": {"entity_id": "example.com:443"}},
        max_mitigations=0,
    )


def test_phase3_simulation_cache_short_circuits_pipeline(tmp_path: Path, monkeypatch) -> None:
    prod_root = tmp_path / "prod"
    sim_root = tmp_path / "sim"
    _seed_baseline(prod_root)
    service = SimulationService(production_root=str(prod_root), simulation_root=str(sim_root))
    req = _request()

    first = service.run(req)
    assert first.simulation_id

    def _should_not_run(*args, **kwargs):
        raise AssertionError("pipeline should not execute on cache hit")

    monkeypatch.setattr(service._pipeline, "run_from_observations", _should_not_run)
    second = service.run(req)
    assert second.simulation_id == first.simulation_id
    assert second.to_dict() == first.to_dict()


def test_phase3_simulation_cache_fail_loud_on_corrupt_payload(tmp_path: Path) -> None:
    prod_root = tmp_path / "prod"
    sim_root = tmp_path / "sim"
    _seed_baseline(prod_root)
    service = SimulationService(production_root=str(prod_root), simulation_root=str(sim_root))
    req = _request()

    # compute deterministic sim id exactly as runtime does
    baseline_path = (
        prod_root
        / "tenant_data_storage"
        / "tenants"
        / req.tenant_id
        / "snapshots"
        / f"{req.baseline_cycle_id}.json"
    )
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    sim_id = service._storage.compute_simulation_id(
        tenant_id=req.tenant_id,
        baseline_cycle_id=req.baseline_cycle_id,
        baseline_snapshot_hash=str(baseline.get("snapshot_hash_sha256", "")),
        scenario_id=req.scenario_id,
        scenario_params=req.scenario_params,
        mitigation_params=req.mitigation or {},
    )
    sim_file = sim_root / "tenants" / req.tenant_id / "simulations" / f"{sim_id}.json"
    _write_json(sim_file, {"simulation_id": sim_id, "tenant_id": req.tenant_id})

    with pytest.raises(RuntimeError, match="Corrupt simulation artifact"):
        service.run(req)
