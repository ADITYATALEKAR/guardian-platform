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


def test_phase6_c16_parallel_analysis_executor_used(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prod_root = tmp_path / "prod"
    sim_root = tmp_path / "sim"
    _seed_baseline(prod_root)
    service = SimulationService(production_root=str(prod_root), simulation_root=str(sim_root))
    service.ANALYSIS_MAX_WORKERS = 3

    submitted: list[str] = []

    class _ImmediateFuture:
        def __init__(self, fn, args, kwargs):
            self._value = fn(*args, **kwargs)

        def result(self):
            return self._value

    class _SpyExecutor:
        def __init__(self, max_workers=None):
            self.max_workers = max_workers

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def submit(self, fn, *args, **kwargs):
            submitted.append(getattr(fn, "__name__", "unknown"))
            return _ImmediateFuture(fn, args, kwargs)

    monkeypatch.setattr("simulator.core.simulation_service.ThreadPoolExecutor", _SpyExecutor)

    response = service.run(_request())
    assert response.simulation_id
    assert len(submitted) == 3
    assert "compute_blast_radius" in submitted
    assert "compute_concentration_metrics" in submitted


def test_phase6_c16_single_worker_skips_parallel_executor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prod_root = tmp_path / "prod"
    sim_root = tmp_path / "sim"
    _seed_baseline(prod_root)
    service = SimulationService(production_root=str(prod_root), simulation_root=str(sim_root))
    service.ANALYSIS_MAX_WORKERS = 1

    def _fail(*args, **kwargs):
        raise AssertionError("parallel executor should not be used for single-worker mode")

    monkeypatch.setattr("simulator.core.simulation_service.ThreadPoolExecutor", _fail)

    response = service.run(_request())
    assert response.simulation_id
