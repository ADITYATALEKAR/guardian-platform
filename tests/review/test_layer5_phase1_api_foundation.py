from __future__ import annotations

import io
import json
from pathlib import Path
import os

from infrastructure.layer5_api import APIRequest, Layer5API, Layer5BootstrapConfig
from infrastructure.layer5_api.errors import UnauthorizedError, normalize_error
from infrastructure.layer5_api.prod_server import build_layer5_wsgi_application
from infrastructure.layer5_api.services.runtime_read_adapter import RuntimeReadAdapter
from infrastructure.operator_plane.registry.operator_registry import create_operator
from infrastructure.operator_plane.registry.operator_tenant_links import add_link
from infrastructure.operator_plane.storage.operator_storage import ensure_operator_storage
from infrastructure.runtime.engine_runtime import EngineRuntime
from infrastructure.storage_manager.storage_manager import StorageManager
from simulator.storage.simulation_storage import SimulationStorage


def _bootstrap(tmp_path: Path) -> tuple[Layer5API, StorageManager]:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    storage.create_tenant("tenant_b")

    storage.save_snapshot(
        "tenant_a",
        {
            "schema_version": "v2",
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
            "timestamp_unix_ms": 1_710_000_000_000,
            "snapshot_hash_sha256": "abc123",
            "endpoint_count": 1,
            "endpoints": [{"hostname": "api.example.com", "port": 443}],
        },
    )
    storage.append_cycle_metadata(
        "tenant_a",
        {
            "schema_version": "v1",
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
            "status": "completed",
            "timestamp_unix_ms": 1_710_000_000_111,
            "duration_ms": 25,
        },
    )
    storage.persist_telemetry_record(
        "tenant_a",
        "cycle_000001",
        {
            "sequence": 1,
            "timestamp_ms": 1,
            "entity_id": "api.example.com:443",
            "fingerprints": [{"kind": "tls"}],
            "posture_signals": [],
            "posture_findings": {"waf_findings": [], "tls_findings": []},
        },
    )
    storage.persist_telemetry_record(
        "tenant_a",
        "cycle_000001",
        {
            "sequence": 2,
            "timestamp_ms": 2,
            "entity_id": "api.example.com:443",
            "fingerprints": [],
            "posture_signals": [{"signal_type": "tls_profile"}],
            "posture_findings": {"waf_findings": [], "tls_findings": []},
        },
    )
    storage.persist_telemetry_record(
        "tenant_a",
        "cycle_000001",
        {
            "sequence": 3,
            "timestamp_ms": 3,
            "entity_id": "api.example.com:443",
            "fingerprints": [],
            "posture_signals": [],
            "posture_findings": {
                "waf_findings": [{"finding_id": "waf_1"}],
                "tls_findings": [],
            },
        },
    )
    storage.persist_guardian_record(
        "tenant_a",
        {
            "timestamp_ms": 1_710_000_000_222,
            "entity_id": "api.example.com:443",
            "severity": 7.5,
            "confidence": 0.92,
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
            "alerts": [{"id": "alert_1"}],
        },
    )

    simulation_root = tmp_path / "sim_root"
    sim_storage = SimulationStorage(str(simulation_root))
    sim_storage.persist(
        "tenant_a",
        "sim_001",
        {
            "simulation_id": "sim_001",
            "tenant_id": "tenant_a",
            "baseline_cycle_id": "cycle_000001",
            "scenario_id": "credential_theft",
            "result": {"impact_score": 0.73},
        },
    )

    operator_root = tmp_path / "operator_storage"
    ensure_operator_storage(operator_root)
    create_operator(
        str(operator_root),
        operator_id="op_a",
        email="opa@example.com",
        password="StrongPassword123!",
        created_at_unix_ms=1_710_000_000_000,
        status="ACTIVE",
    )
    add_link(str(operator_root), "op_a", "tenant_a")

    runtime = EngineRuntime(storage=storage, simulation_root=str(simulation_root))
    app = Layer5API(runtime=runtime, operator_storage_root=str(operator_root))
    return app, storage


def _build_prod_wsgi_app(
    tmp_path: Path,
    *,
    allowed_origins: set[str] | None = None,
    max_body_bytes: int = 1_048_576,
):
    return build_layer5_wsgi_application(
        Layer5BootstrapConfig(
            storage_root=str(tmp_path / "wsgi_storage_root"),
            operator_storage_root=str(tmp_path / "wsgi_operator_storage"),
            simulation_root=str(tmp_path / "wsgi_sim_root"),
        ),
        allowed_origins=allowed_origins or set(),
        max_body_bytes=max_body_bytes,
    )


def _call_wsgi(
    application,
    *,
    method: str,
    path: str,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
    query: str = "",
):
    captured: dict[str, object] = {}

    def start_response(status: str, response_headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = {k.lower(): v for k, v in response_headers}

    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query,
        "CONTENT_LENGTH": str(len(body)),
        "CONTENT_TYPE": "",
        "REMOTE_ADDR": "127.0.0.1",
        "wsgi.input": io.BytesIO(body),
    }
    for key, value in dict(headers or {}).items():
        upper = key.upper().replace("-", "_")
        if upper == "CONTENT_TYPE":
            environ["CONTENT_TYPE"] = value
        elif upper == "CONTENT_LENGTH":
            environ["CONTENT_LENGTH"] = value
        else:
            environ[f"HTTP_{upper}"] = value

    raw = b"".join(application(environ, start_response))
    payload = json.loads(raw.decode("utf-8")) if raw else None
    return captured["status"], captured["headers"], payload


def _login(app: Layer5API) -> str:
    resp = app.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/login",
            json_body={"operator_id": "op_a", "password": "StrongPassword123!"},
        )
    )
    assert resp.status_code == 200
    token = resp.payload["data"]["session_token"]
    assert token
    issued = int(resp.payload["data"]["issued_at_unix_ms"])
    expires = int(resp.payload["data"]["expires_at_unix_ms"])
    assert expires - issued == 60 * 60 * 1000
    return token


def test_phase1_auth_login_me_logout_flow(tmp_path: Path) -> None:
    app, _ = _bootstrap(tmp_path)
    token = _login(app)

    me = app.handle(
        APIRequest(
            method="GET",
            path="/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
    )
    assert me.status_code == 200
    assert me.payload["data"]["operator_id"] == "op_a"
    assert me.payload["data"]["tenant_id"] == "tenant_a"
    assert me.payload["data"]["tenant_ids"] == ["tenant_a"]

    logout = app.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
        )
    )
    assert logout.status_code == 200
    assert logout.payload["data"]["revoked"] is True

    me_again = app.handle(
        APIRequest(
            method="GET",
            path="/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
    )
    assert me_again.status_code == 401


def test_phase1_login_supports_email_or_operator_identifier_only(tmp_path: Path) -> None:
    app, _ = _bootstrap(tmp_path)

    email_login = app.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/login",
            json_body={"operator_id": "opa@example.com", "password": "StrongPassword123!"},
        )
    )
    assert email_login.status_code == 200
    assert email_login.payload["data"]["operator_id"] == "op_a"

    operator_login = app.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/login",
            json_body={"operator_id": "op_a", "password": "StrongPassword123!"},
        )
    )
    assert operator_login.status_code == 200
    assert operator_login.payload["data"]["operator_id"] == "op_a"

    tenant_login = app.handle(
        APIRequest(
            method="POST",
            path="/v1/auth/login",
            json_body={"operator_id": "tenant_a", "password": "StrongPassword123!"},
        )
    )
    assert tenant_login.status_code == 401


def test_phase1_tenant_scope_enforced(tmp_path: Path) -> None:
    app, _ = _bootstrap(tmp_path)
    token = _login(app)

    ok = app.handle(
        APIRequest(
            method="GET",
            path="/v1/tenants/tenant_a/dashboard",
            headers={"Authorization": f"Bearer {token}"},
        )
    )
    assert ok.status_code == 200

    forbidden = app.handle(
        APIRequest(
            method="GET",
            path="/v1/tenants/tenant_b/dashboard",
            headers={"Authorization": f"Bearer {token}"},
        )
    )
    assert forbidden.status_code == 403
    assert forbidden.payload["error"]["code"] == "forbidden"


def test_phase1_scan_status_reports_idle_from_latest_completed_cycle(tmp_path: Path) -> None:
    app, _ = _bootstrap(tmp_path)
    token = _login(app)

    response = app.handle(
        APIRequest(
            method="GET",
            path="/v1/tenants/tenant_a/scan-status",
            headers={"Authorization": f"Bearer {token}"},
        )
    )

    assert response.status_code == 200
    payload = response.payload["data"]
    assert payload["status"] == "completed"
    assert payload["cycle_id"] == "cycle_000001"
    assert payload["stage"] == "completed"
    assert payload["last_completed_duration_ms"] == 25
    assert payload["last_completed_timestamp_unix_ms"] == 1_710_000_000_111


def test_phase1_scan_status_reports_running_cycle_lock_and_stage(tmp_path: Path) -> None:
    app, storage = _bootstrap(tmp_path)
    token = _login(app)
    storage.acquire_cycle_lock("tenant_a", "cycle_000002", 2)
    storage.update_cycle_lock(
        "tenant_a",
        {
            "stage": "category_bcde_discovery",
            "stage_started_at_unix_ms": 1_710_000_000_500,
            "category_a_time_budget_seconds": 300,
            "bcde_time_budget_seconds": 300,
            "cycle_time_budget_seconds": 600,
            "cycle_deadline_unix_ms": 4_102_444_800_000,
            "seed_endpoint_count": 3,
            "root_scope_count": 2,
            "planned_scope_count": 2,
            "expansion_scope_processed_count": 1,
            "expansion_active_category": "BCDE",
            "expansion_phase": "category_bcde_exploration",
            "expansion_current_scope": "example.com",
            "expansion_phase_scope_completed_count": 1,
            "expansion_phase_scope_total_count": 2,
            "expansion_current_module": "TLSPortVariantsModule",
            "expansion_modules_completed_count": 4,
            "expansion_module_total_count": 29,
            "expansion_node_count": 120,
            "expansion_edge_count": 260,
            "expansion_graph_endpoint_count": 18,
            "expanded_candidate_count": 7,
            "total_candidate_count": 10,
            "observation_target_count": 10,
            "observation_cap_hit": False,
            "observed_completed_count": 4,
            "observed_successful_count": 3,
            "observed_failed_count": 1,
            "snapshot_endpoint_count": 0,
            "new_endpoint_count": 0,
            "removed_endpoint_count": 0,
            "stage_history": [
                {"stage": "initializing", "started_at_unix_ms": 1_710_000_000_000},
                {"stage": "category_bcde_exploration", "started_at_unix_ms": 1_710_000_000_500},
            ],
            "expansion_phase_history": [
                {
                    "phase": "category_a_exploration",
                    "status": "low_yield",
                    "scope_total_count": 2,
                    "scope_completed_count": 2,
                    "productive_scope_count": 0,
                }
            ],
        },
    )

    response = app.handle(
        APIRequest(
            method="GET",
            path="/v1/tenants/tenant_a/scan-status",
            headers={"Authorization": f"Bearer {token}"},
        )
    )

    assert response.status_code == 200
    payload = response.payload["data"]
    assert payload["status"] == "running"
    assert payload["cycle_id"] == "cycle_000002"
    assert payload["stage"] == "category_bcde_discovery"
    assert isinstance(payload["elapsed_ms"], int)
    assert payload["elapsed_ms"] >= 0
    assert isinstance(payload["stage_elapsed_ms"], int)
    assert payload["stage_elapsed_ms"] >= 0
    assert payload["last_completed_duration_ms"] == 25
    assert payload["last_completed_timestamp_unix_ms"] == 1_710_000_000_111
    assert payload["category_a_time_budget_seconds"] == 300
    assert payload["bcde_time_budget_seconds"] == 300
    assert payload["cycle_time_budget_seconds"] == 600
    assert payload["cycle_deadline_unix_ms"] == 4_102_444_800_000
    assert isinstance(payload["cycle_budget_remaining_ms"], int)
    assert payload["cycle_budget_remaining_ms"] >= 0
    assert isinstance(payload["stage_estimated_remaining_ms"], int)
    assert payload["stage_estimated_remaining_ms"] >= 0
    assert payload["seed_endpoint_count"] == 3
    assert payload["root_scope_count"] == 2
    assert payload["planned_scope_count"] == 2
    assert payload["expansion_scope_processed_count"] == 1
    assert payload["expansion_active_category"] == "BCDE"
    assert payload["expansion_phase"] == "category_bcde_exploration"
    assert payload["expansion_current_scope"] == "example.com"
    assert payload["expansion_phase_scope_completed_count"] == 1
    assert payload["expansion_phase_scope_total_count"] == 2
    assert payload["expansion_current_module"] == "TLSPortVariantsModule"
    assert payload["expansion_modules_completed_count"] == 4
    assert payload["expansion_module_total_count"] == 29
    assert payload["expansion_node_count"] == 120
    assert payload["expansion_edge_count"] == 260
    assert payload["expansion_graph_endpoint_count"] == 18
    assert payload["expanded_candidate_count"] == 7
    assert payload["total_candidate_count"] == 10
    assert payload["observation_target_count"] == 10
    assert payload["observation_cap_hit"] is False
    assert payload["observed_completed_count"] == 4
    assert payload["observed_successful_count"] == 3
    assert payload["observed_failed_count"] == 1
    assert len(payload["stage_history"]) == 2
    assert payload["stage_history"][-1]["stage"] == "category_bcde_exploration"
    assert payload["expansion_phase_history"][0]["phase"] == "category_a_exploration"

    storage.release_cycle_lock("tenant_a")


def test_phase1_scan_status_clears_stale_local_dead_process_lock(tmp_path: Path) -> None:
    app, storage = _bootstrap(tmp_path)
    token = _login(app)
    lock_path = storage.get_tenant_path("tenant_a") / ".cycle.lock"
    lock_path.write_text(
        json.dumps(
            {
                "cycle_id": "cycle_999999",
                "cycle_number": 999999,
                "started_at_unix_ms": 1_710_000_123_000,
                "pid": 999999,
                "hostname": __import__("socket").gethostname(),
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    response = app.handle(
        APIRequest(
            method="GET",
            path="/v1/tenants/tenant_a/scan-status",
            headers={"Authorization": f"Bearer {token}"},
        )
    )

    assert response.status_code == 200
    payload = response.payload["data"]
    assert payload["status"] == "completed"
    assert payload["cycle_id"] == "cycle_000001"
    assert not lock_path.exists()


def test_phase1_process_alive_handles_windows_systemerror(monkeypatch) -> None:
    original_name = os.name

    def _boom(_pid: int, _sig: int) -> None:
        raise SystemError("win32 os.kill failure")

    monkeypatch.setattr(os, "kill", _boom)
    monkeypatch.setattr(os, "name", "posix")

    assert StorageManager._is_process_alive(12345) is False


def test_phase1_scan_status_reports_abandoned_without_lock(tmp_path: Path) -> None:
    app, storage = _bootstrap(tmp_path)
    token = _login(app)
    storage.append_cycle_metadata(
        "tenant_a",
        {
            "schema_version": "v1",
            "cycle_id": "cycle_000002",
            "cycle_number": 2,
            "status": "running",
            "timestamp_unix_ms": 1_710_000_000_222,
            "duration_ms": 0,
        },
    )

    response = app.handle(
        APIRequest(
            method="GET",
            path="/v1/tenants/tenant_a/scan-status",
            headers={"Authorization": f"Bearer {token}"},
        )
    )

    assert response.status_code == 200
    payload = response.payload["data"]
    assert payload["status"] == "failed"
    assert payload["stage"] == "abandoned"
    assert payload["cycle_id"] == "cycle_000002"


def test_phase1_bundle_and_telemetry_split_contract(tmp_path: Path) -> None:
    app, _ = _bootstrap(tmp_path)
    token = _login(app)

    forbidden_param = app.handle(
        APIRequest(
            method="GET",
            path="/v1/tenants/tenant_a/cycles/cycle_000001/bundle",
            headers={"Authorization": f"Bearer {token}"},
            query={"page": "2"},
        )
    )
    assert forbidden_param.status_code == 400

    bundle = app.handle(
        APIRequest(
            method="GET",
            path="/v1/tenants/tenant_a/cycles/cycle_000001/bundle",
            headers={"Authorization": f"Bearer {token}"},
        )
    )
    assert bundle.status_code == 200
    payload = bundle.payload["data"]
    assert "telemetry" not in payload
    assert "telemetry_summary" in payload
    assert payload["telemetry_summary"]["total_records"] == 3
    assert payload["telemetry_summary"]["counts"]["fingerprints"] == 1
    assert payload["telemetry_summary"]["counts"]["posture_signals"] == 1
    assert payload["telemetry_summary"]["counts"]["posture_findings"] == 1

    telemetry = app.handle(
        APIRequest(
            method="GET",
            path="/v1/tenants/tenant_a/cycles/cycle_000001/telemetry",
            headers={"Authorization": f"Bearer {token}"},
            query={"record_type": "posture_findings", "page": "1", "page_size": "10"},
        )
    )
    assert telemetry.status_code == 200
    assert telemetry.payload["data"]["total"] == 1
    assert len(telemetry.payload["data"]["rows"]) == 1


def test_phase1_cycles_list_endpoint_returns_terminal_cycle_rows(tmp_path: Path) -> None:
    app, storage = _bootstrap(tmp_path)
    token = _login(app)

    storage.append_cycle_metadata(
        "tenant_a",
        {
            "schema_version": "v2.6",
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
            "timestamp_unix_ms": 1_710_000_000_000,
            "duration_ms": 0,
            "status": "running",
            "endpoints_scanned": 0,
        },
    )
    storage.append_cycle_metadata(
        "tenant_a",
        {
            "schema_version": "v2.6",
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
            "timestamp_unix_ms": 1_710_000_000_000,
            "duration_ms": 3210,
            "status": "completed",
            "endpoints_scanned": 12,
        },
    )
    storage.append_cycle_metadata(
        "tenant_a",
        {
            "schema_version": "v2.6",
            "cycle_id": "cycle_000002",
            "cycle_number": 2,
            "timestamp_unix_ms": 1_710_000_100_000,
            "duration_ms": 0,
            "status": "running",
            "endpoints_scanned": 0,
        },
    )

    response = app.handle(
        APIRequest(
            method="GET",
            path="/v1/tenants/tenant_a/cycles",
            headers={"Authorization": f"Bearer {token}"},
        )
    )
    assert response.status_code == 200
    payload = response.payload["data"]
    assert payload["total"] == 2
    rows = payload["rows"]
    assert rows[0]["cycle_id"] == "cycle_000002"
    assert rows[0]["status"] == "running"
    assert rows[1]["cycle_id"] == "cycle_000001"
    assert rows[1]["status"] == "completed"


def test_phase1_endpoint_page_returns_enriched_rows(tmp_path: Path) -> None:
    app, storage = _bootstrap(tmp_path)
    token = _login(app)
    storage.update_tenant_config_fields(
        "tenant_a",
        {
            "main_url": "https://app.example.com",
            "seed_endpoints": ["api.example.com:443"],
        },
    )

    storage.save_temporal_state(
        "tenant_a",
        {
            "schema_version": "v1",
            "endpoints": {
                "api.example.com:443": {
                    "endpoint_id": "api.example.com:443",
                    "volatility_score": 0.25,
                    "visibility_score": 0.95,
                    "consecutive_absence": 0,
                    "presence_history": [
                        {"cycle_number": 1, "timestamp_unix_ms": 1_710_000_000_050, "present": True},
                    ],
                }
            },
        },
        cycle_id="cycle_000001",
    )

    response = app.handle(
        APIRequest(
            method="GET",
            path="/v1/tenants/tenant_a/endpoints",
            headers={"Authorization": f"Bearer {token}"},
            query={"page": "1", "page_size": "50"},
        )
    )
    assert response.status_code == 200
    payload = response.payload["data"]
    assert payload["tenant_id"] == "tenant_a"
    assert payload["cycle_id"] == "cycle_000001"
    assert payload["total"] == 1
    row = payload["rows"][0]
    assert row["entity_id"] == "api.example.com:443"
    assert row["guardian_risk"] == 7.5
    assert row["alert_count"] == 1
    assert row["volatility_score"] == 0.25
    assert row["visibility_score"] == 0.95
    assert row["ownership_category"] == "first_party"
    assert row["relevance_score"] > 0.8


def test_phase1_endpoint_and_cycle_routes_tolerate_query_suffix_and_trailing_slash(tmp_path: Path) -> None:
    app, _ = _bootstrap(tmp_path)
    token = _login(app)

    endpoint_response = app.handle(
        APIRequest(
            method="GET",
            path="/v1/tenants/tenant_a/endpoints/?page=1&page_size=50",
            headers={"Authorization": f"Bearer {token}"},
        )
    )
    assert endpoint_response.status_code == 200
    assert endpoint_response.payload["data"]["tenant_id"] == "tenant_a"

    cycle_response = app.handle(
        APIRequest(
            method="GET",
            path="/v1/tenants/tenant_a/cycles/?page=1&page_size=50",
            headers={"Authorization": f"Bearer {token}"},
        )
    )
    assert cycle_response.status_code == 200
    assert cycle_response.payload["data"]["tenant_id"] == "tenant_a"


def test_phase1_endpoint_detail_returns_enriched_row(tmp_path: Path) -> None:
    app, storage = _bootstrap(tmp_path)
    token = _login(app)
    storage.update_tenant_config_fields(
        "tenant_a",
        {
            "main_url": "https://app.example.com",
            "seed_endpoints": ["api.example.com:443"],
        },
    )

    response = app.handle(
        APIRequest(
            method="GET",
            path="/v1/tenants/tenant_a/endpoints/api.example.com%3A443",
            headers={"Authorization": f"Bearer {token}"},
        )
    )
    assert response.status_code == 200
    payload = response.payload["data"]
    assert payload["cycle_id"] == "cycle_000001"
    row = payload["row"]
    assert row["entity_id"] == "api.example.com:443"
    assert row["ownership_category"] == "first_party"
    assert row["discovery_sources"] == []
    assert row["relevance_reason"]


def test_phase1_simulation_detail_endpoint(tmp_path: Path) -> None:
    app, _ = _bootstrap(tmp_path)
    token = _login(app)

    sim_list = app.handle(
        APIRequest(
            method="GET",
            path="/v1/tenants/tenant_a/simulations",
            headers={"Authorization": f"Bearer {token}"},
        )
    )
    assert sim_list.status_code == 200
    assert sim_list.payload["data"]["total"] == 1

    sim_detail = app.handle(
        APIRequest(
            method="GET",
            path="/v1/tenants/tenant_a/simulations/sim_001",
            headers={"Authorization": f"Bearer {token}"},
        )
    )
    assert sim_detail.status_code == 200
    assert sim_detail.payload["data"]["scenario_id"] == "credential_theft"

    missing = app.handle(
        APIRequest(
            method="GET",
            path="/v1/tenants/tenant_a/simulations/does_not_exist",
            headers={"Authorization": f"Bearer {token}"},
        )
    )
    assert missing.status_code == 404


def test_phase1_error_mapping_matrix_basics(tmp_path: Path) -> None:
    app, _ = _bootstrap(tmp_path)

    unauthorized = app.handle(
        APIRequest(
            method="GET",
            path="/v1/tenants/tenant_a/dashboard",
        )
    )
    assert unauthorized.status_code == 401

    method_not_allowed = app.handle(
        APIRequest(
            method="GET",
            path="/v1/auth/login",
        )
    )
    assert method_not_allowed.status_code == 405

    not_found = app.handle(
        APIRequest(
            method="GET",
            path="/v1/unknown/route",
        )
    )
    assert not_found.status_code == 404


def test_phase1_cycle_bundle_uses_single_telemetry_summary_query() -> None:
    class StubRuntime:
        def __init__(self) -> None:
            self.summary_calls = 0
            self.telemetry_calls = 0

        def build_cycle_artifact_bundle(self, tenant_id: str, *, authz_scope, cycle_id: str):
            return {
                "tenant_id": tenant_id,
                "cycle_id": cycle_id,
                "snapshot": {},
                "cycle_metadata": [],
                "temporal_state": {},
                "trust_graph_snapshot": {},
                "layer3_state_snapshot": {},
                "guardian_records": [],
            }

        def get_cycle_telemetry_summary(self, tenant_id: str, cycle_id: str, *, authz_scope, preview_page_size: int):
            self.summary_calls += 1
            return {
                "total_records": 0,
                "counts": {
                    "fingerprints": 0,
                    "posture_signals": 0,
                    "posture_findings": 0,
                },
                "preview_page": 1,
                "preview_page_size": preview_page_size,
                "preview_rows": [],
            }

        def get_cycle_telemetry(self, *args, **kwargs):
            self.telemetry_calls += 1
            raise AssertionError("legacy multi-query telemetry path should not be used")

    runtime = StubRuntime()
    adapter = RuntimeReadAdapter(runtime)
    payload = adapter.cycle_bundle(
        "tenant_a",
        "cycle_000001",
        authz_scope=object(),
    )
    assert payload["telemetry_summary"]["total_records"] == 0
    assert runtime.summary_calls == 1
    assert runtime.telemetry_calls == 0


def test_phase1_normalize_error_preserves_typed_api_errors() -> None:
    err = UnauthorizedError("invalid session")
    assert normalize_error(err) is err


def test_phase1_health_and_ready_endpoints_are_exposed(tmp_path: Path) -> None:
    app, _ = _bootstrap(tmp_path)

    health = app.handle(
        APIRequest(
            method="GET",
            path="/health",
        )
    )
    ready = app.handle(
        APIRequest(
            method="GET",
            path="/ready",
        )
    )

    assert health.status_code == 200
    assert health.payload["data"]["healthy"] is True
    assert ready.status_code == 200
    assert ready.payload["data"]["ready"] is True


def test_phase1_prod_wsgi_application_serves_health_and_ready(tmp_path: Path) -> None:
    application = _build_prod_wsgi_app(tmp_path, allowed_origins={"http://allowed.example"})

    health_status, health_headers, health_payload = _call_wsgi(
        application,
        method="GET",
        path="/health",
        headers={"Origin": "http://allowed.example"},
    )
    ready_status, _, ready_payload = _call_wsgi(
        application,
        method="GET",
        path="/ready",
        headers={"Origin": "http://allowed.example"},
    )

    assert health_status.startswith("200 ")
    assert health_headers["access-control-allow-origin"] == "http://allowed.example"
    assert health_payload["data"]["healthy"] is True
    assert ready_status.startswith("200 ")
    assert ready_payload["data"]["ready"] is True


def test_phase1_prod_wsgi_application_rejects_malformed_json(tmp_path: Path) -> None:
    application = _build_prod_wsgi_app(tmp_path)
    status, _, payload = _call_wsgi(
        application,
        method="POST",
        path="/v1/auth/login",
        body=b"{bad-json",
        headers={"Content-Type": "application/json"},
    )
    assert status.startswith("400 ")
    assert payload["error"]["code"] == "invalid_json"


def test_phase1_prod_wsgi_application_rejects_oversized_body(tmp_path: Path) -> None:
    application = _build_prod_wsgi_app(tmp_path, max_body_bytes=8)
    status, _, payload = _call_wsgi(
        application,
        method="POST",
        path="/v1/auth/login",
        body=b'{"operator_id":"x"}',
        headers={"Content-Type": "application/json"},
    )
    assert status.startswith("413 ")
    assert payload["error"]["code"] == "payload_too_large"


def test_phase1_prod_wsgi_application_denies_unapproved_origin(tmp_path: Path) -> None:
    application = _build_prod_wsgi_app(tmp_path, allowed_origins={"http://allowed.example"})
    status, headers, payload = _call_wsgi(
        application,
        method="GET",
        path="/health",
        headers={"Origin": "http://denied.example"},
    )
    assert status.startswith("403 ")
    assert "access-control-allow-origin" not in headers
    assert payload["error"]["code"] == "forbidden"


def test_phase1_prod_wsgi_application_preserves_api_not_found_contract(tmp_path: Path) -> None:
    application = _build_prod_wsgi_app(tmp_path)
    status, headers, payload = _call_wsgi(
        application,
        method="GET",
        path="/v1/does-not-exist",
    )
    assert status.startswith("404 ")
    assert headers["content-type"] == "application/json"
    assert payload["error"]["code"] == "not_found"
