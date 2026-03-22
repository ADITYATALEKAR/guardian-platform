from __future__ import annotations

import re
import time
from typing import Any, Dict
from urllib.parse import unquote, urlsplit

from infrastructure.layer5_api.authz.session_guard import SessionGuard
from infrastructure.layer5_api.errors import APIError
from infrastructure.layer5_api.middleware import run_with_api_error_boundary
from infrastructure.layer5_api.models import APIRequest, APIResponse
from infrastructure.layer5_api.services import (
    OperatorAdminAdapter,
    OperatorAuthAdapter,
    RuntimeReadAdapter,
)
from infrastructure.operator_plane.services.operator_service import OperatorService
from infrastructure.runtime.engine_runtime import EngineRuntime
from infrastructure.runtime.health import HealthState


class Layer5API:
    """
    Framework-agnostic Layer 5 API foundation.
    """

    _ROUTE_DASHBOARD = re.compile(r"^/v1/tenants/([^/]+)/dashboard$")
    _ROUTE_ENDPOINTS = re.compile(r"^/v1/tenants/([^/]+)/endpoints$")
    _ROUTE_ENDPOINT_DETAIL = re.compile(r"^/v1/tenants/([^/]+)/endpoints/([^/]+)$")
    _ROUTE_SCAN_STATUS = re.compile(r"^/v1/tenants/([^/]+)/scan-status$")
    _ROUTE_CYCLES = re.compile(r"^/v1/tenants/([^/]+)/cycles$")
    _ROUTE_CYCLE_BUNDLE = re.compile(r"^/v1/tenants/([^/]+)/cycles/([^/]+)/bundle$")
    _ROUTE_CYCLE_TELEMETRY = re.compile(r"^/v1/tenants/([^/]+)/cycles/([^/]+)/telemetry$")
    _ROUTE_SIMULATIONS = re.compile(r"^/v1/tenants/([^/]+)/simulations$")
    _ROUTE_SIMULATION_DETAIL = re.compile(r"^/v1/tenants/([^/]+)/simulations/([^/]+)$")
    _ROUTE_SCENARIOS = re.compile(r"^/v1/scenarios$")
    _ROUTE_ONBOARD_AND_SCAN = re.compile(r"^/v1/tenants/([^/]+)/onboard-and-scan$")
    _ROUTE_ADMIN_OPERATOR_REGISTER = re.compile(r"^/v1/admin/operators/register$")
    _ROUTE_ADMIN_TENANT_REGISTER = re.compile(r"^/v1/admin/tenants/register$")
    _ROUTE_ADMIN_USERS = re.compile(r"^/v1/admin/users$")
    _ROUTE_ADMIN_USER_DELETE = re.compile(r"^/v1/admin/users/([^/]+)$")
    _ROUTE_ADMIN_USER_CHANGE_PASSWORD = re.compile(r"^/v1/admin/users/([^/]+)/change-password$")
    _ROUTE_ADMIN_ME = re.compile(r"^/v1/admin/me$")
    _ROUTE_ADMIN_WORKSPACE_RESET = re.compile(r"^/v1/admin/workspace/reset$")
    _ROUTE_ADMIN_PROFILE_UPDATE = re.compile(r"^/v1/admin/profile/update$")
    _ROUTE_ADMIN_CREDENTIALS_CHANGE_PASSWORD = re.compile(r"^/v1/admin/credentials/change-password$")

    _BUNDLE_FORBIDDEN_QUERY = {
        "record_type",
        "page",
        "page_size",
        "telemetry_page",
        "telemetry_page_size",
    }

    def __init__(
        self,
        *,
        runtime: EngineRuntime,
        operator_storage_root: str,
        operator_service: OperatorService | None = None,
        health_state: HealthState | None = None,
    ):
        self._auth = OperatorAuthAdapter(operator_storage_root)
        self._admin = OperatorAdminAdapter(
            operator_storage_root=operator_storage_root,
            operator_service=operator_service,
        )
        self._session_guard = SessionGuard(operator_storage_root)
        self._runtime = RuntimeReadAdapter(runtime)
        self._health_state = health_state

    def handle(self, request: APIRequest) -> APIResponse:
        return run_with_api_error_boundary(lambda: self._dispatch(request))

    # =========================================================
    # ROUTING
    # =========================================================

    def _dispatch(self, request: APIRequest) -> Dict[str, Any]:
        method = request.method
        path = self._normalize_route_path(request.path)

        if path == "/health":
            self._require_method(method, "GET")
            return self._health_payload(include_readiness=False)

        if path == "/ready":
            self._require_method(method, "GET")
            return self._health_payload(include_readiness=True)

        if path == "/v1/auth/login":
            self._require_method(method, "POST")
            return self._login(request)

        if path == "/v1/auth/register":
            self._require_method(method, "POST")
            return self._register_account(request.json_body)

        if path == "/v1/auth/reset-password":
            self._require_method(method, "POST")
            return self._reset_password(request.json_body)

        if path == "/v1/auth/logout":
            self._require_method(method, "POST")
            token = self._session_token(request)
            return self._auth.logout(token)

        if path == "/v1/auth/me":
            self._require_method(method, "GET")
            token = self._session_token(request)
            return self._auth.me(
                token,
                client_ip=self._request_ip(request),
                user_agent=self._request_user_agent(request),
            )

        if self._ROUTE_ADMIN_OPERATOR_REGISTER.match(path):
            self._require_method(method, "POST")
            return self._register_operator(request)

        if self._ROUTE_ADMIN_TENANT_REGISTER.match(path):
            self._require_method(method, "POST")
            return self._register_tenant(request)

        if self._ROUTE_ADMIN_USERS.match(path):
            if method == "GET":
                return self._list_users(request)
            if method == "POST":
                return self._register_operator(request)
            raise APIError(405, "method_not_allowed", "method not allowed")

        m = self._ROUTE_ADMIN_USER_DELETE.match(path)
        if m:
            self._require_method(method, "DELETE")
            return self._delete_user(request, target_operator_id=m.group(1))

        m = self._ROUTE_ADMIN_USER_CHANGE_PASSWORD.match(path)
        if m:
            self._require_method(method, "POST")
            return self._change_user_password(request, target_operator_id=m.group(1))

        if self._ROUTE_ADMIN_ME.match(path):
            self._require_method(method, "DELETE")
            return self._delete_current_user(request)

        if self._ROUTE_ADMIN_WORKSPACE_RESET.match(path):
            self._require_method(method, "POST")
            return self._reset_workspace(request)

        if self._ROUTE_ADMIN_PROFILE_UPDATE.match(path):
            self._require_method(method, "POST")
            return self._update_profile(request)

        if self._ROUTE_ADMIN_CREDENTIALS_CHANGE_PASSWORD.match(path):
            self._require_method(method, "POST")
            return self._change_password(request)

        m = self._ROUTE_ONBOARD_AND_SCAN.match(path)
        if m:
            self._require_method(method, "POST")
            tenant_id = m.group(1)
            ctx = self._session_guard.require_session(
                self._authorization_header(request),
                client_ip=self._request_ip(request),
                user_agent=self._request_user_agent(request),
            )
            ctx.tenant_scope.assert_allowed(tenant_id)
            return self._onboard_and_scan(request, tenant_id=tenant_id, operator_id=ctx.operator_id)

        m = self._ROUTE_DASHBOARD.match(path)
        if m:
            self._require_method(method, "GET")
            tenant_id = m.group(1)
            ctx = self._session_guard.require_session(
                self._authorization_header(request),
                client_ip=self._request_ip(request),
                user_agent=self._request_user_agent(request),
            )
            return self._runtime.dashboard(tenant_id, authz_scope=ctx.tenant_scope)

        m = self._ROUTE_ENDPOINTS.match(path)
        if m:
            self._require_method(method, "GET")
            tenant_id = m.group(1)
            ctx = self._session_guard.require_session(
                self._authorization_header(request),
                client_ip=self._request_ip(request),
                user_agent=self._request_user_agent(request),
            )
            return self._runtime.endpoint_page(
                tenant_id,
                authz_scope=ctx.tenant_scope,
                page=self._query_int(request.query, "page", 1, min_value=1, max_value=100_000),
                page_size=self._query_int(
                    request.query,
                    "page_size",
                    200,
                    min_value=1,
                    max_value=5_000,
                ),
            )

        m = self._ROUTE_ENDPOINT_DETAIL.match(path)
        if m:
            self._require_method(method, "GET")
            tenant_id, entity_id = m.group(1), unquote(m.group(2))
            ctx = self._session_guard.require_session(
                self._authorization_header(request),
                client_ip=self._request_ip(request),
                user_agent=self._request_user_agent(request),
            )
            payload = self._runtime.endpoint_detail(
                tenant_id,
                entity_id,
                authz_scope=ctx.tenant_scope,
            )
            if not isinstance(payload.get("row"), dict):
                raise APIError(404, "not_found", "endpoint not found")
            return payload

        m = self._ROUTE_SCAN_STATUS.match(path)
        if m:
            self._require_method(method, "GET")
            tenant_id = m.group(1)
            ctx = self._session_guard.require_session(
                self._authorization_header(request),
                client_ip=self._request_ip(request),
                user_agent=self._request_user_agent(request),
            )
            return self._runtime.scan_status(tenant_id, authz_scope=ctx.tenant_scope)

        m = self._ROUTE_CYCLES.match(path)
        if m:
            self._require_method(method, "GET")
            tenant_id = m.group(1)
            ctx = self._session_guard.require_session(
                self._authorization_header(request),
                client_ip=self._request_ip(request),
                user_agent=self._request_user_agent(request),
            )
            return self._runtime.list_cycles(
                tenant_id,
                authz_scope=ctx.tenant_scope,
                page=self._query_int(request.query, "page", 1, min_value=1, max_value=100_000),
                page_size=self._query_int(
                    request.query,
                    "page_size",
                    200,
                    min_value=1,
                    max_value=1_000,
                ),
            )

        m = self._ROUTE_CYCLE_BUNDLE.match(path)
        if m:
            self._require_method(method, "GET")
            self._assert_no_forbidden_bundle_query_params(request.query)
            tenant_id, cycle_id = m.group(1), m.group(2)
            ctx = self._session_guard.require_session(
                self._authorization_header(request),
                client_ip=self._request_ip(request),
                user_agent=self._request_user_agent(request),
            )
            return self._runtime.cycle_bundle(
                tenant_id,
                cycle_id,
                authz_scope=ctx.tenant_scope,
            )

        m = self._ROUTE_CYCLE_TELEMETRY.match(path)
        if m:
            self._require_method(method, "GET")
            tenant_id, cycle_id = m.group(1), m.group(2)
            ctx = self._session_guard.require_session(
                self._authorization_header(request),
                client_ip=self._request_ip(request),
                user_agent=self._request_user_agent(request),
            )
            return self._runtime.cycle_telemetry(
                tenant_id,
                cycle_id,
                authz_scope=ctx.tenant_scope,
                record_type=self._query_str(request.query, "record_type", "all"),
                page=self._query_int(request.query, "page", 1, min_value=1, max_value=100_000),
                page_size=self._query_int(
                    request.query,
                    "page_size",
                    500,
                    min_value=1,
                    max_value=10_000,
                ),
            )

        if self._ROUTE_SCENARIOS.match(path):
            self._require_method(method, "GET")
            ctx = self._session_guard.require_session(
                self._authorization_header(request),
                client_ip=self._request_ip(request),
                user_agent=self._request_user_agent(request),
            )
            return self._runtime.list_scenarios()

        m = self._ROUTE_SIMULATIONS.match(path)
        if m:
            tenant_id = m.group(1)
            ctx = self._session_guard.require_session(
                self._authorization_header(request),
                client_ip=self._request_ip(request),
                user_agent=self._request_user_agent(request),
            )
            if method == "POST":
                ctx.tenant_scope.assert_allowed(tenant_id)
                payload = dict(request.json_body or {})
                scenario_id = str(payload.get("scenario_id", "")).strip()
                if not scenario_id:
                    raise APIError(400, "bad_request", "scenario_id is required")
                scenario_params = payload.get("scenario_params")
                if scenario_params is not None and not isinstance(scenario_params, dict):
                    raise APIError(400, "bad_request", "scenario_params must be an object")
                path_mode = str(payload.get("path_mode", "SAFE")).strip().upper()
                if path_mode not in {"SAFE", "EXTENDED", "DEEP"}:
                    raise APIError(400, "bad_request", "invalid path_mode")
                return self._runtime.run_simulation(
                    tenant_id,
                    authz_scope=ctx.tenant_scope,
                    scenario_id=scenario_id,
                    scenario_params=scenario_params,
                    path_mode=path_mode,
                )
            if method == "GET":
                return self._runtime.list_simulations(
                    tenant_id,
                    authz_scope=ctx.tenant_scope,
                    page=self._query_int(request.query, "page", 1, min_value=1, max_value=100_000),
                    page_size=self._query_int(
                        request.query,
                        "page_size",
                        100,
                        min_value=1,
                        max_value=1_000,
                    ),
                )
            raise APIError(405, "method_not_allowed", "GET or POST required")

        m = self._ROUTE_SIMULATION_DETAIL.match(path)
        if m:
            self._require_method(method, "GET")
            tenant_id, simulation_id = m.group(1), m.group(2)
            ctx = self._session_guard.require_session(
                self._authorization_header(request),
                client_ip=self._request_ip(request),
                user_agent=self._request_user_agent(request),
            )
            return self._runtime.simulation_detail(
                tenant_id,
                simulation_id,
                authz_scope=ctx.tenant_scope,
            )

        raise APIError(404, "not_found", "route not found")

    @staticmethod
    def _normalize_route_path(path: str) -> str:
        raw = str(path or "").strip()
        if not raw:
            return "/"
        parsed = urlsplit(raw)
        normalized = str(parsed.path or raw).strip() or "/"
        if normalized != "/" and normalized.endswith("/"):
            normalized = normalized.rstrip("/")
        return normalized

    # =========================================================
    # HANDLERS
    # =========================================================

    def _login(self, request: APIRequest) -> Dict[str, Any]:
        payload = dict(request.json_body or {})
        return self._auth.login(
            operator_id=str(payload.get("operator_id", "")).strip(),
            password=str(payload.get("password", "")),
            client_ip=self._request_ip(request),
            user_agent=self._request_user_agent(request),
        )

    def _register_account(self, body: Dict[str, Any] | None) -> Dict[str, Any]:
        payload = dict(body or {})
        created_at = payload.get("created_at_unix_ms")
        if created_at is None or str(created_at).strip() == "":
            created_at = int(time.time() * 1000)
        return self._admin.register_account_with_workspace(
            email=str(payload.get("email", "")).strip(),
            password=str(payload.get("password", "")),
            created_at_unix_ms=int(created_at),
            status=str(payload.get("status", "ACTIVE")).strip() or "ACTIVE",
            institution_name=(
                str(payload.get("institution_name", "")).strip()
                if payload.get("institution_name") is not None
                else None
            ),
        )

    def _reset_password(self, body: Dict[str, Any] | None) -> Dict[str, Any]:
        payload = dict(body or {})
        return self._admin.reset_password(
            identifier=str(payload.get("identifier", "")).strip(),
            new_password=str(payload.get("new_password", "")),
        )

    def _register_operator(self, request: APIRequest) -> Dict[str, Any]:
        payload = dict(request.json_body or {})
        acting_operator_id = None
        tenant_id = None

        # Bootstrap mode: first operator can be created without session.
        # Once at least one operator exists, a valid session is required.
        if self._admin.has_any_operator():
            authz = self._authorization_header(request).strip()
            if authz:
                ctx = self._session_guard.require_session(
                    authz,
                    client_ip=self._request_ip(request),
                    user_agent=self._request_user_agent(request),
                )
                acting_operator_id = ctx.operator_id
                tenant_id = str(payload.get("tenant_id", "")).strip() or None
                if tenant_id:
                    ctx.tenant_scope.assert_allowed(tenant_id)

        created_at = payload.get("created_at_unix_ms")
        if created_at is None or str(created_at).strip() == "":
            created_at = 0

        return self._admin.register_operator(
            acting_operator_id=acting_operator_id,
            tenant_id=tenant_id,
            operator_id=str(payload.get("operator_id", "")).strip(),
            email=str(payload.get("email", "")).strip(),
            password=str(payload.get("password", "")),
            created_at_unix_ms=int(created_at),
            status=str(payload.get("status", "ACTIVE")).strip() or "ACTIVE",
        )

    def _list_users(self, request: APIRequest) -> Dict[str, Any]:
        ctx = self._session_guard.require_session(
            self._authorization_header(request),
            client_ip=self._request_ip(request),
            user_agent=self._request_user_agent(request),
        )
        tenant_id = self._query_str(request.query, "tenant_id", "").strip() or None
        if tenant_id:
            ctx.tenant_scope.assert_allowed(tenant_id)
        return self._admin.list_users(operator_id=ctx.operator_id, tenant_id=tenant_id)

    def _delete_user(self, request: APIRequest, *, target_operator_id: str) -> Dict[str, Any]:
        ctx = self._session_guard.require_session(
            self._authorization_header(request),
            client_ip=self._request_ip(request),
            user_agent=self._request_user_agent(request),
        )
        tenant_id = self._query_str(request.query, "tenant_id", "").strip() or None
        if tenant_id:
            ctx.tenant_scope.assert_allowed(tenant_id)
        payload = dict(request.json_body or {})
        return self._admin.delete_user(
            operator_id=ctx.operator_id,
            tenant_id=tenant_id,
            target_operator_id=target_operator_id,
            current_password=str(payload.get("current_password", "")),
        )

    def _change_user_password(self, request: APIRequest, *, target_operator_id: str) -> Dict[str, Any]:
        ctx = self._session_guard.require_session(
            self._authorization_header(request),
            client_ip=self._request_ip(request),
            user_agent=self._request_user_agent(request),
        )
        tenant_id = self._query_str(request.query, "tenant_id", "").strip() or None
        if tenant_id:
            ctx.tenant_scope.assert_allowed(tenant_id)
        payload = dict(request.json_body or {})
        return self._admin.change_user_password(
            operator_id=ctx.operator_id,
            tenant_id=tenant_id,
            target_operator_id=target_operator_id,
            current_password=str(payload.get("current_password", "")),
            new_password=str(payload.get("new_password", "")),
        )

    def _reset_workspace(self, request: APIRequest) -> Dict[str, Any]:
        ctx = self._session_guard.require_session(
            self._authorization_header(request),
            client_ip=self._request_ip(request),
            user_agent=self._request_user_agent(request),
        )
        tenant_id = self._query_str(request.query, "tenant_id", "").strip() or None
        if tenant_id:
            ctx.tenant_scope.assert_allowed(tenant_id)
        payload = dict(request.json_body or {})
        return self._admin.reset_workspace(
            operator_id=ctx.operator_id,
            tenant_id=tenant_id,
            current_password=str(payload.get("current_password", "")),
        )

    def _delete_current_user(self, request: APIRequest) -> Dict[str, Any]:
        ctx = self._session_guard.require_session(
            self._authorization_header(request),
            client_ip=self._request_ip(request),
            user_agent=self._request_user_agent(request),
        )
        payload = dict(request.json_body or {})
        return self._admin.delete_current_user(
            operator_id=ctx.operator_id,
            current_password=str(payload.get("current_password", "")),
        )

    def _register_tenant(self, request: APIRequest) -> Dict[str, Any]:
        ctx = self._session_guard.require_session(
            self._authorization_header(request),
            client_ip=self._request_ip(request),
            user_agent=self._request_user_agent(request),
        )
        raise APIError(403, "forbidden", "additional tenant creation is not permitted")

    def _onboard_and_scan(
        self,
        request: APIRequest,
        *,
        tenant_id: str,
        operator_id: str,
    ) -> Dict[str, Any]:
        payload = dict(request.json_body or {})
        seed_endpoints_raw = payload.get("seed_endpoints")
        seed_endpoints: list[str] = []
        if isinstance(seed_endpoints_raw, list):
            seed_endpoints = [str(x).strip() for x in seed_endpoints_raw if str(x).strip()]

        return self._admin.onboard_workspace_and_start_cycle(
            operator_id=operator_id,
            tenant_id=tenant_id,
            institution_name=str(payload.get("institution_name", "")).strip(),
            main_url=str(payload.get("main_url", "")).strip(),
            seed_endpoints=seed_endpoints,
        )

    def _update_profile(self, request: APIRequest) -> Dict[str, Any]:
        ctx = self._session_guard.require_session(
            self._authorization_header(request),
            client_ip=self._request_ip(request),
            user_agent=self._request_user_agent(request),
        )
        payload = dict(request.json_body or {})
        tenant_id = str(payload.get("tenant_id", "")).strip()
        if not tenant_id:
            raise APIError(400, "bad_request", "tenant_id is required")
        ctx.tenant_scope.assert_allowed(tenant_id)
        return self._admin.update_profile(
            operator_id=ctx.operator_id,
            tenant_id=tenant_id,
            current_password=str(payload.get("current_password", "")),
            email=(
                str(payload.get("email", "")).strip()
                if payload.get("email") is not None
                else None
            ),
            institution_name=(
                str(payload.get("institution_name", "")).strip()
                if payload.get("institution_name") is not None
                else None
            ),
        )

    def _change_password(self, request: APIRequest) -> Dict[str, Any]:
        ctx = self._session_guard.require_session(
            self._authorization_header(request),
            client_ip=self._request_ip(request),
            user_agent=self._request_user_agent(request),
        )
        payload = dict(request.json_body or {})
        return self._admin.change_password(
            operator_id=ctx.operator_id,
            current_password=str(payload.get("current_password", "")),
            new_password=str(payload.get("new_password", "")),
        )

    # =========================================================
    # UTIL
    # =========================================================

    def _authorization_header(self, request: APIRequest) -> str:
        return request.headers.get("authorization", "")

    def _health_payload(self, *, include_readiness: bool) -> Dict[str, Any]:
        state = self._health_state
        if state is None:
            payload = {"healthy": True}
            if include_readiness:
                payload["ready"] = True
            return payload
        payload = {
            "healthy": bool(state.healthy),
            "last_successful_cycle": state.last_successful_cycle,
            "last_failure_timestamp": state.last_failure_timestamp,
        }
        if include_readiness:
            payload["ready"] = bool(state.ready)
        return payload

    def _request_ip(self, request: APIRequest) -> str:
        forwarded = str(request.headers.get("x-forwarded-for", "")).strip()
        if forwarded:
            return forwarded.split(",", 1)[0].strip()
        return str(request.headers.get("x-real-ip", "")).strip()

    def _request_user_agent(self, request: APIRequest) -> str:
        return str(request.headers.get("user-agent", "")).strip()

    def _session_token(self, request: APIRequest) -> str:
        header = self._authorization_header(request)
        parts = str(header or "").strip().split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise APIError(401, "unauthorized", "missing session token")
        token = parts[1].strip()
        if not token:
            raise APIError(401, "unauthorized", "missing session token")
        return token

    def _query_int(
        self,
        query: Dict[str, str],
        key: str,
        default: int,
        *,
        min_value: int,
        max_value: int,
    ) -> int:
        raw = str(query.get(key, "")).strip()
        if not raw:
            return int(default)
        try:
            value = int(raw)
        except Exception as exc:
            raise APIError(400, "bad_request", f"invalid {key}") from exc
        if value < min_value or value > max_value:
            raise APIError(400, "bad_request", f"invalid {key}")
        return value

    def _query_str(
        self,
        query: Dict[str, str],
        key: str,
        default: str,
    ) -> str:
        raw = str(query.get(key, "")).strip()
        return raw or default

    def _assert_no_forbidden_bundle_query_params(self, query: Dict[str, str]) -> None:
        for key in query.keys():
            if key in self._BUNDLE_FORBIDDEN_QUERY:
                raise APIError(
                    400,
                    "bad_request",
                    f"unsupported query parameter for bundle endpoint: {key}",
                )

    def _require_method(self, observed: str, required: str) -> None:
        if observed != required:
            raise APIError(405, "method_not_allowed", f"{required} required")
