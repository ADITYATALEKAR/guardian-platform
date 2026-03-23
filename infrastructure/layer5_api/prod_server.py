from __future__ import annotations

import json
import mimetypes
import os
from http import HTTPStatus
from pathlib import Path
from typing import Callable, Iterable, Mapping
from urllib.parse import parse_qs

from infrastructure.layer5_api import APIRequest, Layer5BootstrapConfig, build_layer5_api


_DEFAULT_MAX_BODY_BYTES = 1_048_576
_ALLOWED_METHODS = "GET,POST,OPTIONS"
_ALLOWED_HEADERS = "authorization,content-type,user-agent,x-forwarded-for,x-real-ip"


def _parse_query(raw_query: str) -> dict[str, str]:
    parsed = parse_qs(raw_query, keep_blank_values=True)
    return {k: (v[-1] if v else "") for k, v in parsed.items()}


def _status_line(status_code: int) -> str:
    try:
        phrase = HTTPStatus(int(status_code)).phrase
    except ValueError:
        phrase = "UNKNOWN"
    return f"{int(status_code)} {phrase}"


def _parse_bool(raw: str | None, *, default: bool = False) -> bool:
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _cors_origin(origin: str, allowed_origins: set[str]) -> str:
    candidate = str(origin or "").strip()
    if not candidate:
        return ""
    if candidate in allowed_origins:
        return candidate
    return ""


def _request_headers(
    environ: Mapping[str, str],
    *,
    trust_forwarded_headers: bool,
) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in environ.items():
        if not key.startswith("HTTP_"):
            continue
        header_name = key[5:].replace("_", "-").lower()
        headers[header_name] = str(value or "").strip()

    content_type = str(environ.get("CONTENT_TYPE", "") or "").strip()
    if content_type:
        headers["content-type"] = content_type

    content_length = str(environ.get("CONTENT_LENGTH", "") or "").strip()
    if content_length:
        headers["content-length"] = content_length

    remote_addr = str(environ.get("REMOTE_ADDR", "") or "").strip()
    if trust_forwarded_headers:
        if remote_addr and not headers.get("x-real-ip"):
            headers["x-real-ip"] = remote_addr
    else:
        headers.pop("x-forwarded-for", None)
        headers.pop("x-real-ip", None)
        if remote_addr:
            headers["x-real-ip"] = remote_addr
    return headers


def _read_json_body(
    environ: Mapping[str, object],
    *,
    max_body_bytes: int,
) -> dict | None:
    raw_length = str(environ.get("CONTENT_LENGTH", "") or "").strip()
    if not raw_length:
        return None
    try:
        length = int(raw_length)
    except Exception as exc:  # pragma: no cover - defensive parse boundary
        raise ValueError("invalid content-length") from exc
    if length <= 0:
        return None
    if length > max_body_bytes:
        raise OverflowError("payload too large")

    stream = environ.get("wsgi.input")
    if stream is None:
        return None
    raw = stream.read(length)
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError("invalid json") from exc


def _json_response(
    start_response: Callable[[str, list[tuple[str, str]]], object],
    *,
    status_code: int,
    payload: dict,
    allow_origin: str = "",
) -> Iterable[bytes]:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    headers = [
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(body))),
        ("Cache-Control", "no-store"),
    ]
    if allow_origin:
        headers.extend(
            [
                ("Access-Control-Allow-Origin", allow_origin),
                ("Vary", "Origin"),
                ("Access-Control-Allow-Methods", _ALLOWED_METHODS),
                ("Access-Control-Allow-Headers", _ALLOWED_HEADERS),
            ]
        )
    start_response(_status_line(status_code), headers)
    return [body]


def _error_payload(code: str, message: str) -> dict:
    return {"error": {"code": str(code), "message": str(message)}}


def _resolve_static_root() -> Path | None:
    env_val = str(os.getenv("LAYER5_STATIC_ROOT", "")).strip()
    if env_val:
        p = Path(env_val)
        return p if p.is_dir() else None
    candidates = [
        Path(__file__).resolve().parent.parent.parent / "layers" / "layer5_interface_ui_ux" / "dist",
    ]
    for c in candidates:
        if c.is_dir() and (c / "index.html").is_file():
            return c
    return None


def _serve_static(
    start_response: Callable[[str, list[tuple[str, str]]], object],
    static_root: Path,
    url_path: str,
) -> Iterable[bytes] | None:
    clean = url_path.lstrip("/")
    if not clean:
        clean = "index.html"
    target = (static_root / clean).resolve()
    if not str(target).startswith(str(static_root)):
        return None
    if not target.is_file():
        return None
    content_type, _ = mimetypes.guess_type(str(target))
    if content_type is None:
        content_type = "application/octet-stream"
    body = target.read_bytes()
    cache = "public, max-age=31536000, immutable" if "/assets/" in url_path else "no-cache"
    start_response(_status_line(200), [
        ("Content-Type", content_type),
        ("Content-Length", str(len(body))),
        ("Cache-Control", cache),
    ])
    return [body]


def build_layer5_wsgi_application(
    config: Layer5BootstrapConfig,
    *,
    allowed_origins: set[str] | None = None,
    trust_forwarded_headers: bool = False,
    max_body_bytes: int = _DEFAULT_MAX_BODY_BYTES,
) -> Callable[[Mapping[str, object], Callable[[str, list[tuple[str, str]]], object]], Iterable[bytes]]:
    api = build_layer5_api(config)
    cors_allowlist = {str(origin).strip() for origin in (allowed_origins or set()) if str(origin).strip()}
    body_limit = max(1, int(max_body_bytes))
    static_root = _resolve_static_root()

    def application(
        environ: Mapping[str, object],
        start_response: Callable[[str, list[tuple[str, str]]], object],
    ) -> Iterable[bytes]:
        method = str(environ.get("REQUEST_METHOD", "GET") or "GET").upper()
        path = str(environ.get("PATH_INFO", "/") or "/")
        query = _parse_query(str(environ.get("QUERY_STRING", "") or ""))
        origin = str(environ.get("HTTP_ORIGIN", "") or "").strip()
        allow_origin = _cors_origin(origin, cors_allowlist)

        if origin and not allow_origin:
            return _json_response(
                start_response,
                status_code=403,
                payload=_error_payload("forbidden", "origin not allowed"),
            )

        if method == "OPTIONS":
            headers = [
                ("Content-Length", "0"),
                ("Cache-Control", "no-store"),
                ("Access-Control-Allow-Methods", _ALLOWED_METHODS),
                ("Access-Control-Allow-Headers", _ALLOWED_HEADERS),
            ]
            if allow_origin:
                headers.extend(
                    [
                        ("Access-Control-Allow-Origin", allow_origin),
                        ("Vary", "Origin"),
                    ]
                )
            start_response(_status_line(204), headers)
            return [b""]

        # API routes: /v1/*, /health, /ready
        if path.startswith("/v1/") or path in ("/health", "/ready"):
            try:
                headers = _request_headers(
                    environ,
                    trust_forwarded_headers=trust_forwarded_headers,
                )
                json_body = _read_json_body(environ, max_body_bytes=body_limit)
            except OverflowError:
                return _json_response(
                    start_response,
                    status_code=413,
                    payload=_error_payload("payload_too_large", "request body exceeds configured limit"),
                    allow_origin=allow_origin,
                )
            except ValueError as exc:
                message = str(exc)
                code = "bad_request"
                if "json" in message:
                    code = "invalid_json"
                return _json_response(
                    start_response,
                    status_code=400,
                    payload=_error_payload(code, message),
                    allow_origin=allow_origin,
                )

            try:
                response = api.handle(
                    APIRequest(
                        method=method,
                        path=path,
                        headers=headers,
                        query=query,
                        json_body=json_body,
                    )
                )
                return _json_response(
                    start_response,
                    status_code=response.status_code,
                    payload=response.payload,
                    allow_origin=allow_origin,
                )
            except Exception as exc:  # pragma: no cover - transport edge boundary
                return _json_response(
                    start_response,
                    status_code=500,
                    payload=_error_payload("transport_error", str(exc)),
                    allow_origin=allow_origin,
                )

        # Static file serving (frontend SPA)
        if static_root and method == "GET":
            result = _serve_static(start_response, static_root, path)
            if result is not None:
                return result
            # SPA fallback: serve index.html for unmatched routes
            result = _serve_static(start_response, static_root, "/index.html")
            if result is not None:
                return result

        return _json_response(
            start_response,
            status_code=404,
            payload=_error_payload("not_found", "not found"),
        )

    return application


def build_layer5_wsgi_application_from_env() -> Callable[[Mapping[str, object], Callable[[str, list[tuple[str, str]]], object]], Iterable[bytes]]:
    storage_root = str(os.getenv("LAYER5_STORAGE_ROOT", "")).strip()
    operator_storage_root = str(os.getenv("LAYER5_OPERATOR_STORAGE_ROOT", "")).strip()
    simulation_root = str(os.getenv("LAYER5_SIMULATION_ROOT", "")).strip()
    if not storage_root or not operator_storage_root or not simulation_root:
        raise RuntimeError(
            "LAYER5_STORAGE_ROOT, LAYER5_OPERATOR_STORAGE_ROOT, and LAYER5_SIMULATION_ROOT are required"
        )

    allowed_origins_raw = str(os.getenv("LAYER5_ALLOWED_ORIGINS", "")).strip()
    allowed_origins = {
        item.strip()
        for item in allowed_origins_raw.split(",")
        if item.strip()
    }
    def _env_int(name: str, default: int) -> int:
        try:
            return int(os.getenv(name, "").strip() or default)
        except (ValueError, TypeError):
            return default

    return build_layer5_wsgi_application(
        Layer5BootstrapConfig(
            storage_root=storage_root,
            operator_storage_root=operator_storage_root,
            simulation_root=simulation_root,
            master_env=str(os.getenv("LAYER5_MASTER_ENV", "OPERATOR_MASTER_PASSWORD")).strip()
            or "OPERATOR_MASTER_PASSWORD",
            discovery_max_workers=_env_int("GUARDIAN_DISCOVERY_MAX_WORKERS", 8),
            discovery_max_endpoints=_env_int("GUARDIAN_DISCOVERY_MAX_ENDPOINTS", 200),
            cycle_time_budget_seconds=_env_int("GUARDIAN_CYCLE_TIME_BUDGET_SECONDS", 600),
            discovery_category_a_time_budget_seconds=_env_int("GUARDIAN_CAT_A_BUDGET_SECONDS", 120),
            discovery_bcde_time_budget_seconds=_env_int("GUARDIAN_CAT_BCDE_BUDGET_SECONDS", 120),
            discovery_exploration_budget_seconds=_env_int("GUARDIAN_EXPLORATION_BUDGET_SECONDS", 120),
            discovery_exploitation_budget_seconds=_env_int("GUARDIAN_EXPLOITATION_BUDGET_SECONDS", 120),
        ),
        allowed_origins=allowed_origins,
        trust_forwarded_headers=_parse_bool(os.getenv("LAYER5_TRUST_FORWARDED_HEADERS")),
        max_body_bytes=int(os.getenv("LAYER5_MAX_BODY_BYTES", str(_DEFAULT_MAX_BODY_BYTES)) or _DEFAULT_MAX_BODY_BYTES),
    )


class _LazyApplication:
    def __init__(self) -> None:
        self._application = None

    def __call__(
        self,
        environ: Mapping[str, object],
        start_response: Callable[[str, list[tuple[str, str]]], object],
    ) -> Iterable[bytes]:
        if self._application is None:
            try:
                self._application = build_layer5_wsgi_application_from_env()
            except Exception as exc:
                return _json_response(
                    start_response,
                    status_code=500,
                    payload=_error_payload("misconfigured_production_server", str(exc)),
                )
        return self._application(environ, start_response)


application = _LazyApplication()
