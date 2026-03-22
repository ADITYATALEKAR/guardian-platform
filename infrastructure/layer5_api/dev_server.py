from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from infrastructure.layer5_api import APIRequest, Layer5BootstrapConfig, build_layer5_api


def _parse_query(raw_query: str) -> dict[str, str]:
    parsed = parse_qs(raw_query, keep_blank_values=True)
    return {k: (v[-1] if v else "") for k, v in parsed.items()}


def _read_json_body(handler: BaseHTTPRequestHandler) -> dict | None:
    length = int(handler.headers.get("content-length", "0") or "0")
    if length <= 0:
        return None
    raw = handler.rfile.read(length)
    if not raw:
        return None
    return json.loads(raw.decode("utf-8"))


def _default_allowed_origins(host: str, port: int) -> set[str]:
    origins = {
        f"http://{host}:{port}",
        f"http://localhost:{port}",
        f"http://127.0.0.1:{port}",
    }
    if host in {"127.0.0.1", "localhost"}:
        origins.update({"http://localhost:5173", "http://127.0.0.1:5173"})
    return origins


def run_layer5_dev_server(
    *,
    host: str,
    port: int,
    storage_root: str,
    operator_storage_root: str,
    simulation_root: str,
    master_env: str = "OPERATOR_MASTER_PASSWORD",
) -> None:
    api = build_layer5_api(
        Layer5BootstrapConfig(
            storage_root=storage_root,
            operator_storage_root=operator_storage_root,
            simulation_root=simulation_root,
            master_env=master_env,
        )
    )
    allowed_origins = _default_allowed_origins(host, port)

    class Handler(BaseHTTPRequestHandler):
        def _allow_origin(self) -> str:
            origin = str(self.headers.get("origin", "")).strip()
            if origin in allowed_origins:
                return origin
            return f"http://{host}:{port}"

        def _send(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.send_header("access-control-allow-origin", self._allow_origin())
            self.send_header("vary", "origin")
            self.send_header("access-control-allow-methods", "GET,POST,DELETE,OPTIONS")
            self.send_header(
                "access-control-allow-headers",
                "authorization,content-type,user-agent,x-forwarded-for,x-real-ip",
            )
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self) -> None:  # noqa: N802
            self.send_response(204)
            self.send_header("access-control-allow-origin", self._allow_origin())
            self.send_header("vary", "origin")
            self.send_header("access-control-allow-methods", "GET,POST,DELETE,OPTIONS")
            self.send_header(
                "access-control-allow-headers",
                "authorization,content-type,user-agent,x-forwarded-for,x-real-ip",
            )
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            self._handle()

        def do_POST(self) -> None:  # noqa: N802
            self._handle()

        def do_DELETE(self) -> None:  # noqa: N802
            self._handle()

        def _handle(self) -> None:
            try:
                parts = urlsplit(self.path)
                req = APIRequest(
                    method=self.command,
                    path=parts.path,
                    headers={k.lower(): v for k, v in self.headers.items()},
                    query=_parse_query(parts.query),
                    json_body=_read_json_body(self),
                )
                resp = api.handle(req)
                self._send(resp.status_code, resp.payload)
            except Exception as exc:  # defensive boundary at transport edge
                import traceback
                traceback.print_exc()
                self._send(500, {"error": {"code": "transport_error", "message": str(exc)}})

        def log_message(self, fmt: str, *args) -> None:
            print(f"[DEV] {self.command} {self.path} -> {fmt % args}", flush=True)

    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.timeout = 15
    httpd.daemon_threads = True
    print(f"Layer5 API dev server running at http://{host}:{port}")
    httpd.serve_forever()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Layer5 API local dev server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--storage-root", required=True)
    parser.add_argument("--operator-storage-root", required=True)
    parser.add_argument("--simulation-root", required=True)
    parser.add_argument("--master-env", default="OPERATOR_MASTER_PASSWORD")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    run_layer5_dev_server(
        host=args.host,
        port=args.port,
        storage_root=args.storage_root,
        operator_storage_root=args.operator_storage_root,
        simulation_root=args.simulation_root,
        master_env=args.master_env,
    )
