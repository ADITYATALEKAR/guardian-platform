from __future__ import annotations

from typing import Callable

from infrastructure.layer5_api.errors import APIError, normalize_error
from infrastructure.layer5_api.models import APIResponse


def run_with_api_error_boundary(fn: Callable[[], dict]) -> APIResponse:
    try:
        payload = fn()
        return APIResponse(status_code=200, payload={"data": payload})
    except Exception as exc:
        err: APIError = normalize_error(exc)
        if err.status_code >= 500:
            import traceback
            print(f"[API ERROR {err.status_code}] {err.code}: {err.message}", flush=True)
            traceback.print_exc()
        return APIResponse(
            status_code=err.status_code,
            payload={
                "error": {
                    "code": err.code,
                    "message": err.message,
                }
            },
        )
