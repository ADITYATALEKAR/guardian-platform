from __future__ import annotations

from typing import Any, Dict, Optional

try:
    from curl_cffi import requests as curl_requests

    CURL_CFFI_AVAILABLE = True
except Exception:
    curl_requests = None
    CURL_CFFI_AVAILABLE = False


BOT_GATED_STATUSES = {403, 405, 406, 409, 429, 503}
BOT_GATED_HINTS = (
    "cloudflare",
    "akamai",
    "bot",
    "captcha",
    "challenge",
    "attention required",
    "access denied",
)


def should_attempt_browser_fallback(
    *,
    status_code: Optional[int] = None,
    headers: Optional[Dict[str, Any]] = None,
    error_text: str = "",
) -> bool:
    if status_code in BOT_GATED_STATUSES:
        return True
    hint_text = str(error_text or "").strip().lower()
    if headers:
        for key, value in headers.items():
            hint_text += f" {str(key).lower()}:{str(value).lower()}"
    return any(token in hint_text for token in BOT_GATED_HINTS)


def browser_request(
    *,
    method: str,
    url: str,
    timeout: float,
    headers: Optional[Dict[str, str]] = None,
    allow_redirects: bool = True,
    verify: bool = True,
    max_body_bytes: int = 1_000_000,
) -> Optional[Dict[str, Any]]:
    if not CURL_CFFI_AVAILABLE:
        return None
    try:
        response = curl_requests.request(
            method=method,
            url=url,
            timeout=float(timeout),
            headers=dict(headers or {}),
            allow_redirects=bool(allow_redirects),
            verify=bool(verify),
            impersonate="chrome124",
            stream=method.upper() == "GET",
        )
        body = ""
        if method.upper() == "GET":
            chunks = []
            size = 0
            for chunk in response.iter_content(chunk_size=65536):
                size += len(chunk)
                chunks.append(chunk)
                if size >= max_body_bytes:
                    break
            body = b"".join(chunks).decode("utf-8", errors="replace")
        return {
            "status": int(getattr(response, "status_code", 0) or 0),
            "headers": dict(getattr(response, "headers", {}) or {}),
            "redirect": (getattr(response, "headers", {}) or {}).get("Location"),
            "url": str(url),
            "final_url": str(getattr(response, "url", url)),
            "body": body,
            "transport": "curl_cffi",
        }
    except Exception:
        return None
