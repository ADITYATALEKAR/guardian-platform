from __future__ import annotations


class APIError(RuntimeError):
    """Normalized API error with HTTP-like status and machine code."""

    def __init__(self, status_code: int, code: str, message: str):
        self.status_code = int(status_code)
        self.code = str(code or "api_error").strip() or "api_error"
        self.message = str(message or "request failed").strip() or "request failed"
        super().__init__(self.message)


class BadRequestError(APIError):
    def __init__(self, message: str):
        super().__init__(400, "bad_request", message)


class UnauthorizedError(APIError):
    def __init__(self, message: str = "invalid session", *, code: str = "unauthorized"):
        super().__init__(401, code, message)


class ForbiddenError(APIError):
    def __init__(self, message: str, *, code: str = "forbidden"):
        super().__init__(403, code, message)


class NotFoundError(APIError):
    def __init__(self, message: str = "resource not found"):
        super().__init__(404, "not_found", message)


class ConflictError(APIError):
    def __init__(self, message: str = "resource already exists"):
        super().__init__(409, "conflict", message)


def normalize_error(exc: Exception) -> APIError:
    if isinstance(exc, APIError):
        return exc

    msg = str(exc or "").strip().lower()

    if "unauthorized tenant access" in msg:
        return APIError(403, "forbidden", "tenant scope violation")

    if "invalid session" in msg or "session not found" in msg:
        return APIError(401, "unauthorized", "invalid session")

    if "invalid credentials" in msg:
        return APIError(401, "invalid_credentials", "invalid credentials")

    if "not found" in msg:
        return APIError(404, "not_found", "resource not found")

    if isinstance(exc, ValueError):
        return APIError(400, "bad_request", str(exc))

    return APIError(500, "internal_error", str(exc) or "internal server error")
