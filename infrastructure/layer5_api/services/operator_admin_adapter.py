from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

from infrastructure.layer5_api.errors import (
    APIError,
    BadRequestError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    UnauthorizedError,
)
from infrastructure.operator_plane.registry.operator_registry import list_operators
from infrastructure.operator_plane.services.operator_service import OperatorService


class OperatorAdminAdapter:
    """
    Thin admin adapter for Layer 5 Phase 5 operator flows.

    - Uses OperatorService when provided.
    - Preserves bootstrap path (first operator can be created before login).
    """

    def __init__(
        self,
        operator_storage_root: str,
        operator_service: Optional[OperatorService] = None,
    ):
        self._root = str(operator_storage_root)
        self._service = operator_service

    def has_any_operator(self) -> bool:
        return len(list_operators(self._root)) > 0

    def register_operator(
        self,
        *,
        acting_operator_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        operator_id: str,
        email: str,
        password: str,
        created_at_unix_ms: int,
        status: str = "ACTIVE",
        role: str = OperatorService.ROLE_MEMBER,
    ) -> Dict[str, Any]:
        service = self._require_service()
        resolved_operator_id = str(operator_id or "").strip() or self._derive_operator_id(email)
        try:
            if acting_operator_id:
                return service.add_user_to_tenant(
                    operator_id=acting_operator_id,
                    tenant_id=tenant_id,
                    new_operator_id=resolved_operator_id,
                    email=email,
                    password=password,
                    created_at_unix_ms=created_at_unix_ms,
                    status=status,
                    role=role,
                )
            return service.register_operator(
                operator_id=resolved_operator_id,
                email=email,
                password=password,
                created_at_unix_ms=created_at_unix_ms,
                status=status,
                role=OperatorService.ROLE_OWNER,
            )
        except Exception as exc:
            self._raise_mapped(exc)
        raise APIError(500, "internal_error", "internal server error")

    def register_tenant(
        self,
        *,
        operator_id: str,
        institution_name: str,
        main_url: str,
        seed_endpoints: list[str] | None,
        password: str | None,
        registration_metadata: Optional[Dict[str, Any]] = None,
        created_at_unix_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        service = self._require_service()
        try:
            return service.register_tenant(
                operator_id=operator_id,
                institution_name=institution_name,
                main_url=main_url,
                seed_endpoints=list(seed_endpoints or []),
                password=password,
                registration_metadata=registration_metadata,
                created_at_unix_ms=created_at_unix_ms,
            )
        except Exception as exc:
            self._raise_mapped(exc)
        raise APIError(500, "internal_error", "internal server error")

    def register_account_with_workspace(
        self,
        *,
        email: str,
        password: str,
        created_at_unix_ms: int,
        status: str = "ACTIVE",
        institution_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        service = self._require_service()
        operator_id = self._derive_operator_id(email)
        workspace_name = (
            str(institution_name or "").strip()
            or self._derive_workspace_name(email)
        )
        try:
            operator = service.register_operator(
                operator_id=operator_id,
                email=email,
                password=password,
                created_at_unix_ms=created_at_unix_ms,
                status=status,
            )
            workspace = service.create_workspace(
                operator_id=operator_id,
                institution_name=workspace_name,
            )
            return {
                "operator_id": operator.get("operator_id", operator_id),
                "email": operator.get("email", email),
                "status": operator.get("status", status),
                "tenant_id": workspace.get("tenant_id"),
                "onboarding_status": workspace.get("onboarding_status", "PENDING"),
                "cycle_started": workspace.get("cycle_started", False),
            }
        except Exception as exc:
            self._raise_mapped(exc)
        raise APIError(500, "internal_error", "internal server error")

    def onboard_workspace_and_start_cycle(
        self,
        *,
        operator_id: str,
        tenant_id: str,
        institution_name: str,
        main_url: str,
        seed_endpoints: list[str] | None,
    ) -> Dict[str, Any]:
        service = self._require_service()
        try:
            return service.onboard_workspace_and_start_cycle(
                operator_id=operator_id,
                tenant_id=tenant_id,
                institution_name=institution_name,
                main_url=main_url,
                seed_endpoints=list(seed_endpoints or []),
            )
        except Exception as exc:
            self._raise_mapped(exc)
        raise APIError(500, "internal_error", "internal server error")

    def update_profile(
        self,
        *,
        operator_id: str,
        tenant_id: str,
        current_password: str,
        email: Optional[str] = None,
        institution_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        service = self._require_service()
        try:
            return service.update_profile(
                operator_id=operator_id,
                tenant_id=tenant_id,
                current_password=current_password,
                email=email,
                institution_name=institution_name,
            )
        except Exception as exc:
            self._raise_mapped(exc)
        raise APIError(500, "internal_error", "internal server error")

    def change_password(
        self,
        *,
        operator_id: str,
        current_password: str,
        new_password: str,
    ) -> Dict[str, Any]:
        service = self._require_service()
        try:
            return service.change_operator_password(
                operator_id=operator_id,
                current_password=current_password,
                new_password=new_password,
            )
        except Exception as exc:
            self._raise_mapped(exc)
        raise APIError(500, "internal_error", "internal server error")

    def reset_password(
        self,
        *,
        identifier: str,
        new_password: str,
    ) -> Dict[str, Any]:
        service = self._require_service()
        try:
            return service.reset_password_by_identifier(
                identifier=identifier,
                new_password=new_password,
            )
        except Exception as exc:
            self._raise_mapped(exc)
        raise APIError(500, "internal_error", "internal server error")

    def list_users(
        self,
        *,
        operator_id: str,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        service = self._require_service()
        try:
            return service.list_users_for_tenant(
                operator_id=operator_id,
                tenant_id=tenant_id,
            )
        except Exception as exc:
            self._raise_mapped(exc)
        raise APIError(500, "internal_error", "internal server error")

    def delete_user(
        self,
        *,
        operator_id: str,
        tenant_id: Optional[str],
        target_operator_id: str,
        current_password: str,
    ) -> Dict[str, Any]:
        service = self._require_service()
        try:
            return service.delete_user_from_tenant(
                operator_id=operator_id,
                tenant_id=tenant_id,
                target_operator_id=target_operator_id,
                current_password=current_password,
            )
        except Exception as exc:
            self._raise_mapped(exc)
        raise APIError(500, "internal_error", "internal server error")

    def change_user_password(
        self,
        *,
        operator_id: str,
        tenant_id: Optional[str],
        target_operator_id: str,
        current_password: str,
        new_password: str,
    ) -> Dict[str, Any]:
        service = self._require_service()
        try:
            return service.change_user_password_in_tenant(
                operator_id=operator_id,
                tenant_id=tenant_id,
                target_operator_id=target_operator_id,
                current_password=current_password,
                new_password=new_password,
            )
        except Exception as exc:
            self._raise_mapped(exc)
        raise APIError(500, "internal_error", "internal server error")

    def reset_workspace(
        self,
        *,
        operator_id: str,
        tenant_id: Optional[str],
        current_password: str,
    ) -> Dict[str, Any]:
        service = self._require_service()
        try:
            return service.reset_workspace(
                operator_id=operator_id,
                tenant_id=tenant_id,
                current_password=current_password,
            )
        except Exception as exc:
            self._raise_mapped(exc)
        raise APIError(500, "internal_error", "internal server error")

    def delete_current_user(
        self,
        *,
        operator_id: str,
        current_password: str,
    ) -> Dict[str, Any]:
        service = self._require_service()
        try:
            return service.delete_current_user(
                operator_id=operator_id,
                current_password=current_password,
            )
        except Exception as exc:
            self._raise_mapped(exc)
        raise APIError(500, "internal_error", "internal server error")

    def _require_service(self) -> OperatorService:
        if self._service is None:
            raise APIError(501, "not_implemented", "operator admin service not configured")
        return self._service

    def _raise_mapped(self, exc: Exception) -> None:
        msg = str(exc or "").strip().lower()
        if "additional tenant creation is not permitted" in msg:
            raise ForbiddenError("additional tenant creation is not permitted") from exc
        if "owner role required" in msg or "admin role required" in msg:
            raise ForbiddenError("admin role required") from exc
        if "email already exists" in msg or "operator exists" in msg:
            raise ConflictError("account already exists") from exc
        if "cannot delete last owner" in msg:
            raise ConflictError("cannot delete last owner") from exc
        if "active cycle lock present" in msg or "active cycle already running" in msg:
            raise ConflictError("active cycle already running") from exc
        if "invalid credentials" in msg:
            raise UnauthorizedError("invalid credentials", code="invalid_credentials") from exc
        if msg == "password":
            raise BadRequestError("password must be at least 12 characters") from exc
        if "tenant already exists" in msg:
            raise ConflictError("tenant already exists") from exc
        if "already exists" in msg:
            raise ConflictError("resource already exists") from exc
        if "tenant_id required" in msg:
            raise BadRequestError("tenant_id is required") from exc
        if "invalid" in msg or "cannot be empty" in msg:
            raise BadRequestError("invalid request") from exc
        if "not found" in msg:
            raise NotFoundError("resource not found") from exc
        raise exc

    def _derive_operator_id(self, email: str) -> str:
        normalized = str(email or "").strip().lower()
        local = normalized.split("@")[0] if "@" in normalized else normalized
        safe = "".join(ch for ch in local if ch.isalnum())[:12] or "user"
        digest = hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:6]
        return f"usr_{safe}_{digest}"

    def _derive_workspace_name(self, email: str) -> str:
        normalized = str(email or "").strip().lower()
        local = normalized.split("@")[0] if "@" in normalized else normalized
        cleaned = local.replace(".", " ").replace("_", " ").strip()
        return cleaned.title() if cleaned else "New Workspace"
