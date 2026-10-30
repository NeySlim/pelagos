# SPDX-License-Identifier: Apache-2.0
"""RFC 7807 problem documents and the error code table (section 19)."""

from __future__ import annotations

from typing import Any

from flask import Response, jsonify, request

from pelagos.domain import messages

PROBLEM_TYPE = "urn:pelagos:error:"
PROBLEM_MIME = "application/problem+json"

STATUS_BY_CODE: dict[str, int] = {
    "validation_error": 400,
    "invalid_credentials": 401,
    "totp_required": 401,
    "second_factor_required": 401,
    "unauthenticated": 401,
    "forbidden": 403,
    "csrf_failed": 403,
    "not_found": 404,
    "module_disabled": 404,
    "method_not_allowed": 405,
    "conflict": 409,
    "config_divergence": 409,
    "precondition_failed": 409,
    "preflight_failed": 409,
    "plan_state": 409,
    "zone_without_records": 409,
    "zone_too_large": 409,
    "plan_expired": 410,
    "engine_validation_failed": 422,
    "release_invalid": 422,
    "confirmation_required": 428,
    "rate_limited": 429,
    "internal_error": 500,
    "not_supported": 501,
    "not_implemented": 501,
    "engine_unavailable": 503,
    "replication_syncing": 503,
}

TITLES: dict[str, str] = {
    "validation_error": "Validation error",
    "invalid_credentials": "Invalid credentials",
    "totp_required": "One-time code required",
    "second_factor_required": "Second factor required",
    "unauthenticated": "Authentication required",
    "forbidden": "Forbidden",
    "csrf_failed": "CSRF check failed",
    "not_found": "Not found",
    "module_disabled": "Module disabled",
    "method_not_allowed": "Method not allowed",
    "conflict": "Conflict",
    "config_divergence": "Configuration file differs from the running configuration",
    "precondition_failed": "Precondition failed",
    "preflight_failed": "A target node cannot apply the plan",
    "plan_state": "Plan is not in the expected state",
    "zone_without_records": "Zone holds no records",
    "zone_too_large": "Zone too large to read here",
    "plan_expired": "Plan expired",
    "engine_validation_failed": "Engine validation failed",
    "release_invalid": "Release refused",
    "confirmation_required": "Confirmation required",
    "rate_limited": "Too many requests",
    "internal_error": "Internal error",
    "not_supported": "Not supported by the engine",
    "not_implemented": "Not implemented",
    "engine_unavailable": "Engine unavailable",
    "replication_syncing": "Replication in progress",
}


def title_message(code: str) -> dict[str, Any]:
    """Translatable form of the problem title (domain.messages key problem.<code>)."""
    return messages.msg(f"problem.{code}" if code in TITLES else "problem.internal_error")


def unexpected_detail() -> dict[str, Any]:
    return messages.msg("problem.detail.unexpected")


class ApiError(Exception):
    def __init__(
        self,
        code: str,
        detail: str | None = None,
        *,
        status: int | None = None,
        errors: list[dict[str, Any]] | None = None,
        headers: dict[str, str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        if code not in STATUS_BY_CODE:
            raise ValueError(f"unknown error code {code}")
        super().__init__(detail or TITLES[code])
        self.code = code
        self.status = status or STATUS_BY_CODE[code]
        self.detail = detail
        self.errors = errors or []
        self.headers = headers or {}
        # RFC 7807 extension members, for instance the failed plan of a 422.
        self.extra = extra or {}

    def to_problem(self, instance: str | None = None) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "type": PROBLEM_TYPE + self.code,
            "title": TITLES[self.code],
            "status": self.status,
            "detail": self.detail or TITLES[self.code],
            "instance": instance or request.path,
            "code": self.code,
            "title_message": title_message(self.code),
        }
        if self.detail is None:
            doc["detail_message"] = doc["title_message"]
        if self.errors:
            doc["errors"] = self.errors
        for key, value in self.extra.items():
            doc.setdefault(key, value)
        return doc


def translate(exc: BaseException) -> ApiError | None:
    """Map service, plan and connector exceptions to problem documents; None for unknown ones."""
    from pelagos.services.errors import (
        ConnectorDenied,
        ConnectorError,
        ConnectorTimeout,
        ConnectorUnavailable,
        NotSupported,
        PreconditionFailed,
        ServiceError,
        ValidationFailed,
        ZoneTooLarge,
        ZoneWithoutRecords,
    )
    from pelagos.services.plan_service import PlanError

    if isinstance(exc, ApiError):
        return exc
    if isinstance(exc, ServiceError | PlanError):
        code = exc.code if exc.code in STATUS_BY_CODE else "internal_error"
        return ApiError(
            code, exc.detail, errors=getattr(exc, "errors", None), extra=getattr(exc, "extra", None)
        )
    if isinstance(exc, ValidationFailed):
        r = exc.result
        return ApiError(
            "engine_validation_failed",
            f"{r.tool} rejected the change",
            errors=[{"field": r.tool, "message": r.output, "node_id": r.node_id}],
        )
    if isinstance(exc, PreconditionFailed):
        return ApiError("precondition_failed", str(exc))
    if isinstance(exc, ZoneWithoutRecords):
        return ApiError(
            "zone_without_records",
            str(exc),
            extra={
                "zone": exc.zone,
                "view": exc.view,
                "kind": exc.kind,
                "detail_message": messages.msg(
                    "problem.detail.zone_without_records", zone=exc.zone, kind=exc.kind
                ),
            },
        )
    if isinstance(exc, ZoneTooLarge):
        return ApiError("zone_too_large", str(exc), extra=zone_too_large_extra(exc))
    if isinstance(exc, NotSupported):
        return ApiError("not_supported", str(exc))
    if isinstance(exc, ConnectorUnavailable | ConnectorTimeout | ConnectorDenied):
        return ApiError("engine_unavailable", str(exc))
    if isinstance(exc, ConnectorError):
        return ApiError("conflict", str(exc))
    if isinstance(exc, NotImplementedError):
        owner = str(exc) or "a later work package"
        return ApiError("not_implemented", f"This feature is specified but not built yet (owner: {owner})")
    if isinstance(exc, PermissionError):
        return ApiError("forbidden", str(exc))
    return None


def zone_too_large_extra(exc: Any) -> dict[str, Any]:
    return {
        "zone": exc.zone,
        "view": exc.view,
        "size": exc.size,
        "limit": exc.limit,
        "detail_message": messages.msg(
            "problem.detail.zone_too_large", zone=exc.zone, size=str(exc.size), limit=str(exc.limit)
        ),
    }


def not_implemented(package: str = "") -> ApiError:
    detail = "This endpoint is specified but not built yet"
    if package:
        detail += f" (owner: {package})"
    return ApiError("not_implemented", detail)


def problem_response(err: ApiError) -> Response:
    resp = jsonify(err.to_problem())
    resp.status_code = err.status
    resp.mimetype = PROBLEM_MIME
    for k, v in err.headers.items():
        resp.headers[k] = v
    return resp
