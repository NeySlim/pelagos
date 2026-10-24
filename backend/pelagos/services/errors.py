# SPDX-License-Identifier: Apache-2.0
"""Service-level errors, mapped to problem documents by the API (section 19 codes)."""

from __future__ import annotations

from typing import Any

# Re-exported so the API maps connector failures without importing connectors (section 2 rules).
from pelagos.connectors.base import (
    ConnectorDenied,
    ConnectorError,
    ConnectorTimeout,
    ConnectorUnavailable,
    NotSupported,
    PreconditionFailed,
    ValidationFailed,
)

__all__ = [
    "Conflict",
    "ConnectorDenied",
    "ConnectorError",
    "ConnectorTimeout",
    "ConnectorUnavailable",
    "EngineUnavailable",
    "NotFound",
    "NotSupported",
    "PreconditionFailed",
    "ServiceError",
    "ValidationError",
    "ValidationFailed",
    "field_error",
]


class ServiceError(Exception):
    """code is a section 19 error code; errors are the problem document's `errors` list."""

    def __init__(
        self,
        code: str,
        detail: str,
        errors: list[dict[str, Any]] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.errors = errors or []
        # RFC 7807 extension members of the problem document.
        self.extra = extra or {}


class ValidationError(ServiceError):
    def __init__(self, detail: str, errors: list[dict[str, Any]] | None = None) -> None:
        super().__init__("validation_error", detail, errors)


class NotFound(ServiceError):
    def __init__(self, detail: str) -> None:
        super().__init__("not_found", detail)


class Conflict(ServiceError):
    def __init__(self, detail: str) -> None:
        super().__init__("conflict", detail)


class EngineUnavailable(ServiceError):
    def __init__(self, detail: str) -> None:
        super().__init__("engine_unavailable", detail)


def field_error(field: str, message: str) -> dict[str, str]:
    return {"field": field, "message": message}
