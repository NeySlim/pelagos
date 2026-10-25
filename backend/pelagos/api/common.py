# SPDX-License-Identifier: Apache-2.0
"""Helpers shared by the namespaces: JSON bodies, query parsing, pagination, plan answers (section 19)."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from flask import request

from pelagos.api.errors import ApiError
from pelagos.core import plan_secrets
from pelagos.domain import Model, Plan, PlanState, from_rfc3339, utcnow
from pelagos.services.masking import MASK as MASK
from pelagos.services.masking import SECRET_KEYS as SECRET_KEYS
from pelagos.services.masking import masked as masked
from pelagos.services.masking import masked_text as masked_text

MAX_PER_PAGE = 500
DEFAULT_PER_PAGE = 50


def json_body(required: bool = True) -> dict[str, Any]:
    """The request body as an object; 400 validation_error otherwise."""
    if not request.data:
        if required:
            raise ApiError("validation_error", "a JSON object body is required")
        return {}
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError("validation_error", "the body must be a JSON object")
    return data


def arg(name: str) -> str | None:
    value = request.args.get(name)
    return value if value not in (None, "") else None


def int_arg(name: str, minimum: int | None = None) -> int | None:
    raw = arg(name)
    if raw is None:
        return None
    try:
        value = int(raw)
    except ValueError:
        raise ApiError(
            "validation_error", f"{name} must be an integer", errors=[{"field": name, "message": "integer"}]
        ) from None
    if minimum is not None and value < minimum:
        raise ApiError("validation_error", f"{name} must be >= {minimum}")
    return value


def bool_arg(name: str) -> bool:
    raw = (arg(name) or "").lower()
    if raw in ("", "0", "false", "no", "off"):
        return False
    if raw in ("1", "true", "yes", "on"):
        return True
    raise ApiError("validation_error", f"{name} must be a boolean")


def time_arg(name: str, default: datetime | None = None) -> datetime | None:
    raw = arg(name)
    if raw is None:
        return default
    try:
        return from_rfc3339(int(raw) if raw.lstrip("-").isdigit() else raw)
    except (ValueError, OverflowError, OSError):
        raise ApiError(
            "validation_error",
            f"{name} must be RFC 3339 or Unix seconds",
            errors=[{"field": name, "message": "bad time"}],
        ) from None


def time_range(default_hours: int = 24) -> tuple[datetime, datetime]:
    until = time_arg("to", utcnow())
    since = time_arg("from", until - timedelta(hours=default_hours))
    assert since is not None and until is not None
    if since > until:
        raise ApiError("validation_error", "from must not be after to")
    return since, until


def pagination() -> tuple[int, int]:
    page = int_arg("page")
    per_page = int_arg("per_page")
    page = 1 if page is None else page
    per_page = DEFAULT_PER_PAGE if per_page is None else per_page
    if page < 1:
        raise ApiError("validation_error", "page is 1-based", errors=[{"field": "page", "message": ">= 1"}])
    if per_page < 1 or per_page > MAX_PER_PAGE:
        raise ApiError(
            "validation_error",
            f"per_page must be between 1 and {MAX_PER_PAGE}",
            errors=[{"field": "per_page", "message": f"1..{MAX_PER_PAGE}"}],
        )
    return page, per_page


def page_of(items: list[Any], meta: dict[str, Any] | None = None) -> dict[str, Any]:
    """Slice a full list per the page/per_page query and serialize it (section 19 shape)."""
    page, per_page = pagination()
    start = (page - 1) * per_page
    return paged([_dump(i) for i in items[start : start + per_page]], page, per_page, len(items), meta)


def paged(
    items: list[Any], page: int, per_page: int, total: int, meta: dict[str, Any] | None = None
) -> dict[str, Any]:
    return {
        "items": [_dump(i) for i in items],
        "page": page,
        "per_page": per_page,
        "total": total,
        "meta": meta or {},
    }


def items(rows: list[Any], **extra: Any) -> dict[str, Any]:
    return {"items": [_dump(r) for r in rows], **extra}


def _dump(value: Any) -> Any:
    return value.to_dict() if isinstance(value, Model) else value


def plan_dict(plan: Plan) -> dict[str, Any]:
    """A plan as the API shows it: key material, given or generated, never leaves the node."""
    data = plan.to_dict()
    data["changes"] = plan_secrets.without_sealed(data.get("changes") or [])
    data = masked(data)
    data["diff"] = masked_text(data.get("diff") or "")
    for v in data.get("validations", []):
        v["output"] = masked_text(v.get("output") or "")
    return data


def plan_answer(plan: Plan) -> tuple[dict[str, Any], int]:
    """200 with the plan, or 422 engine_validation_failed with the tool output and the plan attached."""
    if plan.state is PlanState.FAILED:
        failed = [v for v in plan.validations if not v.ok]
        raise ApiError(
            "engine_validation_failed",
            plan.error or "the engine rejected the change",
            errors=[{"field": v.tool, "message": v.output, "node_id": v.node_id} for v in failed]
            or [{"field": "plan", "message": plan.error or "validation failed"}],
            extra={"plan": plan_dict(plan)},
        )
    return plan_dict(plan), 200
