# SPDX-License-Identifier: Apache-2.0
"""Audit entries: one JSON line each in the replicated audit log (section 11)."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pelagos.domain.common import Engine, Model, new_id, utcnow


class AuditResult(enum.StrEnum):
    OK = "ok"
    ERROR = "error"
    ROLLED_BACK = "rolled_back"
    DENIED = "denied"


@dataclass(slots=True)
class AuditEntry(Model):
    node_id: str
    action: str
    target: str
    id: str = field(default_factory=new_id)
    ts: datetime = field(default_factory=utcnow)
    user: str | None = None
    engine: Engine | None = None
    plan_id: str | None = None
    request: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] = field(default_factory=dict)
    diff: str | None = None
    result: AuditResult = AuditResult.OK
    message: str | None = None
    client_ip: str | None = None

    def to_dict(self) -> dict[str, Any]:
        # Fixed key order so every node writes identical lines for identical entries.
        data = Model.to_dict(self)
        order = (
            "id", "ts", "node_id", "user", "action", "target", "engine", "plan_id",
            "request", "response", "diff", "result", "message", "client_ip",
        )  # fmt: skip
        return {k: data[k] for k in order}
