# SPDX-License-Identifier: Apache-2.0
"""Admin exceptions to consistency checks: "Ignore: admin's choice", kept in cluster.toml.

An exception is a record of `[[exceptions]]` keyed by (check kind, stable object key), with its
author, date and a mandatory comment; it replicates like users and roles. Checks read it through
`services.consistency.excepted_for` and raise nothing for that object while it exists.
"""

from __future__ import annotations

from typing import Any

from pelagos.core.context import NodeContext
from pelagos.domain import (
    EXCEPTABLE_KINDS,
    INCONSISTENCY_KINDS,
    AuditEntry,
    AuditResult,
    new_id,
    to_rfc3339,
    utcnow,
)
from pelagos.installer.security_audit import EXCEPTION_KIND as FINDING_EXCEPTION_KIND
from pelagos.services.errors import Conflict, NotFound, ValidationError, field_error

MAX_COMMENT = 1000
MAX_KEY = 512
MAX_SUMMARY = 300
# Consistency kinds, the health checks and the security audit findings an admin may keep as they
# are; never an outage.
KINDS = frozenset(k.value for k in INCONSISTENCY_KINDS | EXCEPTABLE_KINDS) | {FINDING_EXCEPTION_KIND}


class ExceptionsService:
    def __init__(self, ctx: NodeContext) -> None:
        self.ctx = ctx

    def list(self, kind: str | None = None) -> list[dict[str, Any]]:
        items = [dict(e) for e in self.ctx.cluster().exceptions if e.get("kind") and e.get("key") is not None]
        if kind:
            items = [e for e in items if e["kind"] == kind]
        return sorted(items, key=lambda e: (str(e.get("created_at", "")), e["id"]), reverse=True)

    def create(self, body: dict[str, Any], actor: str, client_ip: str | None) -> dict[str, Any]:
        kind = str(body.get("kind") or "").strip()
        key = body.get("key")
        comment = str(body.get("comment") or "").strip()
        summary = str(body.get("summary") or "").strip()
        errors: list[dict[str, str]] = []
        if kind not in KINDS:
            errors.append(field_error("kind", "an alert kind that accepts exceptions"))
        if not isinstance(key, str) or not key.strip() or len(key) > MAX_KEY:
            errors.append(field_error("key", f"a non-empty string of at most {MAX_KEY} characters"))
        if not comment:
            errors.append(field_error("comment", "required: say why the object is left as it is"))
        elif len(comment) > MAX_COMMENT:
            errors.append(field_error("comment", f"at most {MAX_COMMENT} characters"))
        if len(summary) > MAX_SUMMARY:
            errors.append(field_error("summary", f"at most {MAX_SUMMARY} characters"))
        if errors:
            raise ValidationError("invalid exception", errors)
        key = str(key).strip()
        if _same(self.ctx.cluster().exceptions, kind, key):
            raise Conflict(f"{kind} {key} is already an exception")
        record = {
            "id": new_id(),
            "kind": kind,
            "key": key,
            "comment": comment,
            "created_by": actor,
            "created_at": to_rfc3339(utcnow()),
            "node_id": self.ctx.node.id,
        }
        if summary:
            record["summary"] = summary

        # Checked again under the config lock: two concurrent requests never both write it.
        def add(c: Any) -> None:
            if _same(c.exceptions, kind, key):
                raise Conflict(f"{kind} {key} is already an exception")
            c.exceptions.append(dict(record))

        self.ctx.config_store.update_cluster(add, updated_by=self._by(actor))
        self._audit("alert.exception.add", record, actor, client_ip, comment)
        self._recheck()
        return record

    def revoke(self, exception_id: str, actor: str, client_ip: str | None) -> None:
        found = next((e for e in self.ctx.cluster().exceptions if e.get("id") == exception_id), None)
        if found is None:
            raise NotFound(f"exception {exception_id}")

        # Every record of that (kind, key) goes: two nodes may each have written one.
        def drop(c: Any) -> None:
            c.exceptions[:] = [
                e
                for e in c.exceptions
                if e.get("id") != exception_id and not _same([e], found.get("kind"), found.get("key"))
            ]

        self.ctx.config_store.update_cluster(drop, updated_by=self._by(actor))
        self._audit("alert.exception.revoke", dict(found), actor, client_ip, None)
        self._recheck()

    def _by(self, user: str) -> str:
        return f"user:{user}@node:{self.ctx.node.id}"

    def _audit(
        self, action: str, record: dict[str, Any], actor: str, client_ip: str | None, message: str | None
    ) -> None:
        self.ctx.audit_log.append(
            AuditEntry(
                node_id=self.ctx.node.id,
                user=actor,
                action=action,
                target=f"exception:{record['kind']}:{record['key']}",
                request={k: v for k, v in record.items() if k != "node_id"},
                response={"ok": True},
                result=AuditResult.OK,
                message=message,
                client_ip=client_ip,
            )
        )

    def _recheck(self) -> None:
        """The collector's next consistency pass settles the alerts; ask for it now."""
        from pelagos.collector.events import send_signal

        send_signal(self.ctx.paths.collector_sock, "consistency")


def _same(entries: Any, kind: Any, key: Any) -> bool:
    return any(e.get("kind") == kind and e.get("key") == key for e in entries)
