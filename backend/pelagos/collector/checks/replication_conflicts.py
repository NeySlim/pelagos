# SPDX-License-Identifier: Apache-2.0
"""F0-REPL: replication_conflict alerts from this node's replication.conflict audit entries (section 13).

One alert per entry path seen in the last 24 hours; it resolves once its last entry is older.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any

from pelagos.domain import Alert, AlertKind, Severity, messages

ACTION = "replication.conflict"
WINDOW = timedelta(hours=24)
MAX_ENTRIES = 5000


def _who(by: Any) -> str:
    m = re.match(r"user:(.+)@node:", by if isinstance(by, str) else "")
    return m.group(1) if m else "system"


def _node(side: dict[str, Any], names: dict[str, str]) -> str:
    node = str(side.get("stamp", "")).partition("@")[2]
    return names.get(node, node)


def observe(audit_log: Any, node_id: str, now: datetime, names: dict[str, str] | None = None) -> list[Alert]:
    """Alerts of this node's conflict entries; `names` turns node ids into node names."""
    names = names or {}
    entries, _total = audit_log.query(
        action=ACTION, node_id=node_id, since=now - WINDOW, page=1, per_page=MAX_ENTRIES
    )
    by_path: dict[str, list[Any]] = {}
    for entry in entries:
        if entry.action != ACTION or entry.node_id != node_id:
            continue
        path = str((entry.request or {}).get("path") or entry.target.removeprefix("config:"))
        by_path.setdefault(path, []).append(entry)
    alerts = []
    for path, items in sorted(by_path.items()):
        last = max(items, key=lambda e: (e.ts, e.id))
        request = dict(last.request or {})  # masked when written (core.replication.conflict_entry)
        local, remote = request.get("local") or {}, request.get("remote") or {}
        alerts.append(
            Alert(
                kind=AlertKind.REPLICATION_CONFLICT,
                severity=Severity.INFO,
                node_id=node_id,
                subject=path,
                **messages.fields(
                    "title",
                    messages.msg(
                        "alert.replication_conflict",
                        path=path,
                        local_user=_who(local.get("by")),
                        local_node=_node(local, names),
                        remote_user=_who(remote.get("by")),
                        remote_node=_node(remote, names),
                    ),
                ),
                details={**request, "count": len(items)},
            )
        )
    return alerts
