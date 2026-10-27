# SPDX-License-Identifier: Apache-2.0
"""Kea configuration file versus running configuration, as the DHCP service sees it (section 9).

While a `config_divergence` alert with subject `<engine>:config-file` is open for a target node,
Kea writes through Pelagos answer 409 `config_divergence` until the user adopts one side. On this
node the comparison is re-run live, so a file fixed by hand unblocks before the collector's next poll.
"""

from __future__ import annotations

import logging
from typing import Any

from pelagos.connectors.kea.configfile import FileDiverged
from pelagos.domain import Alert, AlertKind, AlertState, Engine
from pelagos.services.errors import ConnectorError, ServiceError

log = logging.getLogger(__name__)

DIVERGENCE = "config_divergence"


def subject(engine: Engine) -> str:
    return f"{engine.value}:config-file"


def open_file_alerts(alerts: Any, engine: Engine, node_ids: list[str] | None = None) -> list[Alert]:
    """Open or acknowledged file alerts of `engine`, for `node_ids` when given."""
    if alerts is None:
        return []
    try:
        rows = alerts.open_by_subject(AlertKind.CONFIG_DIVERGENCE.value, subject(engine))
    except Exception:
        log.warning("alert table not readable; file divergence not checked", exc_info=True)
        return []
    return [
        a for a in rows if a.state is not AlertState.RESOLVED and (node_ids is None or a.node_id in node_ids)
    ]


def live_differences(backend: Any) -> list[str] | None:
    """Differences between this node's file and its running config; None when they cannot be read."""
    file = getattr(backend, "file", None)
    if file is None:
        return None
    try:
        doc = file.document()
        return file.differences(backend.config_get(), doc)
    except ConnectorError:
        return None


def diverged_error(engine: Engine, items: list[dict[str, Any]]) -> ServiceError:
    nodes = ", ".join(sorted({str(i.get("node_name") or i.get("node_id")) for i in items}))
    paths = ", ".join(sorted({str(i.get("path")) for i in items if i.get("path")}))
    detail = (
        f"the {engine.value} configuration file ({paths or 'on disk'}) differs from the running "
        f"configuration on {nodes}: adopt the file or the running configuration first"
    )
    return ServiceError(DIVERGENCE, detail, extra={"engine": engine.value, "divergences": items})


def check(
    alerts: Any,
    engine: Engine,
    node_ids: list[str],
    self_id: str,
    local: Any,
    names: dict[str, str] | None = None,
    peers: Any = None,
) -> None:
    """Raises 409 config_divergence when a target node has an open file alert for `engine`, or, for
    a peer target, when the peer's own comparison (snapshot `file`) says its file diverges."""
    names = names or {}
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for alert in open_file_alerts(alerts, engine, node_ids):
        differences = list(alert.details.get("differences") or [])
        if alert.node_id == self_id and local is not None:
            live = live_differences(local)
            if live is not None and not live:
                continue  # fixed since the collector's last poll
            differences = live or differences
        seen.add(alert.node_id or "")
        items.append(
            {
                "node_id": alert.node_id,
                "node_name": names.get(alert.node_id or "", alert.node_id),
                "alert_id": alert.id,
                "path": alert.details.get("path"),
                "differences": differences[:20],
            }
        )
    for node_id in node_ids:
        if node_id == self_id or node_id in seen or peers is None:
            continue
        peer = peers.peer(node_id)
        snap = peers.snapshot(peer, engine, "file") if peer is not None else None
        item = (snap or {}).get("file") if not (snap or {}).get("error") else None
        if isinstance(item, dict) and item.get("diverged"):
            items.append(
                {
                    "node_id": node_id,
                    "node_name": names.get(node_id, node_id),
                    "alert_id": item.get("alert_id"),
                    "path": item.get("path"),
                    "differences": list(item.get("differences") or [])[:20],
                }
            )
    if items:
        raise diverged_error(engine, items)


def from_connector(engine: Engine, exc: FileDiverged, node_id: str) -> ServiceError:
    return diverged_error(
        engine,
        [{"node_id": node_id, "path": str(exc.path), "differences": [d for d in exc.differences[:20]]}],
    )


def status(alerts: Any, engine: Engine, self_id: str, local: Any) -> list[dict[str, Any]]:
    """Per node: path, diverged, differences and the alert id; this node is compared live."""
    out: list[dict[str, Any]] = []
    by_node = {a.node_id: a for a in open_file_alerts(alerts, engine)}
    if local is not None and getattr(local, "file", None) is not None:
        file = local.file
        item: dict[str, Any] = {"node_id": self_id, "path": str(file.path), "readable": False}
        try:
            doc = file.document()
            item["readable"] = doc is not None
            if doc is not None:
                item["files"] = [str(p) for p in file.files(doc)]
                item["syntax_warnings"] = doc.syntax_warnings()
                item["includes"] = doc.has_includes
                diffs = file.differences(local.config_get(), doc)
                item["differences"] = diffs[:50]
                item["count"] = len(diffs)
                item["diverged"] = bool(diffs)
        except ConnectorError as exc:
            item["error"] = str(exc)
        alert = by_node.pop(self_id, None)
        item["alert_id"] = alert.id if alert else None
        item.setdefault("diverged", False)
        item.setdefault("syntax_warnings", [])
        out.append(item)
    for node_id, alert in by_node.items():
        out.append(
            {
                "node_id": node_id,
                "path": alert.details.get("path"),
                "diverged": True,
                "differences": list(alert.details.get("differences") or []),
                "count": alert.details.get("count"),
                "alert_id": alert.id,
            }
        )
    return out
