# SPDX-License-Identifier: Apache-2.0
"""Advanced editor support: the BIND statement tree with provenance and the write pipeline history."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pelagos.core.context import NodeContext
from pelagos.domain import BindConfigTree, ConfigEntry, Engine, Family
from pelagos.services.dns_service import DnsService
from pelagos.services.errors import NotFound, ValidationError, field_error

MAX_FILE_BYTES = 2 * 1024 * 1024


class AdvancedService:
    def __init__(self, ctx: NodeContext, dns: DnsService | None) -> None:
        self.ctx = ctx
        self.dns = dns

    # Grammar and schema (provided by WP-BIND and WP-KEA) -----------------

    def bind_grammar(self) -> dict[str, Any]:
        from pelagos.connectors.bind import namedconf

        return namedconf.grammar()

    def kea_schema(self, family: str, dhcp: Any = None) -> dict[str, Any]:
        """`pelagos.connectors.kea.schema.describe(family, version)` (contracts-changes.md)."""
        import importlib

        try:
            module = importlib.import_module("pelagos.connectors.kea.schema")
        except ImportError:
            raise NotImplementedError("WP-KEA") from None
        version = None
        if dhcp is not None and dhcp.local is not None:
            try:
                version = dhcp.local.capabilities().version
            except Exception:
                version = None
        return module.describe(Family(family), version)

    # BIND tree ----------------------------------------------------------

    def bind_tree(self, node_id: str | None) -> dict[str, Any]:
        if self.dns is None:
            raise NotFound("BIND is not configured")
        tree = self.dns._config(node_id)
        return {"node_id": tree.node_id, "user_conf": tree.user_conf, "files": bind_files(tree)}

    # History ------------------------------------------------------------

    def history(self, engine: str | None, node_id: str | None) -> list[dict[str, Any]]:
        if node_id not in (None, self.ctx.node.id):
            raise ValidationError(
                "history is local to each node; node_id must be this node",
                [field_error("node_id", "not this node")],
            )
        if engine is not None and engine not in {e.value for e in Engine}:
            raise ValidationError(f"unknown engine {engine}", [field_error("engine", "invalid")])
        root = self.ctx.paths.backups_dir
        items: list[dict[str, Any]] = []
        if not root.exists():
            return items
        for engine_dir in sorted(root.iterdir()):
            if not engine_dir.is_dir() or (engine is not None and engine_dir.name != engine):
                continue
            for bdir in sorted(engine_dir.iterdir(), reverse=True):
                manifest = bdir / "manifest.json"
                if not manifest.is_file():
                    continue
                item = self._entry(engine_dir.name, bdir, manifest)
                if item is not None:
                    items.append(item)
        items.sort(key=lambda i: i["ts"], reverse=True)
        return items

    def _entry(self, engine: str, bdir: Path, manifest: Path) -> dict[str, Any] | None:
        try:
            data = json.loads(manifest.read_text())
        except (OSError, ValueError):
            return None
        stamp, _, label = bdir.name.partition("-")
        return {
            "id": f"{engine}/{bdir.name}",
            "engine": engine,
            "node_id": self.ctx.node.id,
            "ts": _stamp_to_rfc3339(stamp),
            "plan_id": label if len(label) == 26 and label.isalnum() else None,
            "label": data.get("label") or label,
            "files": [f["path"] for f in data.get("files", [])],
        }

    def history_entry(self, history_id: str) -> dict[str, Any]:
        engine, _, name = history_id.partition("/")
        if not engine or not name or "/" in name or ".." in name:
            raise NotFound(f"history entry {history_id}")
        bdir = self.ctx.paths.backups_dir / engine / name
        manifest = bdir / "manifest.json"
        if not manifest.is_file():
            raise NotFound(f"history entry {history_id}")
        data = json.loads(manifest.read_text())
        files: dict[str, str | None] = {}
        for entry in data.get("files", []):
            if entry.get("absent"):
                files[entry["path"]] = None
                continue
            bak = bdir / f"{entry['index']}.bak"
            try:
                raw = bak.read_bytes()[:MAX_FILE_BYTES]
                files[entry["path"]] = raw.decode("utf-8", errors="replace")
            except OSError:
                files[entry["path"]] = None
        return {"id": history_id, "manifest": data, "files": files}


def bind_files(tree: BindConfigTree) -> list[dict[str, Any]]:
    """Group every statement by the file it came from; managed = under the Pelagos include dir."""
    include_dir = str(tree.pelagos.get("include_dir") or "")
    files: dict[str, dict[str, Any]] = {}

    def file_for(path: str | None) -> dict[str, Any]:
        key = path or tree.user_conf
        if key not in files:
            files[key] = {
                "path": key,
                "managed": bool(include_dir) and key.startswith(include_dir),
                "statements": [],
            }
        return files[key]

    for path in [tree.user_conf, *tree.includes]:
        file_for(path)

    def add(kind: str, entry: ConfigEntry) -> None:
        file_for(entry.path)["statements"].append(
            {
                "kind": kind,
                "name": entry.name,
                "value": entry.value,
                "line": entry.line,
                "managed": entry.managed,
            }
        )

    for entry in tree.options:
        add("options", entry)
    for entry in tree.keys:
        add("key", entry)
    for entry in tree.acls:
        add("acl", entry)
    for entry in tree.controls:
        add("controls", entry)
    for entry in tree.statistics_channels:
        add("statistics-channels", entry)
    if tree.logging:
        file_for(None)["statements"].append(
            {"kind": "logging", "name": "logging", "value": tree.logging, "line": None, "managed": False}
        )
    for zone in tree.zones:
        file_for(zone.config_path)["statements"].append(
            {
                "kind": "zone",
                "name": zone.name,
                "value": zone.to_dict(),
                "line": None,
                "managed": zone.source.value != "user_conf",
                "view": zone.view,
            }
        )
    return list(files.values())


def _stamp_to_rfc3339(stamp: str) -> str:
    # Backup directories are named <YYYYmmddTHHMMSSffffffZ>-<label> by the write pipeline.
    if len(stamp) >= 15 and stamp[8] == "T":
        return f"{stamp[0:4]}-{stamp[4:6]}-{stamp[6:8]}T{stamp[9:11]}:{stamp[11:13]}:{stamp[13:15]}Z"
    return stamp
