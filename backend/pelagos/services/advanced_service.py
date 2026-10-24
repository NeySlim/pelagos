# SPDX-License-Identifier: Apache-2.0
"""Advanced editor support: the BIND statement tree with provenance and the write pipeline history."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pelagos.core.context import NodeContext
from pelagos.domain import Engine
from pelagos.services.dns_service import DnsService
from pelagos.services.errors import ConnectorError, NotFound, ServiceError, ValidationError, field_error

MAX_FILE_BYTES = 2 * 1024 * 1024


class AdvancedService:
    def __init__(self, ctx: NodeContext, dns: DnsService | None) -> None:
        self.ctx = ctx
        self.dns = dns

    # Grammar, statement tree and Kea schema ---------------------------------

    def bind_grammar(self) -> dict[str, Any]:
        from pelagos.connectors.bind import namedconf

        return grammar_document(namedconf.grammar())

    def bind_tree(self, node_id: str | None) -> dict[str, Any]:
        """`BindBackend.config_files_tree()` of the node, statements shaped for the editor."""
        if self.dns is None:
            raise NotFound("BIND is not configured")
        backend, peer = self.dns._read_node(node_id)
        if backend is not None:
            files_tree = getattr(backend, "config_files_tree", None)
            if files_tree is None:
                raise ServiceError("not_supported", "this BIND connector has no statement tree")
            tree, read_on = files_tree(), self.ctx.node.id
        else:
            tree, read_on = self.dns._peer_snapshot(peer, "tree")["tree"], peer.id  # type: ignore[union-attr]
        return tree_document(tree, read_on)

    def kea_schema(self, family: str, dhcp: Any = None, d2: Any = None) -> dict[str, Any]:
        """The connector's config_schema() for the local server's version, else the generic one."""
        if family not in {"v4", "v6", "d2"}:
            raise ValidationError(f"unknown Kea family {family}", [field_error("family", "invalid")])
        backend = d2 if family == "d2" else (dhcp.local if dhcp is not None else None)
        schema = None
        if backend is not None and hasattr(backend, "config_schema"):
            try:
                schema = backend.config_schema()
            except ConnectorError:
                schema = None  # daemon down: fall back to the description without a version
        if schema is None:
            from pelagos.connectors.kea.schema import config_schema

            schema = config_schema(family, None)
        return schema_document(schema)

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
        if engine not in {e.value for e in Engine} or not name or "/" in name or ".." in name:
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


def _stamp_to_rfc3339(stamp: str) -> str:
    # Backup directories are named <YYYYmmddTHHMMSSffffffZ>-<label> by the write pipeline.
    if len(stamp) >= 15 and stamp[8] == "T":
        return f"{stamp[0:4]}-{stamp[4:6]}-{stamp[6:8]}T{stamp[9:11]}:{stamp[11:13]}:{stamp[13:15]}Z"
    return stamp


# Editor shapes (contracts-changes.md, WP-API-AUTH: advanced editor payloads) ----------------------

_CONTEXT_LABELS = {"top": "toplevel"}


def _context_label(name: str) -> str:
    """Grammar context to the editor's label: the block a statement sits in ("zone.primary" is "zone")."""
    if name in _CONTEXT_LABELS:
        return _CONTEXT_LABELS[name]
    if name.startswith("zone.") or name == "zone":
        return "zone"
    return name.rsplit(".", 1)[-1]


def _args_text(entry: dict[str, Any], name: str) -> str:
    grammar = str(entry.get("grammar") or "")
    text = " ".join(grammar.replace("<", " ").replace(">", " ").split())
    if name == "include" and not text:
        return "quoted_string"
    if entry.get("block"):
        return f"{text} {{ ... }}" if text else "block"
    return text


def grammar_document(grammar: dict[str, Any]) -> dict[str, Any]:
    """namedconf.grammar() plus `version` and a flat `statements` list (one row per distinct argument
    grammar, with every context it is allowed in)."""
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for ctx_name, ctx in (grammar.get("contexts") or {}).items():
        label = _context_label(ctx_name)
        for name, entry in (ctx.get("statements") or {}).items():
            args = _args_text(entry, name)
            row = rows.get((name, args))
            if row is None:
                row = rows[(name, args)] = {
                    "name": name,
                    "contexts": [],
                    "args": args,
                    "multiple": bool(entry.get("repeatable", name == "include")),
                    "doc": entry.get("doc_url"),
                    "types": list(entry.get("types") or []),
                    "status": entry.get("status", "current"),
                    "block": entry.get("block"),
                }
            if label not in row["contexts"]:
                row["contexts"].append(label)
    return {
        **grammar,
        "version": grammar.get("bind_version"),
        "statements": sorted(rows.values(), key=lambda r: (r["name"], r["args"])),
    }


def _editor_statement(stmt: dict[str, Any]) -> dict[str, Any]:
    out = dict(stmt)
    children = stmt.get("statements")
    if children is not None:
        args = stmt.get("args") or []
        out["value"] = " ".join(str(a) for a in args) or None
        out["children"] = [_editor_statement(c) for c in children]
    return out


def tree_document(tree: dict[str, Any], node_id: str) -> dict[str, Any]:
    """files_tree() with `value` (block head arguments) and `children` on block statements."""
    return {
        **tree,
        "node_id": node_id,
        "files": [
            {**f, "statements": [_editor_statement(s) for s in f.get("statements") or []]}
            for f in tree.get("files") or []
        ],
    }


def schema_document(schema: dict[str, Any]) -> dict[str, Any]:
    """config_schema() with `keys` as a list of {name, ...}; the mapping stays in `keys_by_name`."""
    keys = schema.get("keys") or {}
    if isinstance(keys, list):
        return schema
    return {
        **schema,
        "keys": [{"name": name, **spec} for name, spec in keys.items()],
        "keys_by_name": keys,
    }
