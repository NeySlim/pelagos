# SPDX-License-Identifier: Apache-2.0
"""The Pelagos include directory: keys.conf, acls.conf, zones.conf, options.conf, views/<name>.conf.

Every file starts with `# pelagos:managed v1`; a `# pelagos:note {json}` comment on the line
before a statement carries user notes. Statements are written in the canonical style and
edited in place so that hand edits elsewhere in the file survive.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pelagos.connectors.bind.namedconf.resolve import (
    MANAGED_HEADER,
    NOTE_PREFIX,
    ConfigFiles,
    note_before,
    parse,
    raw_includes,
    same_path,
    zone_from_node,
)
from pelagos.connectors.bind.namedconf.tree import (
    ConfigDocument,
    Node,
    format_statement,
    quote,
    word_or_quoted,
)
from pelagos.domain.dns import Zone, ZoneKind, normalize_name

DEFAULT_VIEW = "_default"
PRIMARY_LIST_KINDS = (ZoneKind.SECONDARY, ZoneKind.STUB, ZoneKind.MIRROR, ZoneKind.REDIRECT)


@dataclass(slots=True)
class KeySpec:
    name: str
    algorithm: str = "hmac-sha256"
    secret: str = ""
    notes: str | None = None

    def masked(self) -> dict[str, Any]:
        return {"name": self.name, "algorithm": self.algorithm, "secret": "****", "notes": self.notes}


@dataclass(slots=True)
class AclSpec:
    name: str
    elements: list[str] = field(default_factory=list)
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "elements": list(self.elements), "notes": self.notes}


def note_comment(notes: str | None, extra: dict[str, Any] | None = None) -> str | None:
    data: dict[str, Any] = dict(extra or {})
    if notes:
        data["notes"] = notes
    return NOTE_PREFIX + json.dumps(data, ensure_ascii=False, sort_keys=True) if data else None


class ManagedFiles:
    """Paths and renderers for the include directory; no I/O except reading existing files."""

    def __init__(self, include_dir: Path) -> None:
        self.include_dir = Path(include_dir)

    @property
    def pelagos_conf(self) -> Path:
        return self.include_dir / "pelagos.conf"

    @property
    def keys_conf(self) -> Path:
        return self.include_dir / "keys.conf"

    @property
    def acls_conf(self) -> Path:
        return self.include_dir / "acls.conf"

    @property
    def zones_conf(self) -> Path:
        return self.include_dir / "zones.conf"

    @property
    def options_conf(self) -> Path:
        return self.include_dir / "options.conf"

    @property
    def policies_conf(self) -> Path:
        """dnssec-policy statements; included from pelagos.conf once the first policy is written."""
        return self.include_dir / "policies.conf"

    @property
    def views_dir(self) -> Path:
        return self.include_dir / "views"

    def view_conf(self, view: str) -> Path:
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in view)
        return self.views_dir / f"{safe}.conf"

    def zones_file(self, view: str | None) -> Path:
        return self.zones_conf if not view or view == DEFAULT_VIEW else self.view_conf(view)

    def resolve(self, name: str) -> Path:
        """A managed file by basename or relative path ("zones.conf", "views/internal.conf")."""
        candidate = (self.include_dir / name).resolve()
        if candidate.parent not in (self.include_dir.resolve(), self.views_dir.resolve()):
            raise ValueError(f"{name} is not a managed file")
        if candidate.suffix != ".conf":
            raise ValueError(f"{name} is not a managed file")
        return candidate

    # Documents ----------------------------------------------------------------

    def read_text(self, path: Path) -> str:
        return path.read_text() if path.exists() else ""

    def document(self, path: Path, text: str | None = None) -> ConfigDocument:
        """Parse a managed file, or start a new one with the header when it does not exist."""
        if text is None:
            text = self.read_text(path)
        if not text:
            text = MANAGED_HEADER + "\n"
        return parse(text, str(path))

    def render_pelagos_conf(self) -> str:
        lines = [MANAGED_HEADER, "# Included once from the top level of named.conf; do not edit by hand."]
        for p in (self.keys_conf, self.acls_conf, self.zones_conf):
            lines.append(f"include {quote(str(p))};")
        return "\n".join(lines) + "\n"

    def bootstrap_texts(self, views: list[str] | None = None, with_zones: bool = True) -> dict[Path, str]:
        """Content of every managed file that must exist for the include lines to resolve."""
        header = MANAGED_HEADER + "\n"
        out = {
            self.pelagos_conf: self.render_pelagos_conf(),
            self.keys_conf: header,
            self.acls_conf: header,
            self.zones_conf: header,
            self.options_conf: header,
        }
        for view in views or []:
            out[self.view_conf(view)] = header
        if not with_zones:
            out.pop(self.zones_conf)
        return out

    # Statement rendering -------------------------------------------------------

    @staticmethod
    def key_statement(spec: KeySpec) -> str:
        return format_statement(
            f"key {quote(spec.name)} {{ algorithm {spec.algorithm}; secret {quote(spec.secret)}; }};"
        )

    @staticmethod
    def acl_statement(spec: AclSpec) -> str:
        body = " ".join(f"{e};" for e in spec.elements) or "none;"
        return format_statement(f"acl {quote(spec.name)} {{ {body} }};")

    @staticmethod
    def option_statement(name: str, value: str) -> str:
        value = value.strip().rstrip(";").strip()
        return format_statement(f"{name} {value};" if value else f"{name};")

    @staticmethod
    def zone_statement(zone: Zone) -> str:
        name = zone.name.rstrip(".") or "."
        head = f"zone {quote(name)}" + (
            f" {zone.rclass}" if zone.rclass and zone.rclass.upper() != "IN" else ""
        )
        body: list[str] = [f"type {zone.kind.value};"]
        if zone.file:
            body.append(f"file {quote(zone.file)};")
        if zone.primaries:
            opts = zone.extra.get("primaries-options", "")
            body.append(("primaries " + opts + " " if opts else "primaries ") + _list(zone.primaries) + ";")
        if zone.also_notify:
            body.append("also-notify " + _list(zone.also_notify) + ";")
        if zone.allow_transfer:
            body.append("allow-transfer " + _list(zone.allow_transfer) + ";")
        if zone.update_policy:
            if zone.update_policy == ["local"]:
                body.append("update-policy local;")
            else:
                body.append("update-policy " + _list(zone.update_policy) + ";")
        if zone.allow_update:
            body.append("allow-update " + _list(zone.allow_update) + ";")
        if zone.forwarders:
            body.append("forwarders " + _list(zone.forwarders) + ";")
        if zone.forward:
            body.append(f"forward {zone.forward};")
        if zone.dnssec_policy:
            body.append(f"dnssec-policy {word_or_quoted(zone.dnssec_policy)};")
        if zone.inline_signing is not None:
            body.append(f"inline-signing {'yes' if zone.inline_signing else 'no'};")
        for key, value in zone.extra.items():
            if key in ("primaries-options", "type") or key.endswith("-options"):
                continue
            text = str(value).strip().rstrip(";").strip()
            body.append(f"{key} {text};" if text else f"{key};")
        return format_statement(head + " { " + " ".join(body) + " };")

    # In-place editing -------------------------------------------------------------

    @staticmethod
    def find(doc: ConfigDocument, name: str, arg0: str | None) -> Node | None:
        for node in doc.statements():
            if node.name != name:
                continue
            if arg0 is None:
                return node
            first = node.args[0] if node.args else ""
            if first == arg0 or (name == "zone" and normalize_name(first) == normalize_name(arg0)):
                return node
        return None

    @staticmethod
    def upsert(doc: ConfigDocument, statement: str, name: str, arg0: str | None, note: str | None) -> Node:
        """Replace the statement `name arg0` or append it; the note comment is kept in sync."""
        existing = ManagedFiles.find(doc, name, arg0)
        if existing is None:
            node = doc.add_statement(statement)
        else:
            _drop_note(doc, existing)
            node = doc.replace_statement(existing, statement)
        if note:
            siblings, index, _ = doc._locate(node)
            siblings[index:index] = [Node("comment", note), Node("space", "\n")]
        return node

    @staticmethod
    def remove(doc: ConfigDocument, name: str, arg0: str | None) -> Node | None:
        existing = ManagedFiles.find(doc, name, arg0)
        if existing is None:
            return None
        _drop_note(doc, existing)
        doc.remove_statement(existing)
        return existing

    @staticmethod
    def note_of(doc: ConfigDocument, node: Node) -> dict[str, Any] | None:
        for i, c in enumerate(doc.root):
            if c is node:
                return note_before(doc.root, i)
        return None

    # Reading ----------------------------------------------------------------------

    def keys(self, doc: ConfigDocument | None = None) -> list[KeySpec]:
        doc = doc or self.document(self.keys_conf)
        out: list[KeySpec] = []
        for node in doc.find("key"):
            alg = node.first("algorithm")
            secret = node.first("secret")
            note = self.note_of(doc, node) or {}
            out.append(
                KeySpec(
                    name=node.args[0] if node.args else "",
                    algorithm=alg.args[0] if alg and alg.args else "",
                    secret=secret.args[0] if secret and secret.args else "",
                    notes=note.get("notes"),
                )
            )
        return out

    def acls(self, doc: ConfigDocument | None = None) -> list[AclSpec]:
        doc = doc or self.document(self.acls_conf)
        return [
            AclSpec(
                name=node.args[0] if node.args else "",
                elements=node.elements(),
                notes=(self.note_of(doc, node) or {}).get("notes"),
            )
            for node in doc.find("acl")
        ]

    def zones(self, view: str = DEFAULT_VIEW, doc: ConfigDocument | None = None) -> list[Zone]:
        path = self.zones_file(view)
        doc = doc or self.document(path)
        return [
            zone_from_node(node, view, str(path), managed=True, note=self.note_of(doc, node))
            for node in doc.find("zone")
        ]

    def options(self, doc: ConfigDocument | None = None) -> dict[str, str]:
        doc = doc or self.document(self.options_conf)
        return {node.name: node.value_text() for node in doc.statements() if node.kind != "include"}


def _list(elements: list[str]) -> str:
    return "{ " + " ".join(e.strip().rstrip(";") + ";" for e in elements) + " }"


def _drop_note(doc: ConfigDocument, node: Node) -> None:
    siblings, index, _ = doc._locate(node)
    i = index - 1
    while i >= 0 and siblings[i].kind == "space":
        i -= 1
    if i >= 0 and siblings[i].kind == "comment" and siblings[i].text.startswith(NOTE_PREFIX):
        # Drop the comment and the whitespace that separated it from the statement.
        del siblings[i:index]
        prev = siblings[i - 1] if i > 0 else None
        if prev is not None and prev.kind == "space" and not prev.text.endswith("\n"):
            prev.text += "\n"
        elif prev is None or prev.kind != "space":
            siblings.insert(i, Node("space", "\n"))


# Include lines in user files -------------------------------------------------------------


def include_statement(path: Path) -> str:
    return f"include {quote(str(path))};"


def plan_include_lines(files: ConfigFiles, managed: ManagedFiles) -> dict[Path, str]:
    """New text of each user file that needs an include line (top level, options, every view)."""
    edits: dict[Path, ConfigDocument] = {}

    def doc_for(path: str) -> ConfigDocument:
        if Path(path) not in edits:
            edits[Path(path)] = parse(files.docs[path].serialize(), path)
        return edits[Path(path)]

    user = str(files.user_conf)
    if user in files.docs and not _has_include(files, managed.pelagos_conf, depth=0):
        doc_for(user).add_statement(include_statement(managed.pelagos_conf))
    options_doc = _file_holding(files, "options")
    if options_doc and not _has_include(files, managed.options_conf, depth=1, parent="options"):
        doc_for(options_doc).add_statement(include_statement(managed.options_conf), context="options")
    for view_name, path in _views(files).items():
        target = managed.view_conf(view_name)
        if not _has_include(files, target, depth=1, parent="view", parent_arg=view_name):
            doc_for(path).add_statement(include_statement(target), context=f"view {quote(view_name)}")
    return {p: d.serialize() for p, d in edits.items()}


def _file_holding(files: ConfigFiles, name: str) -> str | None:
    for path in files.order:
        for node in files.docs[path].statements():
            if node.name == name:
                return path
    return None


def _views(files: ConfigFiles) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in files.order:
        for node in files.docs[path].statements():
            if node.name == "view" and node.args:
                out.setdefault(node.args[0], path)
    return out


def _has_include(
    files: ConfigFiles, target: Path, depth: int, parent: str | None = None, parent_arg: str | None = None
) -> bool:
    for node, _path, parents in raw_includes(files):
        if len(parents) != depth or not node.args:
            continue
        if parent and (parents[-1].name != parent or (parent_arg and parents[-1].args[:1] != [parent_arg])):
            continue
        if any(same_path(found, target) for found in files.include_targets(node)):
            return True
    return False
