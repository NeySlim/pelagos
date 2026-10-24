# SPDX-License-Identifier: Apache-2.0
"""Resolve a named.conf tree across includes into BindConfigTree, with provenance per statement."""

from __future__ import annotations

import glob
import json
import os
import subprocess
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pelagos.connectors.bind.namedconf.lexer import ParseError
from pelagos.connectors.bind.namedconf.tree import ConfigDocument, Node, compact_text, parse_nodes, unquote
from pelagos.domain.dns import BindConfigTree, ConfigEntry, Zone, ZoneKind, ZoneSource, normalize_name

MANAGED_HEADER = "# pelagos:managed v1"
NOTE_PREFIX = "# pelagos:note "
MANAGED_FILES = ("pelagos.conf", "keys.conf", "acls.conf", "zones.conf", "options.conf")
VIEWS_DIR = "views"

ZONE_LIST_FIELDS = {
    "primaries": "primaries",
    "masters": "primaries",
    "also-notify": "also_notify",
    "allow-transfer": "allow_transfer",
    "update-policy": "update_policy",
    "allow-update": "allow_update",
    "forwarders": "forwarders",
}


def parse(text: str, path: str | None = None) -> ConfigDocument:
    return ConfigDocument(path=path, root=parse_nodes(text, path))


def serialize(doc: ConfigDocument) -> str:
    return doc.serialize()


@dataclass(slots=True)
class Resolved:
    """One statement with the file it came from and the chain of enclosing statements."""

    node: Node
    path: str
    parents: tuple[Node, ...] = ()


@dataclass(slots=True)
class ConfigFiles:
    """Every file of a configuration, parsed once, in include order; missing includes are recorded."""

    user_conf: Path
    docs: dict[str, ConfigDocument] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, user_conf: Path, reader: Callable[[Path], str] | None = None) -> ConfigFiles:
        files = cls(user_conf=user_conf)
        files._load(user_conf, reader or _read_text)
        return files

    def _load(self, path: Path, reader: Callable[[Path], str]) -> None:
        key = str(path)
        if key in self.docs:
            return
        try:
            doc = parse(reader(path), key)
        except FileNotFoundError:
            self.missing.append(key)
            return
        except ParseError as exc:
            self.errors.append(str(exc))
            return
        self.docs[key] = doc
        self.order.append(key)
        for node in _walk_includes(doc.root):
            for target in resolve_include(node, path):
                self._load(target, reader)

    def expanded(self, children: list[Node], path: str) -> Iterator[tuple[Node, str]]:
        """Children with include statements replaced by the statements of the included files."""
        for node in children:
            if node.kind == "include":
                for target in resolve_include(node, Path(path)):
                    sub = self.docs.get(str(target))
                    if sub is not None:
                        yield from self.expanded(sub.root, str(target))
            elif node.is_statement:
                yield node, path

    def statements(self) -> Iterator[Resolved]:
        """Every statement of the resolved configuration, depth first, with its parents."""
        root = self.docs.get(str(self.user_conf))
        if root is None:
            return
        yield from self._statements(root.root, str(self.user_conf), ())

    def _statements(self, children: list[Node], path: str, parents: tuple[Node, ...]) -> Iterator[Resolved]:
        for node, where in self.expanded(children, path):
            yield Resolved(node, where, parents)
            if node.block is not None:
                yield from self._statements(node.block.children, where, (*parents, node))


def _read_text(path: Path) -> str:
    return path.read_text()


def _walk_includes(children: list[Node]) -> Iterator[Node]:
    for node in children:
        if node.kind == "include":
            yield node
        elif node.is_statement and node.block is not None:
            yield from _walk_includes(node.block.children)


def raw_includes(files: ConfigFiles) -> Iterator[tuple[Node, str, tuple[Node, ...]]]:
    """Include statements of every file with the enclosing statements of that same file."""

    def walk(
        children: list[Node], path: str, parents: tuple[Node, ...]
    ) -> Iterator[tuple[Node, str, tuple[Node, ...]]]:
        for node in children:
            if node.kind == "include":
                yield node, path, parents
            elif node.is_statement and node.block is not None:
                yield from walk(node.block.children, path, (*parents, node))

    for path in files.order:
        yield from walk(files.docs[path].root, path, ())


def resolve_include(node: Node, from_path: Path) -> list[Path]:
    """Paths named by an include statement; relative to the including file, globs expanded (BIND 9.18+)."""
    if not node.args:
        return []
    target = node.args[0]
    base = Path(target) if os.path.isabs(target) else from_path.parent / target
    if any(ch in target for ch in "*?["):
        return [Path(p) for p in sorted(glob.glob(str(base)))]
    return [base]


# Notes --------------------------------------------------------------------------------


def note_before(children: list[Node], index: int) -> dict[str, Any] | None:
    """The `# pelagos:note {json}` comment attached to the statement at children[index], if any."""
    i = index - 1
    while i >= 0 and children[i].kind == "space":
        i -= 1
    if i >= 0 and children[i].kind == "comment" and children[i].text.startswith(NOTE_PREFIX):
        try:
            data = json.loads(children[i].text[len(NOTE_PREFIX) :])
        except ValueError:
            return None
        return data if isinstance(data, dict) else {"notes": str(data)}
    return None


def note_for(node: Node, doc_children: list[Node]) -> dict[str, Any] | None:
    for i, c in enumerate(doc_children):
        if c is node:
            return note_before(doc_children, i)
    return None


# Zones ---------------------------------------------------------------------------------


def zone_from_node(
    node: Node,
    view: str = "_default",
    path: str | None = None,
    managed: bool = False,
    note: dict[str, Any] | None = None,
) -> Zone:
    """Project a `zone` statement onto the Zone dataclass; unmodelled statements go to `extra`."""
    args = node.args
    name = normalize_name(args[0]) if args else "."
    rclass = args[1].upper() if len(args) > 1 else "IN"
    kind = ZoneKind.PRIMARY
    zone = Zone(name=name, kind=kind, view=view, rclass=rclass, config_path=path)
    zone.source = ZoneSource.PELAGOS if managed else ZoneSource.USER_CONF
    if note:
        zone.notes = note.get("notes") if isinstance(note.get("notes"), str) else json.dumps(note)
    for stmt in node.statements():
        sname = stmt.name
        if sname == "type":
            try:
                zone.kind = ZoneKind.from_bind(stmt.args[0]) if stmt.args else ZoneKind.PRIMARY
            except ValueError:
                zone.extra["type"] = stmt.value_text()
        elif sname == "file":
            zone.file = stmt.args[0] if stmt.args else None
        elif sname in ZONE_LIST_FIELDS:
            setattr(zone, ZONE_LIST_FIELDS[sname], stmt.elements())
            if sname in ("update-policy", "allow-update"):
                zone.dynamic = True
            if sname in ("primaries", "masters") and stmt.raw_args:
                # `primaries port 5300 { ... }` carries options before the block; keep them visible.
                zone.extra[sname + "-options"] = " ".join(stmt.raw_args)
        elif sname == "forward":
            zone.forward = stmt.args[0] if stmt.args else None
        elif sname == "dnssec-policy":
            zone.dnssec_policy = stmt.args[0] if stmt.args else None
        elif sname == "inline-signing":
            zone.inline_signing = _bool(stmt.args[0]) if stmt.args else None
        elif sname == "in-view":
            zone.extra["in-view"] = stmt.args[0] if stmt.args else ""
        else:
            zone.extra[sname] = stmt.value_text()
    if zone.update_policy == ["local"]:
        zone.dynamic = True
    return zone


def _bool(text: str) -> bool:
    return text.lower() in ("yes", "true", "1", "on")


# BindConfigTree ---------------------------------------------------------------------------


def load_tree(
    user_conf: Path,
    node_id: str,
    checkconf: str | None = "named-checkconf",
    include_dir: Path | None = None,
    reader: Callable[[Path], str] | None = None,
) -> BindConfigTree:
    """Parse the user named.conf and every include into the resolved view with provenance (section 8)."""
    files = ConfigFiles.load(user_conf, reader)
    tree = build_tree(files, node_id, include_dir)
    if checkconf:
        tree.pelagos["checkconf"] = run_checkconf(checkconf, user_conf)
    return tree


def build_tree(files: ConfigFiles, node_id: str, include_dir: Path | None = None) -> BindConfigTree:
    """BindConfigTree of already loaded files; include_dir marks what Pelagos manages."""
    user_conf = files.user_conf
    tree = BindConfigTree(node_id=node_id, user_conf=str(user_conf), includes=list(files.order))
    include_dir = include_dir.resolve() if include_dir else None

    def managed(path: str) -> bool:
        return include_dir is not None and _under(Path(path), include_dir)

    others: list[dict[str, Any]] = []
    view_blocks: dict[str, Node] = {}
    include_line = False
    options_include = False
    pelagos_conf = str(include_dir / "pelagos.conf") if include_dir else None
    options_conf = str(include_dir / "options.conf") if include_dir else None
    view_includes: dict[str, bool] = {}

    # Include lines are looked up in the raw files: expansion hides them.
    for node, path, parents in raw_includes(files):
        target = node.args[0] if node.args else ""
        if not os.path.isabs(target):
            target = str(Path(path).parent / target)
        depth = len(parents)
        if depth == 0 and pelagos_conf and same_path(target, pelagos_conf):
            include_line = True
        elif depth == 1 and parents[0].name == "options" and options_conf and same_path(target, options_conf):
            options_include = True
        elif depth == 1 and parents[0].name == "view" and include_dir and _under(Path(target), include_dir):
            view_includes[parents[0].args[0] if parents[0].args else "_default"] = True

    for res in files.statements():
        node, path, parents = res.node, res.path, res.parents
        depth = len(parents)
        name = node.name
        if depth == 0:
            entry_path = path
            if name == "options":
                for sub, where in files.expanded(node.block.children if node.block else [], path):
                    if sub.is_statement and sub.kind != "include":
                        tree.options.append(_entry(sub, where, managed(where)))
            elif name == "key":
                tree.keys.append(_key_entry(node, path, managed(path)))
            elif name == "acl":
                tree.acls.append(
                    ConfigEntry(
                        name=node.args[0] if node.args else "",
                        value=compact_text(node.block) if node.block else "",
                        path=path,
                        line=node.line,
                        managed=managed(path),
                    )
                )
            elif name == "controls":
                tree.controls.extend(_entry(s, path, managed(path)) for s in node.statements())
            elif name == "statistics-channels":
                tree.statistics_channels.extend(_entry(s, path, managed(path)) for s in node.statements())
            elif name == "logging":
                text = node.serialize().strip()
                tree.logging = text if tree.logging is None else tree.logging + "\n" + text
            elif name == "view":
                view_name = node.args[0] if node.args else "_default"
                view_blocks[view_name] = node
                tree.views.setdefault(view_name, [])
            elif name == "zone":
                doc = files.docs.get(path)
                note = _note(doc, node, parents)
                tree.zones.append(zone_from_node(node, "_default", path, managed(path), note))
            else:
                others.append(
                    {
                        "name": name,
                        "args": node.args,
                        "value": node.value_text() if node.block is None else None,
                        "path": entry_path,
                        "line": node.line,
                        "managed": managed(path),
                    }
                )
        elif depth == 1 and parents[0].name == "view":
            view_name = parents[0].args[0] if parents[0].args else "_default"
            if name == "zone":
                doc = files.docs.get(path)
                note = _note(doc, node, parents)
                zone = zone_from_node(node, view_name, path, managed(path), note)
                tree.views.setdefault(view_name, []).append(zone)
                tree.zones.append(zone)
            elif name == "key":
                tree.keys.append(_key_entry(node, path, managed(path), view_name))

    managed_files: dict[str, bool] = {}
    views_files: list[str] = []
    if include_dir is not None:
        for fname in MANAGED_FILES:
            managed_files[fname] = (include_dir / fname).is_file()
        views_dir = include_dir / VIEWS_DIR
        if views_dir.is_dir():
            views_files = sorted(p.name for p in views_dir.glob("*.conf"))
    tree.pelagos = {
        "include_dir": str(include_dir) if include_dir else None,
        "managed_files": managed_files,
        "view_files": views_files,
        "include_line_present": include_line,
        "options_include_present": options_include,
        "view_includes_present": {v: view_includes.get(v, False) for v in tree.views},
        "missing_includes": files.missing,
        "parse_errors": files.errors,
        "other_statements": others,
        "has_views": bool(tree.views),
    }
    return tree


def _note(doc: ConfigDocument | None, node: Node, parents: tuple[Node, ...]) -> dict[str, Any] | None:
    if doc is None:
        return None
    siblings = parents[-1].block.children if parents and parents[-1].block else doc.root
    note = note_for(node, siblings)
    if note is None and parents:
        # A zone included from a view file: the comment sits in the included file's root.
        note = note_for(node, doc.root)
    return note


def _entry(node: Node, path: str, managed: bool) -> ConfigEntry:
    return ConfigEntry(name=node.name, value=node.value_text(), path=path, line=node.line, managed=managed)


def _key_entry(node: Node, path: str, managed: bool, view: str | None = None) -> ConfigEntry:
    algorithm = node.first("algorithm")
    alg = algorithm.args[0] if algorithm and algorithm.args else "?"
    value = f"algorithm {alg}; secret ****"
    if view:
        value += f"; view {view}"
    return ConfigEntry(
        name=node.args[0] if node.args else "", value=value, path=path, line=node.line, managed=managed
    )


def _under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root)
        return True
    except ValueError:
        return False


def run_checkconf(binary: str, conf: Path, print_tree: bool = False, timeout: float = 30.0) -> dict[str, Any]:
    """named-checkconf as a dict {ok, output}; a missing binary is reported, not raised."""
    cmd = [binary, *(["-p"] if print_tree else []), str(conf)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError:
        return {"ok": None, "output": f"{binary} not found"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "output": f"{binary} timed out"}
    return {"ok": proc.returncode == 0, "output": (proc.stdout + proc.stderr).strip()}


def key_secret(files: ConfigFiles, name: str) -> tuple[str, str] | None:
    """(algorithm, secret) of a key statement anywhere in the configuration; for the connector only."""
    for res in files.statements():
        if res.node.name == "key" and res.node.args and unquote(res.node.args[0]) == name:
            alg = res.node.first("algorithm")
            secret = res.node.first("secret")
            if alg and alg.args and secret and secret.args:
                return alg.args[0], secret.args[0]
    return None


def materialize(files: ConfigFiles, dest: Path, overrides: dict[Path, str]) -> Path:
    """Copy the include chain into dest with include paths rewritten, substituting overrides.

    The result is a self-contained tree named-checkconf can validate before anything is written
    for real. Zone files are not copied: named-checkconf does not open them without -z.
    """
    mapping: dict[str, Path] = {}
    all_paths = list(files.order) + [str(p) for p in overrides if str(p) not in files.docs]
    for i, original in enumerate(all_paths):
        mapping[original] = dest / f"{i}-{Path(original).name}"
    dest.mkdir(parents=True, exist_ok=True)
    for original in all_paths:
        override = overrides.get(Path(original))
        if override is not None:
            doc = parse(override, original)
        else:
            doc = files.docs[original]
            doc = parse(doc.serialize(), original)  # a fresh copy; include rewriting mutates nodes
        for inc in list(_walk_includes(doc.root)):
            targets = resolve_include(inc, Path(original))
            rewritten = [str(mapping.get(str(t), t)) for t in targets]
            if len(rewritten) == 1:
                _set_include_target(inc, rewritten[0])
            elif rewritten:
                # A glob include becomes one include per matched file.
                siblings, index, _ = doc._locate(inc)
                siblings[index : index + 1] = parse_nodes(" ".join(f'include "{p}";' for p in rewritten))
        mapping[original].write_text(doc.serialize())
    return mapping[str(files.user_conf)]


def _set_include_target(inc: Node, target: str) -> None:
    values = [c for c in inc.children if c.kind == "value"]
    if len(values) >= 2:
        values[1].text = '"' + target + '"'


def statement_dict(node: Node) -> dict[str, Any]:
    """JSON view of a statement for the advanced editor; key secrets are masked."""
    out: dict[str, Any] = {
        "name": node.name,
        "args": node.args,
        "line": node.line,
        "include": node.kind == "include",
    }
    if node.block is None:
        out["value"] = "****" if node.name == "secret" else node.value_text()
    else:
        out["statements"] = [statement_dict(s) for s in node.statements()]
    return out


def files_tree(files: ConfigFiles, include_dir: Path | None = None) -> dict[str, Any]:
    """`GET /advanced/bind/tree` payload: every file in include order with its statements."""
    root = include_dir.resolve() if include_dir else None
    return {
        "files": [
            {
                "path": path,
                "managed": root is not None and _under(Path(path), root),
                "statements": [statement_dict(s) for s in files.docs[path].statements()],
            }
            for path in files.order
        ],
        "missing": list(files.missing),
        "errors": list(files.errors),
    }


def same_path(a: str | Path, b: str | Path) -> bool:
    try:
        return Path(a).resolve() == Path(b).resolve()
    except OSError:
        return str(a) == str(b)
