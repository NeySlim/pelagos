# SPDX-License-Identifier: Apache-2.0
"""Hand a statement over to Pelagos: move it from a user file to the matching managed file.

Targets: handover/options/<name>, handover/acls/<name>, handover/keys/<name>,
handover/zones/<view>/<zone>. The statement leaves the user file through the lossless parser (the
rest of the file stays byte for byte) and its canonical text lands in options.conf, acls.conf,
keys.conf or zones.conf. The effective value printed by `named-checkconf -p` must not change.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pelagos.connectors.bind.namedconf.resolve import ConfigFiles, _under, unmovable_keys
from pelagos.connectors.bind.namedconf.tree import Node, canonical, parse_nodes
from pelagos.domain.dns import BindConfigTree, normalize_name
from pelagos.domain.plan import Change, ChangeOp, ValidationResult

if TYPE_CHECKING:
    from pelagos.connectors.bind.configplan import ConfigPlanner

PREFIX = "handover/"
KINDS = ("options", "acls", "keys", "zones")
# `directory` decides where relative includes resolve; moving it would change how the rest loads.
NEVER_MOVED = frozenset({"directory"})
DEFAULT_VIEW = "_default"


@dataclass(slots=True)
class Located:
    node: Node
    path: str


def is_handover(change: Change) -> bool:
    return change.target.startswith(PREFIX)


def parse_target(target: str) -> tuple[str, str, str]:
    """(kind, name, view) of a handover target."""
    rest = target[len(PREFIX) :]
    kind, _, tail = rest.partition("/")
    if kind not in KINDS or not tail:
        raise ValueError(f"unknown handover target {target!r}")
    if kind == "zones":
        view, sep, name = tail.partition("/")
        if not sep or not name:
            raise ValueError("handover/zones needs <view>/<zone>")
        return kind, normalize_name(name), view or DEFAULT_VIEW
    return kind, tail, DEFAULT_VIEW


def user_statements(files: ConfigFiles, include_dir: Path, kind: str, name: str, view: str) -> list[Located]:
    """Statements of that kind and name in files outside the Pelagos include directory."""
    root = include_dir.resolve()
    found: list[Located] = []
    for res in files.statements():
        node, parents = res.node, res.parents
        if node.kind == "include" or _under(Path(res.path), root):
            continue
        if kind == "options":
            ok = len(parents) == 1 and parents[0].name == "options" and node.name == name
        elif kind in ("acls", "keys"):
            ok = not parents and node.name == kind[:-1] and node.args[:1] == [name]
        else:
            if view == DEFAULT_VIEW:
                scope = not parents
            else:
                scope = len(parents) == 1 and parents[0].name == "view" and parents[0].args[:1] == [view]
            ok = scope and node.name == "zone" and bool(node.args) and normalize_name(node.args[0]) == name
        if ok:
            found.append(Located(node, res.path))
    return found


def candidates(tree: BindConfigTree) -> list[dict[str, Any]]:
    """What this node can hand over: user statements of the four kinds, one row each."""
    out: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for e in tree.options:
        if not e.managed:
            counts[e.name] = counts.get(e.name, 0) + 1
    for e in tree.options:
        if e.managed or e.name in NEVER_MOVED or counts[e.name] != 1:
            continue
        out.append(_row("options", e.name, DEFAULT_VIEW, e.value, e.path, "options.conf"))
    for a in tree.acls:
        if not a.managed:
            out.append(_row("acls", a.name, DEFAULT_VIEW, a.value, a.path, "acls.conf"))
    fixed = {(u["path"], u["line"]) for u in tree.pelagos.get("unmovable_keys", [])}
    for k in tree.keys:
        if not k.managed and (k.path, k.line) not in fixed:
            out.append(_row("keys", k.name, DEFAULT_VIEW, k.value, k.path, "keys.conf"))
    for z in tree.zones:
        if z.source.value != "user_conf" or not z.config_path:
            continue
        target = "zones.conf" if z.view == DEFAULT_VIEW else f"views/{z.view}.conf"
        out.append(_row("zones", z.name, z.view, z.kind.value, z.config_path, target))
    return out


def _row(kind: str, name: str, view: str, value: str, path: str, target_file: str) -> dict[str, Any]:
    target = f"{PREFIX}{kind}/{view}/{name}" if kind == "zones" else f"{PREFIX}{kind}/{name}"
    return {
        "kind": kind,
        "name": name,
        "view": view if kind == "zones" else None,
        "target": target,
        "value": value,
        "config_path": path,
        "managed_file": target_file,
    }


# Rendering -------------------------------------------------------------------------------


def render(planner: ConfigPlanner, change: Change) -> None:
    """Move one statement: edit the user file in the planner's parsed copy, add it to the managed file."""
    from pelagos.connectors.bind.configplan import PlanError

    kind, name, view = parse_target(change.target)
    if ChangeOp(change.op) is ChangeOp.DELETE:
        raise PlanError("a handover cannot be a delete")
    if kind == "options" and name in NEVER_MOVED:
        raise PlanError(f"option {name} stays in the user file")
    managed = planner.managed
    pel = planner.tree.pelagos
    found = user_statements(planner.files, managed.include_dir, kind, name, view)
    if not found:
        if planner.replay:  # already moved, or never defined on this node: nothing to do
            return
        raise PlanError(f"{kind[:-1]} {name} is not defined in a user file")
    if len(found) > 1:
        raise PlanError(f"{kind[:-1]} {name} is defined {len(found)} times in user files")
    target = found[0]
    if kind == "keys":
        why = unmovable_keys(planner.files).get((target.path, target.node.line))
        if why:
            raise PlanError(f"key {name} stays in the user file ({why})")
    if kind == "options":
        if not pel.get("options_include_present"):
            raise PlanError(f"{managed.options_conf} is not included from the options block")
        path = managed.options_conf
    elif kind == "zones":
        planner._check_zone_includes(view)
        path = managed.zones_file(view)
    else:
        path = managed.keys_conf if kind == "keys" else managed.acls_conf
    doc = planner.doc(path)
    arg0 = None if kind == "options" else name.rstrip(".") if kind == "zones" else name
    if managed.find(doc, target.node.name, arg0) is not None:
        raise PlanError(f"{kind[:-1]} {name} already exists in {path.name}")
    text = canonical(target.node)
    shown = _mask(text)
    managed_doc_node = doc.add_statement(text)
    where = str(path.relative_to(managed.include_dir))
    after = change.after if isinstance(change.after, dict) else {}
    comment = after.get("comment", True)
    user_doc = planner.files.docs[target.path]
    left = comment and user_doc.replace_with_comment(target.node, f"# moved to {where} by Pelagos")
    if not left:
        user_doc.remove_statement(target.node)
    planner._set_text(Path(target.path), user_doc.serialize())
    planner.result.requires_confirmation = planner.result.requires_confirmation or kind in ("keys", "zones")
    planner.result.changes.append(
        Change(
            ChangeOp.REPLACE,
            change.target,
            before=shown,
            after={
                "file": where,
                "from": target.path,
                "value": _mask(managed_doc_node.serialize()),
                "comment": bool(comment),
            },
            node_ids=change.node_ids,
        )
    )


def _mask(text: str) -> str:
    return re.sub(r'(secret\s+)("[^"]*"|\S+)', r'\1"****"', text)


# Effective value -----------------------------------------------------------------------------


def print_effective(binary: str | None, conf: Path, timeout: float = 30.0) -> str | None:
    """`named-checkconf -p` of a configuration, or None when it cannot be printed."""
    if not binary:
        return None
    try:
        cmd = [binary, "-p", str(conf)]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, OSError):
        return None
    return proc.stdout if proc.returncode == 0 else None


def effective_value(printed: str, target: str) -> str | None:
    """Canonical text of the statement a handover target names, in `named-checkconf -p` output."""
    kind, name, view = parse_target(target)
    nodes = [n for n in parse_nodes(_drop_warnings(printed)) if n.is_statement]
    pieces: list[str] = []
    if kind == "options":
        for options in (n for n in nodes if n.name == "options"):
            pieces += [canonical(s, 1) for s in options.statements() if s.name == name]
    elif kind in ("acls", "keys"):
        pieces = [canonical(n) for n in nodes if n.name == kind[:-1] and n.args[:1] == [name]]
    else:
        scope = nodes
        if view != DEFAULT_VIEW:
            scope = [s for n in nodes if n.name == "view" and n.args[:1] == [view] for s in n.statements()]
        pieces = [
            canonical(n) for n in scope if n.name == "zone" and n.args and normalize_name(n.args[0]) == name
        ]
    if not pieces:
        return None
    return re.sub(r"\s+", " ", "\n".join(pieces))


_WARNING = re.compile(r"^[^\s{}]+:\d+: ")


def _drop_warnings(printed: str) -> str:
    return "".join(line for line in printed.splitlines(keepends=True) if not _WARNING.match(line))


def snapshot(printed: str | None, targets: list[str]) -> dict[str, str | None] | None:
    if printed is None:
        return None
    return {t: effective_value(printed, t) for t in targets}


def unchanged(before: dict[str, str | None] | None, after: dict[str, str | None] | None) -> list[str]:
    """Targets whose effective value differs (all of them when a side could not be printed)."""
    if before is None or after is None:
        return list((before or after or {}).keys())
    return [t for t, v in before.items() if after.get(t) != v]


def check_effective(
    binary: str | None, before_conf: Path, after_conf: Path, targets: list[str]
) -> ValidationResult:
    before = snapshot(print_effective(binary, before_conf), targets)
    after = snapshot(print_effective(binary, after_conf), targets)
    moved = unchanged(before, after)
    if moved:
        return ValidationResult(
            ok=False,
            tool="effective-value",
            output="effective value would change for " + ", ".join(t[len(PREFIX) :] for t in moved),
        )
    return ValidationResult(ok=True, tool="effective-value", output="effective values unchanged")
