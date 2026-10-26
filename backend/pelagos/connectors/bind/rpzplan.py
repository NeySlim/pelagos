# SPDX-License-Identifier: Apache-2.0
"""The `rpz/state` change: policy zones, their TSIG keys, `response-policy` and the rewrite log.

One declarative change: `after` lists every subscription of the cluster, each node renders only the
ones that name it, and removes the managed RPZ zones that are no longer wanted. List content is not
part of the plan: the collector downloads it (pelagos.rpz.sync); the plan only creates empty zones.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from pelagos.connectors.bind.managed import KeySpec, note_comment
from pelagos.domain.dns import Zone, ZoneKind, ZoneSource, normalize_name
from pelagos.domain.plan import Change, ChangeOp
from pelagos.rpz import convert as conv
from pelagos.rpz import model

if TYPE_CHECKING:
    from pelagos.connectors.bind.configplan import ConfigPlanner

RPZ_NOTE = "pelagos-rpz"
KEY_NOTE = "pelagos-rpz"
LOG_CHANNEL = "pelagos_rpz"
RPZ_SUBDIR = "rpz"
LOG_NAME = "rpz.log"


def rpz_dir(zone_dir: Path) -> Path:
    return zone_dir / RPZ_SUBDIR


def log_path(zone_dir: Path) -> Path:
    return rpz_dir(zone_dir) / LOG_NAME


def render(planner: ConfigPlanner, change: Change) -> None:
    from pelagos.connectors.bind.configplan import PlanError

    after = change.after if isinstance(change.after, dict) else {}
    subs = [_sub(raw) for raw in after.get("subs") or []]
    wanted = [s for s in subs if s.on_node(planner.node_id)]
    if not planner.tree.pelagos.get("include_line_present"):
        raise PlanError(f"{planner.managed.pelagos_conf} is not included from {planner.user_conf}")
    for view in planner.tree.views:
        raise PlanError(f"the configuration uses views ({view}): RPZ subscriptions need the default view")
    zones_doc = planner.doc(planner.managed.zones_conf)
    existing = {z.name: z for z in planner.managed.zones(doc=zones_doc) if z.notes == RPZ_NOTE}
    allow = after.get("allow") or {}
    names: set[str] = set()
    for sub in wanted:
        zone = _zone(planner, sub)
        names.add(zone.name)
        _write_zone(planner, zones_doc, zone, sub.kind == "url", [])
    if wanted:
        zone = _allow_zone(planner)
        names.add(zone.name)
        _write_zone(planner, zones_doc, zone, True, allow)
    for name in existing:
        if name not in names:
            planner.managed.remove(zones_doc, "zone", name.rstrip("."))
    _keys(
        planner, wanted, {str(r.get("id")): str(r.get("tsig_secret") or "") for r in after.get("subs") or []}
    )
    _policy(planner, wanted, bool(after.get("break_dnssec", True)))
    _logging(planner, bool(wanted) and bool(after.get("log", True)))
    op = ChangeOp.REPLACE if existing else ChangeOp.ADD
    planner.result.changes.append(
        Change(
            op,
            change.target,
            before={"zones": sorted(existing)},
            after={**after, "zones": sorted(names)},
            node_ids=change.node_ids,
        )
    )
    planner.result.requires_confirmation = planner.result.requires_confirmation or any(
        n not in names for n in existing
    )


def _sub(raw: dict[str, Any]) -> model.Sub:
    fields = {k: v for k, v in raw.items() if k in model.Sub.__dataclass_fields__}
    return model.Sub(**fields)


def _zone(planner: ConfigPlanner, sub: model.Sub) -> Zone:
    from pelagos.connectors.bind.configplan import PlanError

    name = normalize_name(sub.zone)
    if planner.user_zone(name, "_default") is not None:
        raise PlanError(f"zone {name} is defined in a user file; Pelagos never edits it")
    file = str(rpz_dir(planner.zone_dir) / model.zone_file_name(sub.zone))
    zone = Zone(name=name, kind=ZoneKind.PRIMARY, file=file, notes=RPZ_NOTE)
    zone.source = ZoneSource.PELAGOS
    zone.allow_transfer = ["none"]
    zone.extra = {"notify": "no", "allow-query": "{ localhost; }"}
    if sub.kind == "axfr":
        zone.kind = ZoneKind.SECONDARY
        key = f" key {sub.tsig_key}" if sub.tsig_key else ""
        zone.primaries = [f"{p}{key}" for p in sub.primaries]
    return zone


def _allow_zone(planner: ConfigPlanner) -> Zone:
    sub = model.Sub(id=model.ALLOW_ID, name="allow", zone=model.ALLOW_ZONE, action="passthru")
    return _zone(planner, sub)


def _write_zone(
    planner: ConfigPlanner, doc: Any, zone: Zone, primary: bool, allow: dict[str, Any] | list[Any]
) -> None:
    planner.managed.upsert(
        doc, planner.managed.zone_statement(zone), "zone", zone.name.rstrip("."), note_comment(RPZ_NOTE)
    )
    if zone.kind is not ZoneKind.PRIMARY or not primary:
        return
    path = Path(zone.file or "")
    if path.exists() or path in planner.result.texts:
        return
    if zone.name == normalize_name(model.ALLOW_ZONE) and isinstance(allow, dict):
        text = conv.allow_zone_text(allow.get("domains") or [], allow.get("clients") or [], _serial())
    else:
        text = "\n".join(conv.header(_serial())) + "\n"
    planner._set_text(path, text)
    planner.result.zone_files[path] = text


def _serial() -> int:
    from pelagos.domain.common import utcnow

    return int(utcnow().timestamp())


def _keys(planner: ConfigPlanner, wanted: list[model.Sub], secrets: dict[str, str]) -> None:
    from pelagos.connectors.bind.configplan import PlanError

    doc = planner.doc(planner.managed.keys_conf)
    needed = {s.tsig_key: s for s in wanted if s.kind == "axfr" and s.tsig_key}
    present = {k.name: k for k in planner.managed.keys(doc)}
    for name, sub in needed.items():
        if planner._user_entry(planner.tree.keys, name) is not None:
            continue  # a key from the user's own files is used as it is
        secret = secrets.get(sub.id, "")
        if not secret:
            raise PlanError(f"subscription {sub.id}: the TSIG secret for key {name} is missing")
        spec = KeySpec(name=name, algorithm=sub.tsig_algorithm, secret=secret, notes=KEY_NOTE)
        planner.managed.upsert(doc, planner.managed.key_statement(spec), "key", name, note_comment(KEY_NOTE))
    for name, spec in present.items():
        if spec.notes == KEY_NOTE and name not in needed:
            planner.managed.remove(doc, "key", name)


def _policy(planner: ConfigPlanner, wanted: list[model.Sub], break_dnssec: bool) -> None:
    from pelagos.connectors.bind.configplan import PlanError

    if planner._user_entry(planner.tree.options, "response-policy") is not None:
        raise PlanError("response-policy is set in a user file; Pelagos never edits it")
    if not planner.tree.pelagos.get("options_include_present"):
        raise PlanError(f"{planner.managed.options_conf} is not included from the options block")
    doc = planner.doc(planner.managed.options_conf)
    if not wanted:
        planner.managed.remove(doc, "response-policy", None)
        return
    value = model.response_policy_value(wanted, break_dnssec)
    planner.managed.upsert(
        doc, planner.managed.option_statement("response-policy", value), "response-policy", None, None
    )


def _logging(planner: ConfigPlanner, on: bool) -> None:
    """A `logging` block of the user's wins (named accepts one): then the rewrites go where it says."""
    path = planner.managed.include_dir / "rpz.conf"
    user_has = any(
        node.name == "logging"
        for key, doc in planner.files.docs.items()
        if Path(key).parent != planner.managed.include_dir
        for node in doc.statements()
    )
    if user_has or not on:
        text = _managed_header() if (path.exists() or path in planner.result.texts) else None
        if text is not None:
            planner._set_text(path, text)
        return
    target = log_path(planner.zone_dir)
    text = (
        _managed_header()
        + f'logging {{ channel {LOG_CHANNEL} {{ file "{target}" versions 2 size 20m;'
        + " severity info; print-time yes; };"
        + f" category rpz {{ {LOG_CHANNEL}; default_syslog; }}; }};\n"
    )
    planner._set_text(path, text)
    _include(planner, path)


def _managed_header() -> str:
    from pelagos.connectors.bind.namedconf.resolve import MANAGED_HEADER

    return MANAGED_HEADER + "\n"


def _include(planner: ConfigPlanner, path: Path) -> None:
    from pelagos.connectors.bind.configplan import parse

    pel = planner.managed.pelagos_conf
    text = planner.result.texts.get(pel)
    if text is None:
        text = pel.read_text() if pel.is_file() else planner.managed.render_pelagos_conf()
    doc = parse(text, str(pel))
    if any(n.kind == "include" and n.args and n.args[0] == str(path) for n in doc.statements()):
        return
    doc.add_statement(f'include "{path}";')
    planner._set_text(pel, doc.serialize())
