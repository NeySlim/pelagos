# SPDX-License-Identifier: Apache-2.0
"""Security audit findings about how Pelagos reaches zones: static primary zones (offered a
conversion to dynamic) and views (one key per view, selected by match-clients).

Both are proposals: nothing changes unless the operator selects the finding. A view key never
changes which view answers an existing client: only requests signed with the new key move.
"""

from __future__ import annotations

import logging
import stat
from pathlib import Path
from typing import Any

from pelagos.connectors.bind.builtin_zones import BUILTIN_ZONES
from pelagos.domain import Severity, zone_updates
from pelagos.installer import bindconf, managed
from pelagos.installer.bindconf import ConfigFiles, Statement

UPDATE_TYPES = zone_updates.ADMIN_UPDATE_TYPES
log = logging.getLogger(__name__)


def pelagos_rpz_zones(env: Any) -> frozenset[str]:
    """Policy zones Pelagos owns per the cluster RPZ state: their statements and files are rewritten
    by Pelagos, so no audit or import proposes a change to them. Empty before `pelagos init`."""
    if not env.node_initialized():
        return frozenset()
    from pelagos.core.config_store import ConfigStore
    from pelagos.rpz import model

    try:
        cluster = ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml).load_cluster()
        return frozenset(model.managed_zones(cluster.settings))
    except Exception as exc:  # an unreadable cluster.toml audits every zone
        log.warning("RPZ zones of the cluster not read: %s", exc)
        return frozenset()


def view_key_name(view: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in view.lower())
    return f"ddi-{safe}"


def inherited_allow_update(top: list[Statement], view: str) -> Statement | None:
    """The allow-update statement a zone of `view` without its own inherits: the view's, else the options'."""
    for v in views(top):
        if _view_name(v) == view.strip('"') and v.sub("allow-update") is not None:
            return v.sub("allow-update")
    options = next((s for s in top if s.name == "options"), None)
    return options.sub("allow-update") if options is not None else None


def update_rules(zone: bindconf.ZoneDef, top: list[Statement]) -> list[str] | None:
    """Elements of the allow-update that applies to the zone, None when nothing sets one."""
    own = zone.stmt.sub("allow-update")
    stmt = own if own is not None else inherited_allow_update(top, zone.view)
    return bindconf.acl_elements(stmt) if stmt is not None else None


def takes_updates(zone: bindconf.ZoneDef, top: list[Statement]) -> bool:
    return zone_updates.takes_updates(zone.stmt.sub("update-policy") is not None, update_rules(zone, top))


def is_static(zone: bindconf.ZoneDef, top: list[Statement]) -> bool:
    return zone.is_primary and not takes_updates(zone, top)


def views(top: list[Statement]) -> list[Statement]:
    return [s for s in top if s.name == "view" and s.block is not None]


def _view_name(view: Statement) -> str:
    return view.words[0].strip('"') if view.words else "_default"


def view_key_of(top: list[Statement], view: str) -> str | None:
    """The view's own Pelagos key when its match-clients already names it."""
    for v in views(top):
        if _view_name(v) == view:
            key = view_key_name(view)
            mc = v.sub("match-clients")
            elements = [e.replace('"', "") for e in bindconf.acl_elements(mc)] if mc else []
            return key if f"key {key}" in elements else None
    return None


# Findings ------------------------------------------------------------------------------------------


def findings(
    files: ConfigFiles, top: list[Statement], key_names: set[str], skip: frozenset[str] = frozenset()
) -> list[Any]:
    from pelagos.domain.messages import join, msg
    from pelagos.installer.security_audit import Finding, finding_id

    out: list[Any] = []
    if managed.ADMIN_KEY in key_names:
        for z in bindconf.zones(top):
            if not is_static(z, top) or z.name in BUILTIN_ZONES or z.name in skip:
                continue
            subject = f"{z.view}/{z.name}"
            key = view_key_of(top, z.view) or managed.ADMIN_KEY
            au = z.stmt.sub("allow-update")
            proposal = (
                msg("finding.static_zone.proposal_replace", policy=_policy(key))
                if au is not None
                else msg("finding.static_zone.proposal_add", policy=_policy(key))
            )
            out.append(
                Finding.of(
                    finding_id("bind", "static_zone", subject),
                    "static_zone",
                    Severity.INFO,
                    "bind",
                    subject,
                    msg("finding.static_zone.description", zone=z.name),
                    proposal,
                    msg(
                        "finding.static_zone.risk",
                        file=_file(z) or msg("finding.static_zone.the_zone_file"),
                        name=z.name.rstrip("."),
                    ),
                    {
                        "zone": z.name,
                        "view": z.view,
                        "file": z.stmt.path,
                        "line": z.stmt.line,
                        "remediation": "convert_dynamic",
                    },
                )
            )
    all_views = views(top)
    if len(all_views) >= 2 and {managed.ADMIN_KEY, managed.READ_KEY} <= key_names:
        for index, v in enumerate(all_views):
            name = _view_name(v)
            if view_key_of(top, name):
                continue
            key = view_key_name(name)
            earlier = [_view_name(e) for e in all_views[:index]]
            mc = v.sub("match-clients")
            current = bindconf.acl_elements(mc) if mc else ["any"]
            out.append(
                Finding.of(
                    finding_id("bind", "view_key", name),
                    "view_key",
                    Severity.WARNING,
                    "bind",
                    name,
                    msg(
                        "finding.view_key.description",
                        view=name,
                        clients=join(current, "; "),
                        read_key=managed.READ_KEY,
                        admin_key=managed.ADMIN_KEY,
                    ),
                    msg("finding.view_key.proposal_earlier", key=key, view=name, earlier=earlier)
                    if earlier
                    else msg("finding.view_key.proposal", key=key, view=name),
                    msg("finding.view_key.risk"),
                    {
                        "view": name,
                        "key": key,
                        "earlier": earlier,
                        "file": v.path,
                        "line": v.line,
                        "remediation": "view_key",
                    },
                )
            )
    return out


def _policy(key: str) -> str:
    return f"update-policy {{ grant {key} zonesub {' '.join(UPDATE_TYPES)}; }};"


def _file(z: bindconf.ZoneDef) -> str | None:
    f = z.stmt.sub("file")
    return f.words[0].strip('"') if f and f.words else None


# Remediation ------------------------------------------------------------------------------------


def _edit(text: str, edits: list[tuple[int, int, str]]) -> str:
    for start, end, repl in sorted(edits, key=lambda e: (e[0], e[1]), reverse=True):
        text = text[:start] + repl + text[end:]
    return text


def _options_directory(files: ConfigFiles) -> Path | None:
    for s in files.top_level():
        if s.name == "options":
            d = s.sub("directory")
            if d and d.words:
                return Path(d.words[0].strip('"'))
    return None


def journal_problem(env: Any, files: ConfigFiles, zone: bindconf.ZoneDef) -> str | None:
    """named must create <file>.jnl next to the zone file once the zone is dynamic."""
    name = _file(zone)
    if not name:
        return None
    path = Path(name)
    if not path.is_absolute():
        base = _options_directory(files)
        if base is None:
            return None
        path = base / path
    directory = path.parent
    try:
        st = directory.stat()
    except OSError:
        return None
    user, group = env.paths.bind_user, env.paths.bind_group
    import grp
    import pwd

    try:
        uid = pwd.getpwnam(user).pw_uid
    except KeyError:
        uid = None
    try:
        gid = grp.getgrnam(group).gr_gid
    except KeyError:
        gid = None
    mode = stat.S_IMODE(st.st_mode)
    if (uid is not None and st.st_uid == uid and mode & 0o200) or (
        gid is not None and st.st_gid == gid and mode & 0o020
    ):
        return None
    if uid is None and gid is None:
        return None
    return (
        f"named ({user}:{group}) cannot write in {directory} (mode {mode:04o}), where it would keep "
        f"{path.name}.jnl: move the zone file to a directory named can write (for instance the one "
        "of the other dynamic zones) or make this one group-writable, then run the conversion again"
    )


def remediate_convert_dynamic(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    from pelagos.installer.security_audit import _file_text, _reload_files, _run_bind, _zone_stmt

    files = _reload_files(env)
    top = list(files.top_level())
    if managed.ADMIN_KEY not in {k.name for k in bindconf.keys(top)}:
        raise RuntimeError(f"key {managed.ADMIN_KEY} is not defined: run the import first")
    z = _zone_stmt(files, d["view"], d["zone"])
    if not is_static(z, top):
        return f"zone {d['zone']} is already dynamic"
    if not env.dry_run:
        problem = journal_problem(env, files, z)
        if problem:
            raise RuntimeError(problem)
    key = view_key_of(top, d["view"]) or managed.ADMIN_KEY
    text = _file_text(files, str(z.stmt.path))
    au = z.stmt.sub("allow-update")
    if au is not None:
        new = bindconf.replace_span(text, au.start, au.end, _policy(key))
    else:
        assert z.stmt.block is not None
        new = bindconf.insert_in_block(text, z.stmt.block, _policy(key))
    out = _run_bind(env, {str(z.stmt.path): new}, f"security-convert-dynamic-{d['zone']}")
    note = "changes go to its journal; use rndc freeze/thaw to edit it by hand"
    return f"{out}\nzone {d['zone']} is dynamic: {note}"


def remediate_view_key(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    from pelagos.installer.security_audit import _file_text, _reload_files, _run_bind

    files = _reload_files(env)
    top = list(files.top_level())
    view, key = d["view"], d["key"]
    if view_key_of(top, view):
        return f"view {view} already selects {key}"
    defined = {k.name for k in bindconf.keys(top)}
    edits: dict[str, list[tuple[int, int, str]]] = {}
    texts: dict[str, str] = {}

    def add(stmt: Statement, start: int, end: int, repl: str) -> None:
        path = str(stmt.path)
        texts.setdefault(path, _file_text(files, path))
        edits.setdefault(path, []).append((start, end, repl))

    secret = None
    if key not in defined:
        secret = managed.new_secret()
        keys_conf = env.paths.keys_conf
        base = keys_conf.read_text() if keys_conf.exists() else managed.render_keys_conf({})
        texts[str(keys_conf)] = base.rstrip("\n") + "\n" + bindconf.format_key(key, "hmac-sha256", secret)
        edits.setdefault(str(keys_conf), [])
    all_views = views(top)
    target = next((v for v in all_views if _view_name(v) == view), None)
    if target is None or target.block is None:
        raise RuntimeError(f"view {view} not found any more")
    for v in all_views:
        if _view_name(v) == view:
            element = f"key {key};"
        elif _view_name(v) in d.get("earlier", []):
            element = f"!key {key};"
        else:
            continue
        mc = v.sub("match-clients")
        if mc is not None and mc.block is not None:
            add(mc, mc.block.start + 1, mc.block.start + 1, f" {element}")
        else:
            assert v.block is not None
            add(v, v.block.start + 1, v.block.start + 1, f"\n\tmatch-clients {{ {element} any; }};")
    view_transfer_done = False
    for z in [z for z in bindconf.zones(top) if z.view == view]:
        pol = z.stmt.sub("update-policy")
        if pol is not None and pol.block is not None and z.is_primary:
            add(z.stmt, pol.block.end, pol.block.end, f" grant {key} zonesub {' '.join(UPDATE_TYPES)}; ")
        au = z.stmt.sub("allow-update")
        if au is not None and au.block is not None and not is_static(z, top):
            add(z.stmt, au.block.start + 1, au.block.start + 1, f" key {key};")
        if not (z.is_primary or z.kind in ("secondary", "slave", "mirror")):
            continue
        xfr = z.stmt.sub("allow-transfer")
        if xfr is not None and xfr.block is not None:
            add(z.stmt, xfr.block.start + 1, xfr.block.start + 1, f" key {key};")
        elif not view_transfer_done:
            vx = target.sub("allow-transfer")
            if vx is not None and vx.block is not None:
                add(target, vx.block.start + 1, vx.block.start + 1, f" key {key};")
            else:
                # The view block overrides the options one: carry its elements so nobody loses transfers.
                options = next((s for s in top if s.name == "options"), None)
                inherited = bindconf.acl_elements(options.sub("allow-transfer")) if options else []
                kept = [e for e in inherited if e.replace('"', "") != f"key {key}"]
                elements = " ".join(f"{e};" for e in [f"key {key}", *kept])
                add(
                    target,
                    target.block.start + 1,
                    target.block.start + 1,
                    f"\n\tallow-transfer {{ {elements} }};",
                )
            view_transfer_done = True
    changed = {p: _edit(texts[p], e) for p, e in edits.items()}
    out = _run_bind(env, changed, f"security-view-key-{view}")
    notes = [out]
    if secret is not None:
        notes.append(env.store_secrets({f"tsig/{key}": secret}))
    notes.append(store_view_key(env, view, key))
    return "\n".join(n for n in notes if n)


def store_view_key(env: Any, view: str, key: str) -> str:
    """settings.dns.view_keys.<view> in cluster.toml: the key the connector signs with for that view."""
    if env.dry_run:
        return f"dry run: would set dns.view_keys.{view} = {key}"
    if not (env.node_initialized() and env.node_paths.master_key.exists()):
        return "node not initialized; set dns.view_keys in cluster.toml after pelagos init"
    from pelagos.core.config_store import ConfigStore

    store = ConfigStore(
        env.node_paths.node_toml, env.node_paths.cluster_toml, env.node_paths.locks_dir / "cluster.lock"
    )

    def mutate(cfg: Any) -> None:
        dns = cfg.settings.setdefault("dns", {})
        keys = dict(dns.get("view_keys") or {})
        keys[view] = key
        dns["view_keys"] = keys

    store.update_cluster(mutate, updated_by=f"node:{env.node_id}")
    return f"dns.view_keys.{view} = {key} stored in cluster.toml"
