# SPDX-License-Identifier: Apache-2.0
"""managed_drift: a change made outside Pelagos to something it manages, with adopt or restore.

Tracked objects (installer.ledger): the HA listener guard (files, loaded table, unit), each Kea HA
relationship (peers, URLs, roles, TLS and timing settings) and the files Pelagos owns whole (the Kea
socket drop-ins). An HA relationship is recorded the first time the audit sees it and again after
each Pelagos write of that engine (the engine write mark), unless the audit had already seen the
same difference before that write: a plan never absorbs a hand edit that was reported first.
Adopt makes Pelagos's record match the node; restore applies the record to the node.
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any

from pelagos.domain.messages import join, msg
from pelagos.installer import ha_guard, ha_listener, keaconf, keasetup, ledger

KIND = "managed_drift"
ACTIONS = ("adopt", "restore")
MANAGED_HEADER = "# pelagos:managed"
REL_KEYS = (
    "mode",
    "heartbeat-delay",
    "max-response-delay",
    "max-ack-delay",
    "max-unacked-clients",
    "send-lease-updates",
    "sync-leases",
    "wait-backup-ack",
    "trust-anchor",
    "cert-file",
    "key-file",
    "require-client-certs",
    "restrict-commands",
)
PEER_KEYS = ("url", "role", "auto-failover", "trust-anchor", "cert-file", "key-file", "basic-auth-user")


# HA guard ----------------------------------------------------------------------------------------


def guard_differences(env: Any, rec: dict[str, Any]) -> list[str]:
    state = rec.get("state") or {}
    out = ledger.file_differences(rec)
    if env.binary("nft") is not None:
        mine = ha_guard.loaded(env, ha_listener.GUARD_TABLE)
        if mine is None:
            out.append(f"table inet {ha_listener.GUARD_TABLE} is not loaded")
        else:
            want = list(state.get("peers") or [])
            if set(mine.peers) != set(want):
                out.append(
                    f"the loaded table admits {', '.join(mine.peers) or 'no address'} "
                    f"(Pelagos: {', '.join(want)})"
                )
            ports = sorted(state.get("ports") or [])
            if not set(ports) <= set(mine.ports):
                out.append(f"the loaded table filters port(s) {mine.ports} (Pelagos: {ports})")
    if not env.services.is_enabled(ha_listener.GUARD_UNIT):
        out.append(f"{ha_listener.GUARD_UNIT} is not enabled")
    if state.get("adopted_from") and ha_guard.legacy(env) is not None:
        back = f"table inet {ha_guard.LEGACY_TABLE} or {ha_guard.LEGACY_UNIT}"
        out.append(f"the hand-made guard is back ({back})")
    return out


def _seed_guard(env: Any) -> None:
    """A guard the 0.1.2 plan loaded before the ledger existed is recorded as found."""
    rules, unit = ha_guard.rules_path(env), ha_guard.unit_path(env)
    if ledger.get(env, ha_guard.KEY) or not rules.is_file() or not unit.is_file():
        return
    text = rules.read_text()
    if not text.startswith(MANAGED_HEADER) or ha_guard.legacy(env) is not None:
        return
    found = ha_guard.loaded(env, ha_listener.GUARD_TABLE) or ha_guard.parse_text(text)
    state = {"table": ha_listener.GUARD_TABLE, "unit": ha_listener.GUARD_UNIT, "file": str(rules)}
    state.update(ports=found.ports, peers=found.peers)
    ledger.record(env, ha_guard.KEY, "ha_guard", state, {rules: text, unit: unit.read_text()})


def _retire_legacy(env: Any) -> str:
    leg = ha_guard.legacy(env)
    if leg is None:
        return ""
    nft = env.binary("nft")
    backup = Path(env.backup_root) / f"ha-guard-restore-{time.strftime('%Y%m%dT%H%M%S')}"
    backup.mkdir(parents=True, exist_ok=True)
    if leg.unit is not None:
        ha_guard._systemctl(env, "disable", ha_guard.LEGACY_UNIT)
    for p in ([leg.unit] if leg.unit else []) + leg.rules:
        shutil.copy2(p, backup / p.name)
        p.unlink(missing_ok=True)
    if nft:
        env.runner.run([nft, "delete", "table", "inet", ha_guard.LEGACY_TABLE], privileged=True, check=False)
    env.services.daemon_reload()
    return f"{leg.source} removed again (copies in {backup})"


def _guard_restore(env: Any, rec: dict[str, Any]) -> str:
    state = rec.get("state") or {}
    out = [
        ha_guard.install(
            env,
            list(state.get("ports") or []),
            list(state.get("peers") or []),
            ha_guard._watch_seconds(ha_guard._listeners(env)),
        )
    ]
    if state.get("adopted_from"):
        out.append(_retire_legacy(env))
    return "\n".join(o for o in out if o)


def _guard_adopt(env: Any, rec: dict[str, Any]) -> str:
    mine = ha_guard.loaded(env, ha_listener.GUARD_TABLE) if env.binary("nft") else None
    if mine is not None:
        if not mine.peers:
            raise RuntimeError("the loaded guard admits no peer address: restore it instead")
        state = rec.get("state") or {}
        ports = mine.ports or list(state.get("ports") or [])
        return ha_guard.install(env, ports, mine.peers, None)
    # No guard loaded on the node: Pelagos stops managing one.
    backup = Path(env.backup_root) / f"ha-guard-forget-{time.strftime('%Y%m%dT%H%M%S')}"
    backup.mkdir(parents=True, exist_ok=True)
    env.services.disable_now(ha_listener.GUARD_UNIT)
    for p in (ha_guard.rules_path(env), ha_guard.unit_path(env)):
        if p.exists():
            shutil.copy2(p, backup / p.name)
            p.unlink()
    env.services.daemon_reload()
    ledger.update(env, {ha_guard.KEY: None})
    return f"no guard loaded: Pelagos no longer manages one (files kept in {backup})"


# Kea HA relationships ----------------------------------------------------------------------------


def _ha_body(env: Any, engine: str) -> tuple[Path, dict[str, Any]] | None:
    conf = env.paths.kea_conf(keasetup.DAEMONS[engine])
    try:
        return conf, keaconf.loads(conf.read_text(), str(conf))
    except (OSError, keaconf.KeaConfigError):
        return None


def _relationships(config: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        body = config[keaconf.root_key(config)]
    except keaconf.KeaConfigError:
        return []
    return [rel for _hi, _ri, rel in ha_listener._relationships(body)]


def ha_state(rel: dict[str, Any]) -> dict[str, Any]:
    """The settings of one relationship Pelagos tracks (no secret: basic-auth passwords are left out)."""
    peers = {}
    for p in rel.get("peers") or []:
        if isinstance(p, dict) and p.get("name"):
            peers[str(p["name"])] = {k: p[k] for k in PEER_KEYS if k in p}
    return {"relationship": {k: rel[k] for k in REL_KEYS if k in rel}, "peers": peers}


def ha_states(env: Any) -> dict[str, tuple[str, str, dict[str, Any]]]:
    out = {}
    for engine in ("kea4", "kea6"):
        found = _ha_body(env, engine)
        if found is None:
            continue
        for rel in _relationships(found[1]):
            server = str(rel.get("this-server-name") or "")
            if server:
                out[f"kea_ha:{engine}:{server}"] = (engine, server, ha_state(rel))
    return out


def _fmt(value: Any) -> str:
    return "absent" if value is None else json.dumps(value)


def ha_differences(want: dict[str, Any], have: dict[str, Any]) -> list[str]:
    out = []
    wr, hr = want.get("relationship") or {}, have.get("relationship") or {}
    for k in sorted(set(wr) | set(hr)):
        if wr.get(k) != hr.get(k):
            out.append(f"{k}: {_fmt(hr.get(k))} (Pelagos: {_fmt(wr.get(k))})")
    wp, hp = want.get("peers") or {}, have.get("peers") or {}
    for name in sorted(set(wp) | set(hp)):
        if name not in hp:
            out.append(f"peer {name} removed")
        elif name not in wp:
            out.append(f"peer {name} added ({_fmt(hp[name].get('url'))})")
        else:
            for k in sorted(set(wp[name]) | set(hp[name])):
                if wp[name].get(k) != hp[name].get(k):
                    out.append(f"peer {name} {k}: {_fmt(hp[name].get(k))} (Pelagos: {_fmt(wp[name].get(k))})")
    return out


def _written_at(env: Any, engine: str) -> float | None:
    from pelagos.core import ha_maintenance

    try:
        return ha_maintenance.marked_at(env.node_paths, engine, "write")
    except (AttributeError, TypeError):
        return None


def _ha_entry(engine: str, server: str, state: dict[str, Any]) -> dict[str, Any]:
    return ledger.entry("kea_ha", {"engine": engine, "server": server, **state})


def _track_ha(env: Any) -> list[tuple[str, dict[str, Any], dict[str, Any] | None]]:
    """(key, ledger entry, current state or None) of every HA relationship that drifted; records new
    relationships and Pelagos's own writes on the way."""
    current = ha_states(env)
    recorded = {k: v for k, v in ledger.read(env).items() if v.get("kind") == "kea_ha"}
    changes: dict[str, dict[str, Any] | None] = {}
    drifted = []
    now = time.time()
    for key, (engine, server, state) in current.items():
        rec = recorded.get(key)
        if rec is None:
            changes[key] = _ha_entry(engine, server, state)
            continue
        want = {k: v for k, v in (rec.get("state") or {}).items() if k in ("relationship", "peers")}
        if want == state:
            if rec.get("observed"):
                changes[key] = {**rec, "observed": None}
            continue
        fp = ledger.sha256_text(json.dumps(state, sort_keys=True))
        seen = rec.get("observed") or {}
        written = _written_at(env, engine)
        seen_before = seen.get("sha256") == fp and float(seen.get("at") or 0) < (written or 0)
        if written and written > float(rec.get("recorded_at") or 0) and not seen_before:
            changes[key] = _ha_entry(engine, server, state)
            continue
        if seen.get("sha256") != fp:
            rec = {**rec, "observed": {"sha256": fp, "at": now}}
            changes[key] = rec
        drifted.append((key, rec, state))
    for key, rec in recorded.items():
        if key not in current:
            drifted.append((key, rec, None))
    if changes:
        ledger.update(env, changes)
    return drifted


def _ha_restore(env: Any, key: str, rec: dict[str, Any]) -> str:
    state = rec.get("state") or {}
    engine, server = str(state.get("engine")), str(state.get("server"))
    found = _ha_body(env, engine)
    if found is None:
        raise RuntimeError(f"the {engine} configuration cannot be read")
    conf, config = found
    new = json.loads(json.dumps(config))
    rel = next((r for r in _relationships(new) if r.get("this-server-name") == server), None)
    if rel is None:
        raise RuntimeError(f"{engine} has no HA relationship for {server} any more: adopt instead")
    want_rel = state.get("relationship") or {}
    for k in REL_KEYS:
        if k in want_rel:
            rel[k] = want_rel[k]
        else:
            rel.pop(k, None)
    want_peers = state.get("peers") or {}
    peers = [p for p in rel.get("peers") or [] if isinstance(p, dict) and str(p.get("name")) in want_peers]
    for name, fields in want_peers.items():
        peer = next((p for p in peers if str(p.get("name")) == name), None)
        if peer is None:
            peer = {"name": name}
            peers.append(peer)
        for k in PEER_KEYS:
            if k in fields:
                peer[k] = fields[k]
            else:
                peer.pop(k, None)
    rel["peers"] = peers
    files = keasetup.edited_files(conf, new)
    out = keasetup.write_files(env, engine, conf, files, f"drift-restore-{engine}", restart=False)
    ledger.update(env, {key: _ha_entry(engine, server, ha_state(rel))})
    return out


def _ha_adopt(env: Any, key: str) -> str:
    current = ha_states(env)
    if key not in current:
        ledger.update(env, {key: None})
        return f"{key} is gone from the configuration: no longer tracked"
    engine, server, state = current[key]
    ledger.update(env, {key: _ha_entry(engine, server, state)})
    return f"{engine} HA relationship of {server}: the node's settings are now Pelagos's"


# Files Pelagos owns ------------------------------------------------------------------------------


def owned_files(env: Any) -> list[Path]:
    out = []
    for engine in keasetup.DAEMONS:
        try:
            unit = env.kea_unit(engine)
        except Exception:  # noqa: S112 - no unit known for this engine
            continue
        out.append(Path(env.paths.systemd_dir) / f"{unit}.d" / keasetup.DROPIN_NAME)
    return out


def record_file(env: Any, path: Path) -> None:
    """Called by the installer after it writes a file it owns whole."""
    try:
        ledger.record(env, f"file:{path}", "file", {"path": str(path)}, {path: Path(path).read_text()})
    except OSError:
        pass


def _seed_files(env: Any) -> None:
    known = ledger.read(env)
    for path in owned_files(env):
        if f"file:{path}" in known or not path.is_file():
            continue
        text = path.read_text()
        if text.startswith(MANAGED_HEADER):
            ledger.record(env, f"file:{path}", "file", {"path": str(path)}, {path: text})


def _file_restore(env: Any, rec: dict[str, Any]) -> str:
    out = []
    for path, want in (rec.get("files") or {}).items():
        p = Path(path)
        if env.dry_run:
            out.append(f"dry run: would rewrite {p}")
            continue
        ha_guard._write(p, str(want.get("text") or ""), 0o644)
        out.append(f"{p} rewritten")
    if any(str(Path(env.paths.systemd_dir)) in p for p in rec.get("files") or {}):
        env.services.daemon_reload()
    return "\n".join(out)


def _file_adopt(env: Any, key: str, rec: dict[str, Any]) -> str:
    path = Path((rec.get("state") or {}).get("path") or key.removeprefix("file:"))
    if not path.is_file():
        ledger.update(env, {key: None})
        return f"{path} is gone: no longer tracked"
    record_file(env, path)
    return f"{path}: the node's content is now Pelagos's"


# Audit and plans ---------------------------------------------------------------------------------


def _label(key: str, rec: dict[str, Any]) -> dict[str, Any]:
    state = rec.get("state") or {}
    if key == ha_guard.KEY:
        return msg("drift.object.ha_guard", table=f"inet {ha_listener.GUARD_TABLE}")
    if rec.get("kind") == "kea_ha":
        return msg("drift.object.kea_ha", engine=str(state.get("engine")), server=str(state.get("server")))
    return msg("drift.object.file", path=str(state.get("path") or key.removeprefix("file:")))


def _finding(key: str, rec: dict[str, Any], differences: list[str], actions: list[str]) -> Any:
    from pelagos.domain import Severity
    from pelagos.installer.security_audit import Finding, finding_id

    label = _label(key, rec)
    engine = "kea"
    return Finding.of(
        finding_id(engine, KIND, key),
        KIND,
        Severity.WARNING,
        engine,
        key,
        msg("finding.managed_drift.description", object=label, differences=join(differences, "; ")),
        msg("finding.managed_drift.proposal", object=label),
        msg("finding.managed_drift.risk"),
        {
            "remediation": "drift",
            "object": key,
            "object_kind": rec.get("kind"),
            "differences": differences,
            "actions": actions,
        },
    )


def audit(env: Any) -> list[Any]:
    """Drift findings of this node; records what it sees for the first time (see the module doc)."""
    out = ha_guard.findings(env)
    if not getattr(env, "dry_run", False):
        _seed_guard(env)
        _seed_files(env)
    for key, rec, state in _track_ha(env):
        if state is None:
            out.append(_finding(key, rec, ["the relationship is no longer in the configuration"], ["adopt"]))
        else:
            want = {k: v for k, v in (rec.get("state") or {}).items() if k in ("relationship", "peers")}
            out.append(_finding(key, rec, ha_differences(want, state), list(ACTIONS)))
    for key, rec in sorted(ledger.read(env).items()):
        if rec.get("kind") == "ha_guard":
            diffs = guard_differences(env, rec)
        elif rec.get("kind") == "file":
            diffs = ledger.file_differences(rec)
        else:
            continue
        if diffs:
            out.append(_finding(key, rec, diffs, list(ACTIONS)))
    return out


def split_choice(fid: str) -> tuple[str, str | None]:
    """`<finding id>#adopt` or `#restore` selects the drift action; any other id is unchanged."""
    base, sep, action = fid.rpartition("#")
    return (base, action) if sep and action in ACTIONS else (fid, None)


def remediate(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    key = str(d.get("object"))
    action = d.get("action") or "restore"
    if action not in d.get("actions", ACTIONS):
        raise RuntimeError(f"{action} is not possible for {key}")
    rec = ledger.get(env, key)
    if rec is None:
        return f"{key} is not tracked any more"
    kind = rec.get("kind")
    if kind == "ha_guard":
        return _guard_restore(env, rec) if action == "restore" else _guard_adopt(env, rec)
    if kind == "kea_ha":
        return _ha_restore(env, key, rec) if action == "restore" else _ha_adopt(env, key)
    if kind == "file":
        return _file_restore(env, rec) if action == "restore" else _file_adopt(env, key, rec)
    raise RuntimeError(f"unknown managed object {key}")
