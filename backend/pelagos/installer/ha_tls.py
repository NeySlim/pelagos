# SPDX-License-Identifier: Apache-2.0
"""The TLS step of the Kea HA listener remediation, and the renewal of the HA certificates.

One plan covers every Pelagos node of the HA relationships of this node (kea4 and kea6, backups
included). Each node gets one certificate from the cluster CA (EC P-256, its HA URL addresses as
SANs, serverAuth and clientAuth) in the Kea configuration directory (`tls/`, root:<kea group>, key
0640), or at the paths its configuration already names. Then the non-primary peers switch (TLS files
in the relationship, https URLs, require-client-certs), the primaries right after, and every node
waits for status-get to show its relationships back in their normal state. When the configuration
already is TLS, the same plan renews: new files at the same paths, one reload at a time, each peer
checked before the next. A failed switch or check runs the undo step on every node (previous files
and configuration back, then a reload).
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import time
from pathlib import Path
from typing import Any

from pelagos.core import ca as ca_mod
from pelagos.core import kea_ha_tls as kt
from pelagos.domain import ChangeOp, Engine, Plan, PlanScope, PlanState, messages
from pelagos.domain.plan import Change
from pelagos.installer import keaconf, keasetup

# status-get states in which a server does what its role expects (as connectors.kea.ha).
NORMAL_STATES = frozenset({"hot-standby", "load-balancing", "passive-backup", "backup"})
# require-client-certs exists since Kea 2.1.7 (ARM hooks-ha.rst "HTTPS Support").
SERVER_TLS_SINCE = (2, 1, 7)
POLL_SECONDS = 2.0


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def _configs(env: Any) -> dict[str, tuple[Path, dict[str, Any]]]:
    out = {}
    for engine in ("kea4", "kea6"):
        conf = env.paths.kea_conf(keasetup.DAEMONS[engine])
        try:
            out[engine] = (conf, keaconf.loads(conf.read_text(), str(conf)))
        except (OSError, keaconf.KeaConfigError):
            continue
    return out


def _ca_pem(env: Any) -> bytes:
    path = env.node_paths.pki_dir / "ca.crt"
    try:
        return path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"cluster CA certificate {path} unreadable: {exc}") from None


def _ca_pair(env: Any) -> ca_mod.KeyPair | None:
    key = env.node_paths.pki_dir / "ca.key"
    return ca_mod.KeyPair(key.read_bytes(), _ca_pem(env)) if key.is_file() else None


# Plan --------------------------------------------------------------------------------------------


def _node_for(peer: kt.HAPeerURL, nodes: list[dict[str, Any]]) -> dict[str, Any] | None:
    by_host = [n for n in nodes if peer.host and peer.host in (n.get("hosts") or [])]
    if len(by_host) == 1:
        return by_host[0]
    by_name = [n for n in nodes if n.get("name") == peer.name]
    return by_name[0] if len(by_name) == 1 else None


def plan_targets(
    env: Any, nodes: list[dict[str, Any]]
) -> tuple[dict[str, dict[str, Any]], list[kt.Relationship], str]:
    """{node id: {name, engines: {engine: [servers]}, hosts, primary}}, this node's relationships and
    the mode ("enable" or "renew"). ValueError with the reason when Pelagos cannot do it."""
    rels = [r for engine, (_c, cfg) in _configs(env).items() for r in kt.relationships(engine, cfg)]
    if not rels:
        raise ValueError("no Kea HA relationship on this node")
    for rel in rels:
        version = env.t.kea_version(keasetup.DAEMONS[rel.engine])
        if version and keaconf.version_tuple(version) < SERVER_TLS_SINCE:
            raise ValueError(f"Kea {version} has no TLS on the HA listener (2.1.7 or later)")
        if not rel.dedicated:
            raise ValueError(
                f"{rel.engine} HA {rel.server} goes through kea-ctrl-agent: set TLS there by hand"
            )
        if rel.me is None:
            raise ValueError(f"{rel.engine}: this-server-name {rel.server} is not among the peers")
    if _ca_pair(env) is None:
        raise ValueError(
            "this node does not hold the cluster CA key: plan the HA TLS step on a node that does"
        )
    me = next((n for n in nodes if n.get("id") == env.node_id), {"id": env.node_id, "name": env.node_id})
    targets: dict[str, dict[str, Any]] = {}
    for rel in rels:
        for peer in rel.peers:
            node = me if peer.name == rel.server else _node_for(peer, nodes)
            if node is None:
                raise ValueError(
                    f"{rel.engine} HA peer {peer.name} ({peer.url}) is not a node of this cluster: "
                    "both ends of the TLS link need Pelagos"
                )
            if not peer.host:
                raise ValueError(f"{rel.engine} HA peer {peer.name}: no address in {peer.url}")
            t = targets.setdefault(
                node["id"],
                {"name": node.get("name") or node["id"], "engines": {}, "hosts": [], "primary": False},
            )
            servers = t["engines"].setdefault(rel.engine, [])
            if peer.name not in servers:
                servers.append(peer.name)
            if peer.host not in t["hosts"]:
                t["hosts"].append(peer.host)
            t["primary"] = t["primary"] or peer.role == "primary"
    if len(targets) < 2:
        raise ValueError("the HA peers all map to this node: nothing to secure between nodes")
    ca_pem = _ca_pem(env)
    renew = all(r.full and r.trust_anchor and kt.anchor_has(r.trust_anchor, ca_pem) for r in rels)
    return targets, rels, "renew" if renew else "enable"


def build_plan(env: Any, nodes: list[dict[str, Any]], created_by: str = "") -> Plan:
    """The coordinated TLS switch (or renewal) for every node of this node's HA relationships."""
    targets, rels, mode = plan_targets(env, nodes)
    order = sorted(targets, key=lambda n: (n != env.node_id, targets[n]["name"]))
    standby = [n for n in order if not targets[n]["primary"]]
    primary = [n for n in order if targets[n]["primary"]]
    verify_each = mode == "renew"
    changes: list[Change] = []

    def add(step: str, node_id: str, summary: str) -> None:
        t = targets[node_id]
        details = {
            "remediation": "ha_tls",
            "mode": mode,
            "engines": t["engines"],
            "hosts": t["hosts"],
            "node_name": t["name"],
            "verify_each": verify_each,
        }
        changes.append(
            Change(
                ChangeOp.REPLACE,
                f"security/ha-tls/{step}/{node_id}",
                before={"mode": mode},
                after={
                    "step": step,
                    "details": details,
                    "summary": f"{t['name']}: {summary}",
                    "manual": False,
                },
                node_ids=[node_id],
            )
        )

    for n in order:
        hosts = ", ".join(targets[n]["hosts"])
        add(kt.DEPOSIT, n, f"certificate from the cluster CA for {hosts} in the Kea TLS directory")
    switch = (
        "reload with the new certificate"
        if mode == "renew"
        else "switch the HA to TLS (https, client certificates)"
    )
    for n in standby:
        add(kt.STANDBY, n, switch + (", then wait for the normal state" if verify_each else ""))
    for n in primary:
        add(kt.PRIMARY, n, switch + (", then wait for the normal state" if verify_each else ""))
    for n in order:
        add(kt.VERIFY, n, "wait until status-get shows every HA relationship in its normal state")
    for n in order:
        add(kt.UNDO, n, "only if a switch or check fails: previous files and configuration back")
    engines = sorted({r.engine for r in rels})
    summary = messages.msg(f"plan.ha_tls.{mode}", engines=", ".join(engines))
    return Plan(
        scope=PlanScope.SECURITY,
        node_id=env.node_id,
        engine=Engine.KEA4 if "kea4" in engines else Engine.KEA6,
        summary=messages.render(summary),
        summary_message=summary,
        created_by=created_by,
        changes=changes,
        diff="\n".join(f"~ {c.target}: {c.after['summary']}" for c in changes),
        target_node_ids=sorted(targets),
        requires_confirmation=True,
        state=PlanState.VALIDATED,
    )


def issue_for(ca: ca_mod.KeyPair, details: dict[str, Any]) -> ca_mod.KeyPair:
    """The coordinator's certificate for one node of the plan (sealed in that node's deposit step)."""
    return ca_mod.issue_service(
        ca, f"kea-ha {details.get('node_name') or ''}".strip(), list(details["hosts"])
    )


# Steps on each node ------------------------------------------------------------------------------


def _local(
    env: Any, details: dict[str, Any]
) -> dict[str, tuple[Path, dict[str, Any], list[kt.Relationship]]]:
    """This node's configuration for the engines of the step; refuses servers it does not run."""
    configs = _configs(env)
    out = {}
    for engine, servers in (details.get("engines") or {}).items():
        if engine not in ("kea4", "kea6") or engine not in configs:
            raise RuntimeError(f"{engine}: no configuration on this node")
        conf, cfg = configs[engine]
        rels = [r for r in kt.relationships(engine, cfg) if r.server in servers]
        if not rels:
            raise RuntimeError(f"{engine}: this node runs none of the HA servers {', '.join(servers)}")
        out[engine] = (conf, cfg, rels)
    return out


def _tls_dir(env: Any) -> Path:
    return env.paths.kea_conf_dir / kt.TLS_DIR


def _usable(env: Any, conf: Path, path: str | None) -> bool:
    return bool(path) and keasetup.confined(env, conf, Path(str(path))) is None


def chosen_files(env: Any, conf: Path, rel: kt.Relationship, ca_pem: bytes) -> tuple[str, str, str]:
    """(trust-anchor, cert-file, key-file) for `rel`: the paths it names when Pelagos may write them
    (inside the Kea directories), else tls/<server>.crt and .key; the trust anchor it names when that
    file already holds the cluster CA, else tls/ca.crt."""
    d = _tls_dir(env)
    if (
        _usable(env, conf, rel.cert_file)
        and _usable(env, conf, rel.key_file)
        and rel.cert_file != rel.key_file
    ):
        cert, key = str(rel.cert_file), str(rel.key_file)
    else:
        cert, key = str(d / f"{rel.server}.crt"), str(d / f"{rel.server}.key")
    anchor = rel.trust_anchor
    if not (anchor and not Path(anchor).is_dir() and kt.anchor_has(anchor, ca_pem)):
        anchor = str(d / kt.CA_FILE)
    return anchor, cert, key


def _undo_dir(env: Any, ctx: dict[str, Any]) -> Path:
    return env.backup_root / "ha-tls" / str(ctx.get("plan_id") or "current")


UNDO_KEEP_SECONDS = 7 * 86400


def _prune(env: Any) -> None:
    """Undo copies of plans older than a week go (they hold previous private keys)."""
    root = env.backup_root / "ha-tls"
    if not root.is_dir():
        return
    now = time.time()
    for old in root.iterdir():
        try:
            if now - old.stat().st_mtime > UNDO_KEEP_SECONDS:
                shutil.rmtree(old, ignore_errors=True)
        except OSError:
            pass


def _remember(env: Any, ctx: dict[str, Any], name: str, path: Path) -> None:
    """Keeps what `path` holds before the plan first touches it (None when it did not exist)."""
    d = _undo_dir(env, ctx)
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    index = d / f"{name}.json"
    saved = json.loads(index.read_text()) if index.exists() else {}
    if str(path) in saved:
        return
    try:
        st = os.stat(path)
        saved[str(path)] = {
            "data": base64.b64encode(path.read_bytes()).decode(),
            "mode": st.st_mode & 0o7777,
            "gid": st.st_gid,
        }
    except FileNotFoundError:
        saved[str(path)] = None
    tmp = index.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(saved, fh)
    os.replace(tmp, index)


def _write(env: Any, path: Path, data: bytes, mode: int) -> None:
    group = env.file_group(env.paths.kea_group)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent == _tls_dir(env):
        os.chmod(path.parent, 0o750)  # noqa: S103 - the Kea group reads the certificates
        if group:
            shutil.chown(path.parent, "root", group)
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(tmp, mode)
    if group:
        shutil.chown(tmp, "root", group)
    os.replace(tmp, path)
    env.relabel([path])


def _material(env: Any, after: dict[str, Any], ctx: dict[str, Any], hosts: list[str]) -> ca_mod.KeyPair:
    """The sealed key and certificate the coordinator sent, else one issued here with the CA key."""
    key = (ctx.get("secrets") or {}).get(kt.KEY_SECRET)
    cert = after.get("cert_pem")
    if key and cert:
        return ca_mod.KeyPair(str(key).encode(), str(cert).encode())
    pair = _ca_pair(env)
    if pair is None:
        raise RuntimeError("no certificate was sent with this step and this node holds no CA key")
    return ca_mod.issue_service(pair, f"kea-ha {after['details'].get('node_name') or ''}".strip(), hosts)


def _check_material(pair: ca_mod.KeyPair, ca_pem: bytes, hosts: list[str]) -> None:
    if not ca_mod.signed_by(pair.cert_pem, ca_pem):
        raise RuntimeError("the certificate is not signed by this cluster's CA")
    if not ca_mod.key_matches(pair.key_pem, pair.cert_pem):
        raise RuntimeError("the key does not match the certificate")
    from cryptography import x509

    san = kt.cert_facts(x509.load_pem_x509_certificate(pair.cert_pem))["san"]
    missing = [h for h in hosts if h not in san]
    if missing:
        raise RuntimeError(f"the certificate does not name {', '.join(missing)} (HA URL of this node)")


def deposit(env: Any, after: dict[str, Any], ctx: dict[str, Any]) -> str:
    """Writes the cluster CA, this node's certificate and key where its relationships will read them."""
    local = _local(env, after["details"])
    hosts = list(dict.fromkeys(h for _c, _cfg, rels in local.values() for r in rels for h in r.my_hosts))
    hosts = list(dict.fromkeys([*hosts, *(after["details"].get("hosts") or [])]))
    ca_pem = _ca_pem(env)
    pair = _material(env, after, ctx, hosts)
    _check_material(pair, ca_pem, [h for _c, _cfg, rels in local.values() for r in rels for h in r.my_hosts])
    writes: dict[Path, tuple[bytes, int]] = {}
    for conf, _cfg, rels in local.values():
        for rel in rels:
            anchor, cert, key = chosen_files(env, conf, rel, ca_pem)
            if not kt.anchor_has(anchor, ca_pem):
                writes[Path(anchor)] = (ca_pem, 0o644)
            writes[Path(cert)] = (pair.cert_pem, 0o644)
            writes[Path(key)] = (pair.key_pem, 0o640)
    if env.dry_run:
        return "dry run: would write " + ", ".join(str(p) for p in writes)
    _prune(env)
    for path in writes:
        _remember(env, ctx, "files", path)
    for path, (data, mode) in writes.items():
        _write(env, path, data, mode)
    end = ca_mod.cert_not_after(pair.cert_pem).date().isoformat()
    return f"{', '.join(str(p) for p in writes)} written (certificate for {', '.join(hosts)}, until {end})"


def _reload(env: Any, engine: str, conf: Path) -> str:
    unit = env.kea_unit(engine)
    if not env.services.is_active(unit):
        return f"{unit} not running: reload skipped"
    answer = env.t.kea_command(keasetup.socket_path(env, engine, conf), "config-reload")
    if answer.get("result") != 0:
        raise RuntimeError(f"{engine} config-reload failed: {answer.get('text', answer)}")
    keasetup._mark_written(env, engine)
    return f"{unit}: configuration reloaded (config-reload)"


def switch(env: Any, after: dict[str, Any], ctx: dict[str, Any]) -> str:
    """TLS in every relationship of the step (or, when it already is, a reload for the new files)."""
    local = _local(env, after["details"])
    ca_pem = _ca_pem(env)
    out = []
    for engine, (conf, cfg, rels) in local.items():
        files = {(r.hook_index, r.rel_index): chosen_files(env, conf, r, ca_pem) for r in rels}
        new, changed = kt.with_tls(cfg, files)
        if env.dry_run:
            out.append(f"dry run: {engine} {'switched to TLS' if changed else 'reloaded'}")
            continue
        if changed:
            edited = keasetup.edited_files(conf, new)
            for path in edited:
                _remember(env, ctx, "config", Path(path))
            out.append(
                keasetup.write_files(env, engine, conf, edited, f"security-ha-tls-{engine}", restart=False)
            )
        else:
            out.append(_reload(env, engine, conf))
    if after["details"].get("verify_each") and not env.dry_run:
        out.append(verify(env, after, ctx))
    return "\n".join(out)


def _timeout(rels: list[tuple[dict[str, Any], kt.Relationship]]) -> float:
    longest = 0.0
    for raw, _rel in rels:
        heartbeat = float(raw.get("heartbeat-delay", 10000) or 10000) / 1000
        response = float(raw.get("max-response-delay", 60000) or 60000) / 1000
        longest = max(longest, response + 3 * heartbeat)
    return min(240.0, max(60.0, longest))


def _normal(entry: dict[str, Any]) -> str | None:
    """None when this relationship serves normally, else what is wrong."""
    servers = entry.get("ha-servers") or {}
    local = servers.get("local") or {}
    state = local.get("state")
    if state not in NORMAL_STATES:
        return f"{local.get('server-name')} is {state}"
    remote = servers.get("remote")
    if state == "backup" or not isinstance(remote, dict) or not remote:
        return None
    if remote.get("in-touch") is not True or remote.get("communication-interrupted"):
        return f"{local.get('server-name')} has no contact with {remote.get('server-name')}"
    if remote.get("last-state") not in NORMAL_STATES:
        return f"{remote.get('server-name')} is {remote.get('last-state')}"
    return None


def verify(env: Any, after: dict[str, Any], ctx: dict[str, Any]) -> str:
    """Waits until status-get shows every relationship of the step in its normal state, twice in a row."""
    local = _local(env, after["details"])
    raw_rels = []
    for _engine, (_conf, cfg, rels) in local.items():
        body = cfg[kt.root_of(cfg) or "Dhcp4"]
        entries = kt._ha_entries(body)
        for rel in rels:
            raw = next(r for hi, ri, r in entries if (hi, ri) == (rel.hook_index, rel.rel_index))
            raw_rels.append((raw, rel))
    timeout = _timeout(raw_rels)
    deadline = time.monotonic() + timeout
    good = 0
    problem = "no answer yet"
    while True:
        problems = []
        for engine, (conf, _cfg, rels) in local.items():
            unit = env.kea_unit(engine)
            if not env.services.is_active(unit):
                problems.append(f"{unit} is not running")
                continue
            try:
                answer = env.t.kea_command(keasetup.socket_path(env, engine, conf), "status-get")
            except (OSError, ValueError) as exc:
                problems.append(f"{engine} status-get: {exc}")
                continue
            entries = (answer.get("arguments") or {}).get("high-availability") or []
            servers = {r.server for r in rels}
            mine = [
                e
                for e in entries
                if isinstance(e, dict)
                and ((e.get("ha-servers") or {}).get("local") or {}).get("server-name") in servers
            ]
            if len(mine) < len(servers):
                problems.append(f"{engine}: status-get lists {len(mine)} of {len(servers)} relationships")
            problems += [f"{engine}: {p}" for e in mine if (p := _normal(e))]
        if not problems:
            good += 1
            if good >= 2:
                return "HA back in its normal state: " + ", ".join(
                    f"{e} {r.server}" for e, (_c, _cfg, rels) in local.items() for r in rels
                )
        else:
            good = 0
            problem = "; ".join(problems)
        if time.monotonic() >= deadline:
            raise RuntimeError(f"HA not back in its normal state within {timeout:.0f}s: {problem}")
        _sleep(POLL_SECONDS)


def undo(env: Any, after: dict[str, Any], ctx: dict[str, Any]) -> str:
    """Puts back the files and configuration this plan replaced on this node, then reloads Kea."""
    d = _undo_dir(env, ctx)
    out = []
    for name in ("files", "config"):
        index = d / f"{name}.json"
        if not index.exists():
            continue
        for path_text, saved in json.loads(index.read_text()).items():
            path = Path(path_text)
            if saved is None:
                path.unlink(missing_ok=True)
                out.append(f"{path} removed")
                continue
            _write(env, path, base64.b64decode(saved["data"]), int(saved["mode"]))
            try:
                os.chown(path, 0, int(saved["gid"]))
            except OSError:
                pass
            out.append(f"{path} restored")
    if not out:
        return "nothing to undo on this node"
    configs = _configs(env)
    for engine in after["details"].get("engines") or {}:
        if engine in configs:
            ok, output = env.t.kea_test(keasetup.DAEMONS[engine], configs[engine][0])
            if not ok:
                raise RuntimeError(f"{engine}: restored configuration rejected: {output}")
            out.append(_reload(env, engine, configs[engine][0]))
    shutil.rmtree(d, ignore_errors=True)
    return "\n".join(out)


STEP_FUNCTIONS = {
    kt.DEPOSIT: deposit,
    kt.STANDBY: switch,
    kt.PRIMARY: switch,
    kt.VERIFY: verify,
    kt.UNDO: undo,
}
