# SPDX-License-Identifier: Apache-2.0
"""Helper steps of the Kea 3.x migration that change a node (architecture section 28, batches K4, K5).

Time 1 (design 13.4 decision 5): the primary's converted files checked on the primary with the
daemons of its prepared packages, `ha-maintenance-start` on it, Kea stopped on the standby, the
target packages installed from the cache prepared earlier, the converted files put in place and
checked by the installed daemons.
Time 2: the primary stops and leaves a compacted copy of its lease files, which replaces the
standby's. Time 3: the detection delays shortened for the window are put back.
The return puts the exact 2.6 packages, the saved files, the AppArmor profiles, the dpkg stat
overrides, the directory modes and the unit states back, part by part, then starts what ran before.
Reconcile (`kea-mig-check`, `kea-mig-cleanup`) reads a node back and removes the leftovers.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import shutil
import stat
import tempfile
import time
from pathlib import Path
from typing import Any

from pelagos.connectors.kea import migration as mig
from pelagos.core import ha_maintenance
from pelagos.core import kea_migration as kmc
from pelagos.installer import ha_tls, keaconf, keasetup
from pelagos.installer import kea_migration as km

STATE = "state.json"  # private/: what the switch changed, for the return
POLICY_RC = "usr/sbin/policy-rc.d"
POLICY_MARK = "# pelagos: Kea migration, no service starts while packages change\n"
KEA_DIRS = ("etc/kea", "var/lib/kea", "var/log/kea", "run/kea")
HA_ENGINES = ("kea4", "kea6")
TLS_KEYS = ("trust-anchor", "cert-file", "key-file")
MAINTENANCE_STATES = frozenset({"partner-in-maintenance", "partner-down"})
START_WAIT = 30.0
# Copies dpkg and rpm leave beside a configuration file they did not overwrite.
PACKAGE_COPIES = (".dpkg-dist", ".dpkg-old", ".dpkg-new", ".rpmnew", ".rpmsave")
HA_WAIT_MIN, HA_WAIT_MAX = 120.0, 600.0
DELAY_KEYS = ("max-response-delay", "max-unacked-clients")
FAMILY_OF = {"kea4": "4", "kea6": "6"}
LEASE_HEADER = "address,"  # first column of both memfile formats


class SwitchError(RuntimeError):
    """A migration step failed; what it already changed is listed in the node's state for the return."""


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


# Node files ------------------------------------------------------------------------------------


def _mdir(env: Any, details: dict[str, Any]) -> Path:
    """Root's directory of the migration (kmc.state_dir), with its manifest."""
    mdir = kmc.state_dir(env.node_paths, str(details.get("migration_id") or ""))
    if not (mdir / "manifest.json").is_file():
        raise SwitchError(f"{mdir} has no manifest: prepare this node again")
    return mdir


def _public(env: Any, details: dict[str, Any]) -> Path:
    """The service user's directory of the migration: lease copies only, never trusted."""
    return kmc.migration_dir(env.node_paths.var, str(details.get("migration_id") or ""))


def _inside(path: Any, top: Path) -> Path:
    p = Path(str(path or ""))
    if not p.is_absolute() or ".." in p.parts or not p.is_relative_to(top) or p == top:
        raise SwitchError(f"the manifest names {path!r} outside {top}: prepare this node again")
    return p


def _manifest(env: Any, mdir: Path) -> dict[str, Any]:
    """The manifest the prepare step wrote, every name and destination in it checked: package and
    converted files are bare names, every file it puts back or writes is under the Kea directory."""
    from pelagos.installer.kea_migration_steps import bare_name, repo_files

    try:
        data = json.loads((mdir / "manifest.json").read_text())
    except (OSError, ValueError) as exc:
        raise SwitchError(f"the manifest of this node is unreadable ({exc}): prepare it again") from None
    if not isinstance(data, dict):
        raise SwitchError("the manifest of this node is not an object: prepare it again")
    conf_dir = env.paths.kea_conf_dir
    conv = data.get("converted") or {}
    try:
        for key in ("packages_before", "packages_target", "target_files"):
            for item in data.get(key) or []:
                bare_name(item.get("file"))
        for item in [*(conv.get("files") or []), *(conv.get("secrets") or [])]:
            bare_name(item.get("file"))
    except (ValueError, AttributeError) as exc:
        raise SwitchError(f"the manifest names a file outside its directory ({exc}): prepare again") from None
    for item in [*(conv.get("files") or []), *(conv.get("secrets") or []), *(data.get("saved") or [])]:
        _inside(item.get("path"), conf_dir)
    allowed = {str(f.path) for f in repo_files(env, str(data.get("series")), str(data.get("source")))}
    for name in data.get("repo_files_added") or []:
        if name not in allowed:
            raise SwitchError(f"the manifest names {name!r}, not a repository file of this migration")
    return data


def _checked_file(path: Path, sha256: Any) -> Path:
    """`path` as the prepare noted it (sum checked), else a SwitchError telling to prepare again."""
    from pelagos.installer.kea_migration_steps import _sha256

    if path.is_symlink() or not path.is_file():
        raise SwitchError(f"{path} is missing: prepare this node again")
    if not sha256 or _sha256(path) != sha256:
        raise SwitchError(f"{path} changed since the prepare: prepare this node again")
    return path


def check_packages(mdir: Path, manifest: dict[str, Any], directions: tuple[str, ...]) -> None:
    """The package files the next install needs are there with the sums the prepare noted; checked
    before any Kea stops, so a node whose files went away stops nothing."""
    if "previous" in directions:
        for p in manifest.get("packages_before") or []:
            _checked_file(mdir / "packages" / "previous" / p["file"], p.get("sha256"))
    if "target" in directions:
        for p in manifest.get("target_files") or manifest.get("packages_target") or []:
            _checked_file(mdir / "packages" / "target" / p["file"], p.get("sha256"))


def _state(mdir: Path) -> dict[str, Any]:
    try:
        data = json.loads((mdir / "private" / STATE).read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_state(mdir: Path, state: dict[str, Any]) -> None:
    from pelagos.installer.kea_migration_steps import _write

    _write(mdir / "private" / STATE, json.dumps(state, indent=2, sort_keys=True) + "\n")


def _remember(mdir: Path, key: str, value: Any) -> dict[str, Any]:
    """Records `key` once: a step run again (a resume, the return) keeps the first, pre-migration value."""
    state = _state(mdir)
    if key not in state:
        state[key] = value
        _save_state(mdir, state)
    return state


def _root(env: Any, path: str) -> Path:
    return Path(env.paths.root) / path.lstrip("/")


# Units -----------------------------------------------------------------------------------------


def kea_units(env: Any) -> list[str]:
    """Every Kea unit systemd knows here (any daemon, distro or ISC name) and kea-ctrl-agent."""
    names: list[str] = []
    for engine in km.DAEMONS:
        names += env.paths.kea_service_candidates(engine)
    names += list(km.CA_UNITS)
    return [u for u in dict.fromkeys(names) if env.services.exists(u)]


def stop(env: Any, details: dict[str, Any]) -> dict[str, Any]:
    """`kea-mig-stop`: every Kea unit of the node stopped (kea-ctrl-agent too); what was active and
    enabled before the migration is noted for the return."""
    mdir = _mdir(env, details)
    manifest = _manifest(env, mdir)
    back = details.get("phase") == kmc.ROLLBACK or "finished_at" in _state(mdir)
    check_packages(mdir, manifest, ("previous",) if back else ("previous", "target"))
    units = kea_units(env)
    before = {}
    for unit in units:
        active, enabled = env.services.unit_state(unit)
        before[unit] = {
            "active": active == "active",
            "enabled": enabled == "enabled",
            "enabled_state": enabled,
        }
    _remember(mdir, "units_before", before)
    stopped = []
    for unit in units:
        if env.services.is_active(unit):
            env.services.stop(unit)
            stopped.append(unit)
    running = [u for u in units if env.services.is_active(u)]
    if running:
        raise SwitchError(f"still running after the stop: {', '.join(running)}")
    out: dict[str, Any] = {"stopped": stopped}
    if details.get("export_leases"):
        engines = [e for e in details.get("engines") or [] if e in FAMILY_OF]
        out["leases"] = export_leases(env, mdir, str(details.get("migration_id")), engines)
    return out


# Lease files -------------------------------------------------------------------------------------


def lease_file(env: Any, engine: str) -> Path | None:
    """The memfile lease file of `engine` as its installed configuration names it; None when the
    leases are not kept in a file (another backend, `persist: false`)."""
    cfg = _load(env.paths.kea_conf(km.DAEMONS[engine]))
    db = (cfg.get(mig.ROOTS[engine]) or {}).get("lease-database") or {}
    if not isinstance(db, dict) or db.get("type", "memfile") != "memfile" or db.get("persist") is False:
        return None
    name = str(db.get("name") or f"kea-leases{FAMILY_OF[engine]}.csv")
    return _root(env, name) if posixpath.isabs(name) else env.paths.kea_lease_dir / name


def _lines(path: Path) -> list[str]:
    try:
        return path.read_text(errors="replace").splitlines(keepends=True)
    except FileNotFoundError:
        return []


def _concat(parts: list[Path], dest: Path) -> None:
    """The lease files in the order Kea loads them (`.2`, `.1`, the file), one header kept: a later
    line for an address wins, as when Kea reads them."""
    header: str | None = None
    with dest.open("w") as out:
        for part in parts:
            lines = _lines(part)
            if lines and lines[0].startswith(LEASE_HEADER):
                if header is None:
                    header = lines[0]
                    out.write(header)
                elif lines[0] != header:
                    raise SwitchError(f"{part} has another lease file format than {parts[0]}")
                lines = lines[1:]
            out.writelines(line if line.endswith("\n") else line + "\n" for line in lines)


def export_leases(env: Any, mdir: Path, migration_id: str, engines: list[str]) -> dict[str, Any]:
    """With Kea stopped: each lease file and its `.2` / `.1` leftovers compacted by kea-lfc (merged
    as Kea would read them when kea-lfc is missing), the result left at the copy the partner
    fetches (`leases<family>.csv`, 0600). Returns {family: {"sha256","size","source"}}."""

    out: dict[str, Any] = {}
    for engine in engines:
        path = lease_file(env, engine)
        family = FAMILY_OF[engine]
        if path is None:
            out[family] = {"skipped": "leases are not kept in a file"}
            continue
        parts = [p for p in (Path(f"{path}.2"), Path(f"{path}.1"), path) if p.is_file()]
        if not parts:
            out[family] = {"skipped": f"{path} does not exist"}
            continue
        work = mdir / "private" / f"lfc{family}"
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(mode=0o700, parents=True)
        merged = work / "input.csv"
        _concat(parts, merged)
        result = _lfc(env, family, work, merged) or merged
        copy = kmc.lease_copy_path(env.node_paths.var, migration_id, family)
        with result.open("rb") as src:
            data = src.read()
        _public_write(env, migration_id, copy.name, data)
        shutil.rmtree(work, ignore_errors=True)
        digest = hashlib.sha256(data).hexdigest()
        out[family] = {"sha256": digest, "size": len(data), "source": str(path)}
    return out


def _public_fd(env: Any, migration_id: str) -> int:
    """The service user's migration directory opened without following a link at any level."""
    fd = os.open(env.node_paths.var, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in (kmc.DIR, kmc.migration_dir(env.node_paths.var, migration_id).name):
            try:
                os.mkdir(name, 0o750, dir_fd=fd)
            except FileExistsError:
                pass
            nxt = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
    except OSError:
        os.close(fd)
        raise
    return fd


def _public_write(env: Any, migration_id: str, name: str, data: bytes) -> None:
    fd = _public_fd(env, migration_id)
    try:
        tmp = f".{name}.part"
        try:
            os.unlink(tmp, dir_fd=fd)
        except FileNotFoundError:
            pass
        out = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(out, "wb") as f:
            f.write(data)
        os.replace(tmp, name, src_dir_fd=fd, dst_dir_fd=fd)
    finally:
        os.close(fd)


def _public_read(env: Any, migration_id: str, name: str) -> bytes | None:
    """A file of the service user's migration directory, None when absent; a link is refused."""
    try:
        fd = _public_fd(env, migration_id)
    except OSError:
        return None
    try:
        try:
            f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise SwitchError(f"{name} cannot be read safely: {exc}") from None
        with os.fdopen(f, "rb") as src:
            if not stat.S_ISREG(os.fstat(src.fileno()).st_mode):
                raise SwitchError(f"{name} is not a regular file")
            return src.read()
    finally:
        os.close(fd)


def _lfc(env: Any, family: str, work: Path, merged: Path) -> Path | None:
    """kea-lfc over the merged file: it leaves the compacted leases in its `-x` file. None when the
    tool is missing or fails (the merged file is then the copy, which Kea loads the same way)."""
    binary = env.binary("kea-lfc")
    if not binary:
        return None
    prev = work / "previous.csv"
    argv = [binary, f"-{family}", "-x", str(prev), "-i", str(merged), "-o", str(work / "output.csv")]
    argv += ["-f", str(work / "finish.csv"), "-p", str(work / "lfc.pid"), "-c", str(work / "unused")]
    res = env.runner.run(argv, privileged=True, check=False, timeout=600)
    lines = _lines(prev) if res.ok else []
    return prev if lines and lines[0].startswith(LEASE_HEADER) else None


def received_meta(env: Any, migration_id: str, family: str) -> dict[str, Any]:
    try:
        raw = _public_read(env, migration_id, kmc.received_meta_name(family))
        data = json.loads(raw) if raw is not None else {}
    except (SwitchError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def leases_in(env: Any, details: dict[str, Any]) -> dict[str, Any]:
    """`kea-mig-leases-in`: the partner's lease copy fetched by this node's service (sum checked again
    against what the fetch noted) replaces this node's lease file and its `.1` / `.2` leftovers,
    which go to the migration's private directory. Kea must be stopped here."""
    mdir = _mdir(env, details)
    migration_id = str(details.get("migration_id") or "")
    _all_stopped(env)
    source = str(details.get("from_node") or "")
    engines = [e for e in details.get("engines") or [] if e in FAMILY_OF]
    families = [str(f) for f in details.get("families") or []]
    out: dict[str, Any] = {}
    for engine in engines:
        family = FAMILY_OF[engine]
        if family not in families:
            continue
        # Read once through a link-free path: what is checked is what is installed.
        data = _public_read(env, migration_id, kmc.received_name(family))
        meta = received_meta(env, migration_id, family)
        if data is None:
            if meta.get("skipped"):
                out[family] = {"skipped": meta["skipped"]}
                continue
            raise SwitchError(f"no lease copy for DHCPv{family} fetched from the partner")
        if meta.get("from_node") != source:
            raise SwitchError(f"the DHCPv{family} lease copy does not come from {source}")
        digest = hashlib.sha256(data).hexdigest()
        if digest != meta.get("sha256") or len(data) != meta.get("size"):
            raise SwitchError(f"the DHCPv{family} lease copy changed since it was fetched")
        if not data.startswith(LEASE_HEADER.encode()):
            raise SwitchError(f"the DHCPv{family} lease copy is not a Kea lease file")
        path = lease_file(env, engine)
        if path is None:
            raise SwitchError(f"{engine} keeps no lease file here: the partner's leases cannot be taken")
        path.parent.mkdir(parents=True, exist_ok=True)
        keep = mdir / "private" / f"leases{family}-before"
        keep.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            st = path.stat()
            mode, uid, gid = st.st_mode & 0o7777, st.st_uid, st.st_gid
        except OSError:
            st = path.parent.stat()
            mode, uid, gid = 0o644, st.st_uid, st.st_gid
        for old in (path, Path(f"{path}.1"), Path(f"{path}.2")):
            if old.is_file() and not (keep / old.name).exists():
                shutil.copy2(old, keep / old.name)
            if old != path and (old.is_file() or old.is_symlink()):
                old.unlink()
        _write_like(path, data, mode, uid, gid)
        env.relabel([path])
        out[family] = {"path": str(path), "sha256": digest, "size": len(data)}
    return {"leases": out}


def _wait_active(env: Any, engine: str, conf: Path, unit: str) -> str:
    deadline = time.monotonic() + START_WAIT
    sock = keasetup.socket_path(env, engine, conf)
    while True:
        if env.services.is_active(unit) and env.t.socket_alive(sock):
            return f"{unit} running"
        if time.monotonic() >= deadline:
            journal = ""
            try:
                journal = env.services.journal(unit, lines=15)
            except Exception:  # the journal only explains the failure
                journal = ""
            raise SwitchError(
                f"{unit} did not start or its control socket does not answer\n{journal}".strip()
            )
        _sleep(1.0)


def start(env: Any, details: dict[str, Any]) -> dict[str, Any]:
    """`kea-mig-start`: the daemons of `details.engines` enabled and started, each answering on its
    socket; with `details.restore` the units the stop step found active before the migration too."""
    engines = [e for e in details.get("engines") or [] if e in km.DAEMONS]
    out = []
    restore = {}
    if details.get("restore"):
        try:
            restore = _state(_mdir(env, details)).get("units_before") or {}
        except SwitchError:
            restore = {}
    for engine in engines:
        unit = env.kea_unit(engine)
        conf = env.paths.kea_conf(km.DAEMONS[engine])
        if env.services.is_active(unit):
            out.append(_wait_active(env, engine, conf, unit).replace("running", "already running"))
            continue
        env.runner.run(["systemctl", "reset-failed", unit], privileged=True, check=False, timeout=30)
        was = restore.get(unit)
        if was is not None and not was.get("enabled"):
            env.services.start(unit)
        else:
            env.services.enable_now(unit)
        out.append(_wait_active(env, engine, conf, unit))
    for unit, was in sorted(restore.items()):
        if not was.get("active") or not env.services.exists(unit) or env.services.is_active(unit):
            continue
        if was.get("enabled"):
            env.services.enable_now(unit)
        else:
            env.services.start(unit)
        out.append(f"{unit} started again")
    versions = {e: v for e in engines if (v := env.t.kea_version(km.DAEMONS[e]))}
    return {"started": out, "versions": versions}


# HA maintenance on the serving peer ------------------------------------------------------------


def _ha_engines(env: Any, engines: list[str]) -> dict[str, tuple[Path, list[str]]]:
    """engine -> (its file, its HA server names) for the daemons of `engines` with an HA hook."""
    out = {}
    for engine in HA_ENGINES:
        if engine not in engines:
            continue
        conf = env.paths.kea_conf(km.DAEMONS[engine])
        cfg = _load(conf)
        rels = mig.ha_relationships(cfg, engine)
        servers = [str(r.get("this-server-name")) for r in rels if r.get("this-server-name")]
        if servers:
            out[engine] = (conf, servers)
    return out


def _load(conf: Path) -> dict[str, Any]:
    """A Kea file as Kea reads it (comments allowed); {} when unreadable."""
    try:
        return keaconf.loads(conf.read_text(), str(conf))
    except (OSError, ValueError, keaconf.KeaConfigError):
        return {}


def _ha_status(env: Any, engine: str, conf: Path, servers: list[str]) -> list[dict[str, Any]]:
    answer = env.t.kea_command(keasetup.socket_path(env, engine, conf), "status-get")
    entries = (answer.get("arguments") or {}).get("high-availability") or []
    return [
        e
        for e in entries
        if isinstance(e, dict)
        and ((e.get("ha-servers") or {}).get("local") or {}).get("server-name") in servers
    ]


def _local_state(entry: dict[str, Any]) -> str:
    return str(((entry.get("ha-servers") or {}).get("local") or {}).get("state") or "")


def maintenance(env: Any, details: dict[str, Any], plan_id: str | None = None) -> dict[str, Any]:
    """`kea-mig-ha-maintenance` on the node that keeps serving. `start`: the pair must be in its
    normal state; `ha-maintenance-start` puts the partner in-maintenance and this node serves alone.
    `cancel`: `ha-maintenance-cancel` while the partner never went away, then a wait until the pair
    is back to its normal state (a partner that restarted negotiates by itself, ARM 2.6.3 hooks-ha)."""
    action = details.get("action")
    if action not in ("start", "cancel"):
        raise ValueError(f"unknown HA maintenance action {action!r}")
    found = _ha_engines(env, list(details.get("engines") or []))
    if not found:
        return {"engines": [], "note": "no HA relationship on this node: nothing to do"}
    out = {}
    for engine, (conf, servers) in found.items():
        entries = _ha_status(env, engine, conf, servers)
        states = sorted({_local_state(e) for e in entries})
        if action == "start":
            if states and set(states) <= MAINTENANCE_STATES:
                out[engine] = f"already serving alone ({', '.join(states)})"
            else:
                problems = [p for e in entries if (p := ha_tls._normal(e))]
                if problems or not entries:
                    why = "; ".join(problems) or "no answer"
                    raise SwitchError(f"{engine}: the HA pair is not in its normal state: {why}")
                sock = keasetup.socket_path(env, engine, conf)
                answer = env.t.kea_command(sock, "ha-maintenance-start")
                if answer.get("result") != 0:
                    raise SwitchError(f"{engine} ha-maintenance-start: {answer.get('text', answer)}")
                out[engine] = str(answer.get("text") or "maintenance started")
            ha_maintenance.record(env.node_paths, engine, "start", plan_id)
        else:
            if "partner-in-maintenance" in states:
                sock = keasetup.socket_path(env, engine, conf)
                answer = env.t.kea_command(sock, "ha-maintenance-cancel")
                if answer.get("result") != 0:
                    raise SwitchError(f"{engine} ha-maintenance-cancel: {answer.get('text', answer)}")
            out[engine] = wait_ha(env, engine, conf, servers)
            ha_maintenance.record(env.node_paths, engine, "cancel", plan_id)
    return {"engines": sorted(out), "ha": out}


def _ha_timeout(conf: Path, engine: str) -> float:
    cfg = _load(conf)
    longest = 0.0
    for rel in mig.ha_relationships(cfg, engine):
        heartbeat = float(rel.get("heartbeat-delay", 10000) or 10000) / 1000
        response = float(rel.get("max-response-delay", 60000) or 60000) / 1000
        longest = max(longest, response + 6 * heartbeat)
    return min(HA_WAIT_MAX, max(HA_WAIT_MIN, longest))


def wait_ha(env: Any, engine: str, conf: Path, servers: list[str]) -> str:
    """Until status-get shows every relationship of `servers` normal, twice in a row."""
    deadline = time.monotonic() + _ha_timeout(conf, engine)
    good, problem = 0, "no answer yet"
    while True:
        try:
            entries = _ha_status(env, engine, conf, servers)
            problems = [p for e in entries if (p := ha_tls._normal(e))]
            if len(entries) < len(servers):
                problems.append(f"status-get lists {len(entries)} of {len(servers)} relationships")
        except (OSError, ValueError) as exc:
            problems = [f"status-get: {exc}"]
        if not problems:
            good += 1
            if good >= 2:
                return "HA back in its normal state: " + ", ".join(sorted({_local_state(e) for e in entries}))
        else:
            good, problem = 0, "; ".join(problems)
        if time.monotonic() >= deadline:
            raise SwitchError(f"{engine}: HA not back in its normal state: {problem}")
        _sleep(ha_tls.POLL_SECONDS)


# Packages ----------------------------------------------------------------------------------------


class _NoStarts:
    """policy-rc.d answering 101 while dpkg runs: a package script starts no Kea daemon with files
    that are not yet the right ones. An administrator's own policy-rc.d is left alone."""

    def __init__(self, env: Any) -> None:
        self.path = _root(env, POLICY_RC)
        self.mine = False

    def __enter__(self) -> _NoStarts:
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text("#!/bin/sh\n" + POLICY_MARK + "exit 101\n")
            self.path.chmod(0o755)
            self.mine = True
        return self

    def __exit__(self, *_exc: Any) -> None:
        if self.mine:
            try:
                if POLICY_MARK in self.path.read_text():
                    self.path.unlink()
            except OSError:
                pass


def _statoverrides(env: Any) -> list[str]:
    if not env.distro.is_debian:
        return []
    res = env.runner.run(
        ["dpkg-statoverride", "--list"], privileged=True, check=False, mutates=False, timeout=60
    )
    return sorted(line.strip() for line in res.stdout.splitlines() if line.strip()) if res.ok else []


def _dir_modes(env: Any) -> dict[str, dict[str, int]]:
    out = {}
    for rel in KEA_DIRS:
        path = _root(env, rel)
        try:
            st = path.lstat()
        except OSError:
            continue
        out["/" + rel] = {"uid": st.st_uid, "gid": st.st_gid, "mode": st.st_mode & 0o7777}
    return out


def _apparmor_disabled(env: Any) -> list[str]:
    d = _root(env, "etc/apparmor.d/disable")
    return sorted(p.name for p in d.glob("usr.sbin.kea-*")) if d.is_dir() else []


def _apt(env: Any, args: list[str]) -> Any:
    argv = [
        "apt-get",
        "-y",
        "-q",
        "--no-download",
        "-o",
        "Dpkg::Options::=--force-confold",
        "-o",
        "Dpkg::Options::=--force-confdef",
        *args,
    ]
    with _NoStarts(env):
        return env.runner.run(argv, privileged=True, check=False, timeout=1800)


def _installed_match(env: Any, wanted: list[dict[str, str]], gone: list[str]) -> list[str]:
    """What differs from `wanted` (exact versions) and `gone` (absent) once the packages changed."""
    installed = km.installed_packages(env.runner, env.distro)
    wrong = [
        f"{p['name']} {installed.get(p['name'], 'absent')} instead of {p['version']}"
        for p in wanted
        if installed.get(p["name"]) != p["version"]
    ]
    wrong += [f"{name} still installed" for name in gone if name in installed]
    return wrong


def install_target_packages(env: Any, manifest: dict[str, Any], mdir: Path) -> str:
    target = manifest.get("packages_target") or []
    remove = [p["name"] for p in manifest.get("packages_remove") or [] if p.get("name")]
    target_names = {p["name"] for p in target}
    remove = [n for n in remove if n not in target_names]
    check_packages(mdir, manifest, ("target",))
    folder = mdir / "packages" / "target"
    if env.distro.is_debian:
        from pelagos.installer.kea_migration_steps import _mkdir, apt_archives

        _mkdir(folder / "partial")
        files = [str(folder / p["file"]) for p in target if p.get("file")]
        specs = files if len(files) == len(target) else [f"{p['name']}={p['version']}" for p in target]
        res = _apt(env, [*apt_archives(folder), "install", *specs, *(f"{n}-" for n in remove)])
    elif env.distro.is_rhel:
        files = [str(folder / p["file"]) for p in target]
        res = env.runner.run(
            ["dnf", "-y", "-q", "--allowerasing", "--disablerepo=*", "install", *files],
            privileged=True,
            check=False,
            timeout=1800,
        )
        installed = km.installed_packages(env.runner, env.distro)
        left = [n for n in remove if n in installed]
        if res.ok and left:
            res = env.runner.run(
                ["dnf", "-y", "-q", "remove", *left], privileged=True, check=False, timeout=900
            )
    else:
        raise SwitchError(f"no package manager for {env.distro.id}")
    if not res.ok:
        raise SwitchError(f"target packages not installed: {res.output.strip()[-600:]}")
    wrong = _installed_match(env, target, remove)
    if wrong:
        raise SwitchError("target packages not as prepared: " + "; ".join(wrong))
    return f"{len(target)} target packages installed, {len(remove)} removed"


def install_previous_packages(env: Any, manifest: dict[str, Any], mdir: Path) -> str:
    previous = manifest.get("packages_before") or []
    if not previous:
        raise SwitchError("the manifest lists no previous package: the return is impossible")
    keep = {p["name"] for p in previous}
    installed = km.installed_packages(env.runner, env.distro)
    extra = sorted(n for n in installed if n not in keep)
    check_packages(mdir, manifest, ("previous",))
    folder = mdir / "packages" / "previous"
    files = [folder / p["file"] for p in previous]
    if env.distro.is_debian:
        from pelagos.installer.kea_migration_steps import _mkdir, apt_archives

        # A local .deb whose version an index also lists is fetched from that index (lab 2026-10-30:
        # "Unable to fetch some archives" under --no-download): the kept files are apt's cache here.
        _mkdir(folder / "partial")
        res = _apt(
            env,
            [
                *apt_archives(folder),
                "--allow-downgrades",
                "install",
                *(str(f) for f in files),
                *(f"{n}-" for n in extra),
            ],
        )
    elif env.distro.is_rhel:
        res = env.runner.run(
            ["dnf", "-y", "-q", "--allowerasing", "--disablerepo=*", "install", *(str(f) for f in files)],
            privileged=True,
            check=False,
            timeout=1800,
        )
        left = sorted(n for n in km.installed_packages(env.runner, env.distro) if n not in keep)
        if res.ok and left:
            res = env.runner.run(
                ["dnf", "-y", "-q", "remove", *left], privileged=True, check=False, timeout=900
            )
    else:
        raise SwitchError(f"no package manager for {env.distro.id}")
    if not res.ok:
        raise SwitchError(f"previous packages not installed: {res.output.strip()[-600:]}")
    wanted = [{"name": p["name"], "version": p["version"]} for p in previous]
    wrong = _installed_match(env, wanted, extra)
    if wrong:
        raise SwitchError("previous packages not back: " + "; ".join(wrong))
    return f"{len(previous)} previous packages installed again, {len(extra)} removed"


# Files -----------------------------------------------------------------------------------------


def _write_like(path: Path, data: bytes, mode: int, uid: int | None, gid: int | None) -> None:
    tmp = path.with_name(f".{path.name}.pelagos-mig")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    if os.geteuid() == 0 and uid is not None and gid is not None:
        os.chown(tmp, uid, gid)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


with_standby_delays = km.with_standby_delays


def note_delays(mdir: Path, engine: str, cfg: dict[str, Any], original: bytes, shortened: bytes) -> None:
    """The detection delays of each relationship before they are shortened and the file as it was,
    for kea-mig-delays (which puts those bytes back while the file is still the shortened one)."""
    keep = mdir / "private" / f"delays-{engine}.conf"
    fd = os.open(keep, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(original)
    state = _state(mdir)
    saved = state.setdefault("delays", {})
    saved[engine] = {
        "relationships": {
            str(rel.get("this-server-name") or i): {k: rel.get(k) for k in DELAY_KEYS}
            for i, rel in enumerate(mig.ha_relationships(cfg, engine))
        },
        "file": keep.name,
        "shortened_sha256": hashlib.sha256(shortened).hexdigest(),
    }
    _save_state(mdir, state)


def shorten_files(env: Any, mdir: Path, engines: list[str], delay_ms: int) -> list[str]:
    """The installed files of `engines` with the short delays (the return of a migrated pair: the
    2.6 files just put back), originals noted for kea-mig-delays."""
    out = []
    for engine in [e for e in engines if e in HA_ENGINES]:
        conf = env.paths.kea_conf(km.DAEMONS[engine])
        cfg = _load(conf)
        if not mig.ha_relationships(cfg, engine):
            continue
        st = conf.stat()
        data = (json.dumps(with_standby_delays(cfg, engine, delay_ms), indent=2) + "\n").encode()
        note_delays(mdir, engine, cfg, conf.read_bytes(), data)
        _write_like(conf, data, st.st_mode & 0o7777, st.st_uid, st.st_gid)
        env.relabel([conf])
        out.append(f"{conf}: HA detection shortened to {delay_ms} ms for the window")
    return out


def put_target_files(
    env: Any, manifest: dict[str, Any], mdir: Path, short: bool, delay_ms: int | None
) -> list[str]:
    """The converted files in place (sums checked against the manifest), their secret files, the
    group write `config-write` needs; the node that must take over alone gets the short delays."""
    from pelagos.installer.kea_migration_steps import _sha256

    target = mdir / "private" / "target"
    conv = manifest.get("converted") or {}
    out = []
    for item in conv.get("secrets") or []:
        src = target / item["file"]
        if _sha256(src) != item["sha256"]:
            raise SwitchError(f"{src} changed since the prepare: prepare again")
        dest = Path(item["path"])
        if dest.parent == env.paths.kea_conf_dir / keasetup.D2_SECRET_SUBDIR:
            keasetup.ensure_d2_secret_dir(env)
        out.append(keasetup.write_secret_file(env, dest, src.read_text().rstrip("\n")))
    for item in conv.get("files") or []:
        src = target / item["file"]
        if _sha256(src) != item["sha256"]:
            raise SwitchError(f"{src} changed since the prepare: prepare again")
        engine = item["engine"]
        cfg = json.loads(src.read_text())
        dest = Path(item["path"])
        data = (json.dumps(cfg, indent=2) + "\n").encode()
        if short and engine in HA_ENGINES and delay_ms and mig.ha_relationships(cfg, engine):
            shortened = (json.dumps(with_standby_delays(cfg, engine, delay_ms), indent=2) + "\n").encode()
            note_delays(mdir, engine, cfg, data, shortened)
            data = shortened
        try:
            st = dest.stat()
            mode, uid, gid = st.st_mode & 0o7777, st.st_uid, st.st_gid
        except OSError:
            mode, uid, gid = 0o640, None, None
        _write_like(dest, data, mode, uid, gid)
        out.append(f"{dest} written (Kea {manifest.get('target_version')})")
        out.append(keasetup.ensure_config_writable(env, dest, km.DAEMONS[engine]))
        env.relabel([dest])
    return [o for o in out if o]


def restore_files(env: Any, manifest: dict[str, Any], mdir: Path) -> list[str]:
    """/etc/kea as the prepare saved it: content, owner, mode and links; the secret files the
    conversion added and that did not exist before are removed."""
    saved = manifest.get("saved") or []
    before = mdir / "private" / "before"
    conf_dir = env.paths.kea_conf_dir
    known = {e["path"] for e in saved}
    out = []
    for entry in sorted(saved, key=lambda e: e["path"].count("/")):
        path = Path(entry["path"])
        rel = path.relative_to(conf_dir)
        copy = before / rel
        uid, gid, mode = int(entry["uid"]), int(entry["gid"]), int(entry["mode"], 8)
        if "link" in entry:
            if path.is_symlink() and os.readlink(path) == entry["link"]:
                continue
            if path.exists() or path.is_symlink():
                path.unlink() if not path.is_dir() or path.is_symlink() else shutil.rmtree(path)
            os.symlink(entry["link"], path)
            out.append(f"{path} -> {entry['link']}")
        elif copy.is_dir() and not copy.is_symlink():
            path.mkdir(parents=True, exist_ok=True)
            if os.geteuid() == 0:
                os.chown(path, uid, gid)
            os.chmod(path, mode)
        elif copy.is_file():
            data = copy.read_bytes()
            current = path.read_bytes() if path.is_file() and not path.is_symlink() else None
            _write_like(path, data, mode, uid, gid)
            if current != data:
                out.append(f"{path} restored")
    for item in (manifest.get("converted") or {}).get("secrets") or []:
        path = Path(item["path"])
        if item["path"] not in known and (path.is_file() or path.is_symlink()):
            path.unlink()
            out.append(f"{path} removed (added by the conversion)")
    for leftover in sorted(conf_dir.rglob("*")):
        if leftover.suffix in PACKAGE_COPIES and str(leftover) not in known and leftover.is_file():
            leftover.unlink()
            out.append(f"{leftover} removed (left by the package manager)")
    # Anything else the prepare did not see (a key file the conversion added under another name):
    # moved aside, never deleted, so /etc/kea is exactly the saved tree.
    extra = mdir / "private" / "extra"
    for leftover in sorted(conf_dir.rglob("*"), key=lambda p: -len(p.parts)):
        if str(leftover) in known or (leftover.is_dir() and not leftover.is_symlink()):
            continue
        dest = extra / leftover.relative_to(conf_dir)
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.move(str(leftover), str(dest))
        out.append(f"{leftover} moved to {dest} (not there before the migration)")
    env.relabel([Path(e["path"]) for e in saved])
    return out


def remove_target_conffiles(env: Any, manifest: dict[str, Any]) -> list[str]:
    """Kea files the target packages brought into the configuration directory (dpkg keeps them for a
    removed package) and that the prepare did not save. The packages stay known as removed: purging
    isc-kea-common would delete /etc/kea and /var/lib/kea."""
    if not env.distro.is_debian:
        return []
    names = [p["name"] for p in manifest.get("packages_target") or [] if p.get("name")]
    if not names:
        return []
    res = env.runner.run(
        ["dpkg-query", "-W", "-f=${Conffiles}\n", *names],
        privileged=True,
        check=False,
        mutates=False,
        timeout=60,
    )
    saved = {e["path"] for e in manifest.get("saved") or []}
    conf_dir = env.paths.kea_conf_dir
    out = []
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2 or "obsolete" in parts[2:]:
            continue
        path = _root(env, parts[0])
        if str(path) in saved or not path.is_relative_to(conf_dir) or not path.is_file():
            continue
        path.unlink()
        out.append(f"{parts[0]} removed (a file of the target packages)")
    for top, dirs, _files in os.walk(conf_dir, topdown=False):
        for name in dirs:
            d = Path(top) / name
            if str(d) not in saved and not d.is_symlink() and not any(d.iterdir()):
                d.rmdir()
                out.append(f"{d} removed (an empty directory of the target packages)")
    return out


def check_files(env: Any, engines: list[str], test_flag: bool = True) -> list[str]:
    """Each daemon's file checked by the installed binary as the Kea user (`-T` loads the hooks and
    their files on kea-dhcp4/6 3.x, `-t` otherwise)."""
    out = []
    for engine in engines:
        daemon = km.DAEMONS[engine]
        conf = env.paths.kea_conf(daemon)
        flag = km.TEST_FLAG[engine] if test_flag else "-t"
        ok, output = _kea_check(env, daemon, conf, flag)
        if not ok:
            raise SwitchError(f"{daemon} {flag} refuses {conf}: {km.error_line(output)}")
        out.append(f"{daemon} {flag} {conf}: ok")
    return out


def _kea_check(env: Any, daemon: str, conf: Path, flag: str) -> tuple[bool, str]:
    binary = env.binary(daemon)
    if not binary:
        raise SwitchError(f"{daemon} is not installed")
    argv = [binary, flag, str(conf)]
    if env.runner.is_root and env.binary("runuser"):
        argv = ["runuser", "-u", env.paths.kea_user, "--", *argv]
    res = env.runner.run(argv, privileged=True, check=False, mutates=False, timeout=120)
    return res.ok, res.output


# AppArmor, stat overrides, directories ---------------------------------------------------------


def apparmor_active(env: Any) -> bool:
    """AppArmor enforces here: its securityfs is mounted (absent in many containers and some VMs)."""
    return _root(env, "sys/kernel/security/apparmor").is_dir()


def reenable_apparmor(env: Any, names: list[str]) -> list[str]:
    """The `disable/` links the target added removed; each profile loaded again when AppArmor runs
    (without it the link alone is what the next boot reads)."""
    out = []
    active = apparmor_active(env)
    for name in names:
        link = _root(env, "etc/apparmor.d/disable") / name
        profile = _root(env, "etc/apparmor.d") / name
        if link.is_symlink() or link.exists():
            link.unlink()
            out.append(f"{link} removed")
        if not profile.is_file():
            continue
        if not active:
            out.append(f"AppArmor profile {name}: not loaded, AppArmor is not active on this host")
            continue
        res = env.runner.run(
            ["apparmor_parser", "-r", str(profile)], privileged=True, check=False, timeout=60
        )
        if res.ok:
            out.append(f"AppArmor profile {name} enabled again")
        else:
            out.append(f"AppArmor profile {name}: apparmor_parser failed ({res.output.strip()[-200:]})")
    return out


def restore_units(env: Any, before: dict[str, Any]) -> list[str]:
    """Each Kea unit enabled or disabled as the first stop found it (a package script may have
    enabled one again, kea-dhcp6-server for instance); nothing starts here."""
    if not env.binary("systemctl") or not isinstance(before, dict):
        return []
    out = []
    for unit, was in sorted(before.items()):
        if not isinstance(was, dict) or not env.services.exists(unit):
            continue
        raw = str(was.get("enabled_state") or ("enabled" if was.get("enabled") else ""))
        _active, now = env.services.unit_state(unit)
        if raw == "enabled" and now != "enabled":
            verb = "enable"
        elif raw != "enabled" and now == "enabled" and (raw == "disabled" or not was.get("enabled")):
            verb = "disable"
        else:
            continue
        env.runner.run(["systemctl", verb, unit], privileged=True, check=False, timeout=60)
        out.append(f"{unit} {verb}d again (as before the migration)")
    return out


NOOP_POSTRM = "#!/bin/sh\n# pelagos: neutralized before the purge of a removed ISC package\nexit 0\n"
_ISC_PACKAGE = re.compile(r"^(python3-)?isc-kea(-|$)")


def purge_leftovers(env: Any) -> list[str]:
    """ISC Kea packages dpkg still knows as removed (`rc`) purged. Their purge scripts would delete
    /etc/kea, /var/lib/kea and the `_kea` user the Debian packages share, so they are replaced by a
    no-op first and /etc/kea is checked against a copy taken just before, kept in root's migration
    state directory (outside any migration, never under tmpfs) when the purge fails."""
    if not env.distro.is_debian:
        return []
    res = env.runner.run(
        [
            "dpkg-query",
            "-W",
            "-f=${Package}\t${db:Status-Abbrev}\t${Conffiles}\n",
            "isc-kea*",
            "python3-isc-kea*",
        ],
        privileged=True,
        check=False,
        mutates=False,
        timeout=60,
    )
    names, inits = [], []
    current = ""
    for line in res.stdout.splitlines():
        parts = line.split("\t")
        if not line.startswith(" ") and len(parts) >= 2:  # ${Conffiles} goes on, one per line
            current = parts[0] if parts[1].strip() == "rc" and _ISC_PACKAGE.match(parts[0]) else ""
            if current:
                names.append(current)
        if current:
            inits += [w.rsplit("/", 1)[1] for w in line.split() if w.startswith("/etc/init.d/")]
    if not names:
        return []
    conf_dir = env.paths.kea_conf_dir
    top = Path(env.node_paths.kea_migration_state)
    top.mkdir(mode=0o700, parents=True, exist_ok=True)
    guard = Path(tempfile.mkdtemp(prefix="purge-", dir=str(top)))
    copy = guard / "conf"
    out: list[str] = []
    failure = ""
    try:
        if conf_dir.is_dir():
            shutil.copytree(conf_dir, copy, symlinks=True)
        info = _root(env, "var/lib/dpkg/info")
        for name in names:
            for script in info.glob(f"{name}.postrm"), info.glob(f"{name}:*.postrm"):
                for path in script:
                    path.write_text(NOOP_POSTRM)
        got = env.runner.run(["dpkg", "--purge", *names], privileged=True, check=False, timeout=600)
        if not got.ok:
            failure = f"dpkg --purge {' '.join(names)}: {got.output.strip()[-300:]}"
        else:
            out.append(f"purged (removed ISC packages): {', '.join(names)}")
            for init in dict.fromkeys(inits):
                if not _root(env, f"etc/init.d/{init}").exists():
                    env.runner.run(
                        ["update-rc.d", "-f", init, "remove"], privileged=True, check=False, timeout=60
                    )
    except OSError as exc:
        failure = f"purge of {', '.join(names)}: {exc}"
    finally:
        # A failed purge may already have deleted conffiles at the Debian paths: put back either way.
        try:
            if copy.is_dir():
                out += _put_back(copy, conf_dir)
        except OSError as exc:
            failure = f"{failure + '; ' if failure else ''}{conf_dir} not put back: {exc}"
    if failure:
        # The copy is the only one left of /etc/kea before the purge: kept for a manual check.
        raise SwitchError(f"{failure} (copy of {conf_dir} before the purge kept in {copy})")
    shutil.rmtree(guard, ignore_errors=True)
    return out


def _put_back(copy: Path, conf_dir: Path) -> list[str]:
    """Each file of `copy` missing or different under `conf_dir` written back with its owner."""
    out = []
    for saved in sorted(copy.rglob("*")):
        dest = conf_dir / saved.relative_to(copy)
        if saved.is_symlink():
            if not dest.exists() and not dest.is_symlink():
                os.symlink(os.readlink(saved), dest)
            continue
        if saved.is_dir():
            if not dest.exists():
                dest.mkdir()
                shutil.copystat(saved, dest)
            continue
        if not dest.is_file() or dest.read_bytes() != saved.read_bytes():
            shutil.copy2(saved, dest)
            st = saved.stat()
            if os.geteuid() == 0:
                os.chown(dest, st.st_uid, st.st_gid)
            out.append(f"{dest} put back after the purge")
    return out


def restore_statoverrides(env: Any, before: list[str]) -> list[str]:
    """Stat overrides the target packages added are removed (Debian keeps its own modes)."""
    out = []
    for line in _statoverrides(env):
        if line in before:
            continue
        path = line.split()[-1]
        env.runner.run(["dpkg-statoverride", "--remove", path], privileged=True, check=False, timeout=60)
        out.append(f"dpkg-statoverride of {path} removed")
    return out


def restore_dirs(env: Any, modes: dict[str, dict[str, int]]) -> list[str]:
    out = []
    for path, m in sorted(modes.items()):
        target = _root(env, path)
        try:
            st = target.lstat()
        except OSError:
            continue
        if (st.st_uid, st.st_gid, st.st_mode & 0o7777) == (m["uid"], m["gid"], m["mode"]):
            continue
        if os.geteuid() == 0:
            os.chown(target, m["uid"], m["gid"], follow_symlinks=False)
        os.chmod(target, m["mode"])
        out.append(f"{path} back to {oct(m['mode'])[2:]} {m['uid']}:{m['gid']}")
    return out


def remove_repo_files(env: Any, manifest: dict[str, Any]) -> list[str]:
    out = []
    for name in manifest.get("repo_files_added") or []:
        path = _root(env, name)
        if path.is_file():
            path.unlink()
            out.append(f"{name} removed")
    return out


# The steps ---------------------------------------------------------------------------------------


def _all_stopped(env: Any) -> None:
    running = [u for u in kea_units(env) if env.services.is_active(u)]
    if running:
        raise SwitchError(f"Kea still runs here ({', '.join(running)}): the stop step comes first")


def install(env: Any, details: dict[str, Any]) -> dict[str, Any]:
    """`kea-mig-install`. `target`: the prepared packages from the cache (Debian Kea removed), the
    AppArmor profiles of the removed packages disabled, the converted files in place, each checked
    by the installed daemon; Kea stays stopped. `previous`: the exact 2.6 packages, files,
    profiles, stat overrides and directory modes back, checked by the 2.6 daemons."""
    direction = details.get("direction")
    mdir = _mdir(env, details)
    manifest = _manifest(env, mdir)
    _all_stopped(env)
    engines = [e for e in manifest.get("engines") or [] if e in km.DAEMONS]
    out: list[str] = []
    if direction == "target":
        _remember(mdir, "statoverrides", _statoverrides(env))
        _remember(mdir, "dirs", _dir_modes(env))
        already = set(_apparmor_disabled(env))
        out.append(install_target_packages(env, manifest, mdir))
        from pelagos.installer.install import disable_stale_apparmor

        out += disable_stale_apparmor(env)
        state = _state(mdir)
        added = sorted(set(state.get("apparmor_disabled") or []) | (set(_apparmor_disabled(env)) - already))
        state["apparmor_disabled"] = added
        _save_state(mdir, state)
        out += put_target_files(env, manifest, mdir, _short(details), _delay(details))
        env.services.daemon_reload()
        out += check_files(env, engines)
        version = manifest.get("target_version")
    elif direction == "previous":
        out, version = install_previous(env, manifest, mdir, details, engines)
    else:
        raise ValueError(f"unknown install direction {direction!r}")
    return {"direction": direction, "version": version, "log": out}


def install_previous(
    env: Any, manifest: dict[str, Any], mdir: Path, details: dict[str, Any], engines: list[str]
) -> tuple[list[str], str]:
    """The return of one node, in order: packages, files, directories, AppArmor, repository files,
    unit states, leftover ISC packages, then the 2.6 check. A part that fails does not stop the
    others (Kea is stopped, each part is safe alone); every failure is reported at the end."""
    state = _state(mdir)
    out: list[str] = []
    errors: list[str] = []

    def part(name: str, fn: Any) -> None:
        try:
            got = fn()
        except Exception as exc:
            errors.append(f"{name}: {str(exc)[-600:]}")
            out.append(f"FAILED {name}: {str(exc)[-600:]}")
            return
        out.extend([got] if isinstance(got, str) else list(got or []))

    if "statoverrides" in state:
        part("stat overrides", lambda: restore_statoverrides(env, state.get("statoverrides") or []))
    part("packages", lambda: install_previous_packages(env, manifest, mdir))
    part("files", lambda: restore_files(env, manifest, mdir))
    part("target conffiles", lambda: remove_target_conffiles(env, manifest))
    part("directories", lambda: restore_dirs(env, state.get("dirs") or {}))
    part("AppArmor", lambda: reenable_apparmor(env, state.get("apparmor_disabled") or []))
    part("repository files", lambda: remove_repo_files(env, manifest))
    part("units", lambda: restore_units(env, state.get("units_before") or {}))
    part("removed ISC packages", lambda: purge_leftovers(env))
    fresh = _state(mdir)
    fresh.pop("delays", None)
    _save_state(mdir, fresh)
    if details.get("short_delays") and _delay(details):
        part("short delays", lambda: shorten_files(env, mdir, engines, int(_delay(details) or 0)))
    try:
        env.services.daemon_reload()
    except Exception as exc:  # the check below says whether the units still work
        out.append(f"daemon-reload: {exc}")
    part("check", lambda: check_files(env, engines, test_flag=False))
    if errors:
        raise SwitchError("the return is incomplete: " + "; ".join(errors) + "\n" + "\n".join(out))
    return out, next(iter((manifest.get("from_versions") or {}).values()), "")


def _short(details: dict[str, Any]) -> bool:
    """Whether this node takes over alone in the window: said by the plan, else its standby role."""
    if "short_delays" in details:
        return bool(details["short_delays"])
    node = details.get("node") if isinstance(details.get("node"), dict) else {}
    return node.get("role") == "standby"


def _delay(details: dict[str, Any]) -> int | None:
    options = details.get("options") if isinstance(details.get("options"), dict) else {}
    delay = options.get("response_delay_milliseconds")
    return int(delay) if isinstance(delay, int) and not isinstance(delay, bool) else None


def delays(env: Any, details: dict[str, Any], plan_id: str | None = None) -> dict[str, Any]:
    """`kea-mig-delays` (time 3): the detection delays noted before the window back in each file,
    `config-reload`, then a wait until the pair is normal again; the HA maintenance window of the
    node is closed. Nothing else in the files changes."""
    mdir = _mdir(env, details)
    state = _state(mdir)
    saved = state.get("delays") or {}
    out: dict[str, Any] = {}
    engines = [e for e in details.get("engines") or [] if e in HA_ENGINES]
    for engine in engines:
        ha_maintenance.close(env.node_paths, engine)
        if engine not in saved:
            continue
        conf = env.paths.kea_conf(km.DAEMONS[engine])
        entry = saved[engine] if isinstance(saved[engine], dict) else {}
        current = conf.read_bytes()
        keep = mdir / "private" / str(entry.get("file") or "")
        if keep.is_file() and hashlib.sha256(current).hexdigest() == entry.get("shortened_sha256"):
            data = keep.read_bytes()  # untouched since the window: the file exactly as it was
        else:
            cfg = _load(conf)
            for i, rel in enumerate(mig.ha_relationships(cfg, engine)):
                original = (entry.get("relationships") or {}).get(str(rel.get("this-server-name") or i)) or {}
                for key in DELAY_KEYS:
                    if original.get(key) is None:
                        rel.pop(key, None)
                    else:
                        rel[key] = original[key]
            data = (json.dumps(cfg, indent=2) + "\n").encode()
        st = conf.stat()
        _write_like(conf, data, st.st_mode & 0o7777, st.st_uid, st.st_gid)
        env.relabel([conf])
        rels = mig.ha_relationships(_load(conf), engine)
        sock = keasetup.socket_path(env, engine, conf)
        answer = env.t.kea_command(sock, "config-reload")
        if answer.get("result") != 0:
            raise SwitchError(f"{engine} config-reload: {answer.get('text', answer)}")
        servers = [str(r.get("this-server-name")) for r in rels if r.get("this-server-name")]
        out[engine] = wait_ha(env, engine, conf, servers) if servers else "reloaded"
        state = _state(mdir)
        (state.get("delays") or {}).pop(engine, None)
        _save_state(mdir, state)
    if not out:
        return {"delays": {}, "note": "no shortened delay on this node"}
    return {"delays": out}


def finish(env: Any, details: dict[str, Any]) -> dict[str, Any]:
    """`kea-mig-finish`: what only the way forward needed goes (the converted files and dnf's target
    packages); the saved 2.6 files, the kept 2.6 packages, the notes and the lease copies stay for
    the return of the pair."""
    mdir = _mdir(env, details)
    removed = []
    for rel in ("private/target", "packages/target"):
        path = mdir / rel
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
            removed.append(rel)
    for engine in HA_ENGINES:
        ha_maintenance.close(env.node_paths, engine)
    state = _state(mdir)
    state["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _save_state(mdir, state)
    return {"removed": removed, "kept": ["private/before", "packages/previous"]}


def validate_partner(env: Any, details: dict[str, Any]) -> dict[str, Any]:
    """`kea-mig-validate-partner`, on the partner itself before time 1: its converted files checked
    by the target daemons extracted from its own prepared packages, exactly as its analysis and
    prepare checked them. A file never leaves its host: interface names, sockets and paths differ
    between nodes (2026-10-30: a standby refused its primary's `interfaces-config`)."""
    if str(details.get("partner") or env.node_id) != env.node_id:
        raise SwitchError("the partner's files are checked on the partner: plan this phase again")
    mdir = _mdir(env, details)
    manifest = _manifest(env, mdir)
    check_packages(mdir, manifest, ("target",))
    from pelagos.installer.kea_migration_steps import _sha256

    target = mdir / "private" / "target"
    conv = manifest.get("converted") or {}
    secrets = {}
    for item in conv.get("secrets") or []:
        src = target / item["file"]
        if _sha256(src) != item["sha256"]:
            raise SwitchError(f"{src} changed since the prepare: prepare again")
        secrets[str(item["path"])] = src.read_text().rstrip("\n")
    folder = mdir / "packages" / "target"
    files = [
        folder / p["file"] for p in manifest.get("target_files") or manifest.get("packages_target") or []
    ]
    work = Path(tempfile.mkdtemp(prefix="pelagos-kea-validate-"))
    ws = km.Workspace(
        env.runner,
        env.distro,
        str(manifest.get("series")),
        str(manifest.get("source")),
        work,
        kea_user=env.paths.kea_user,
    )
    out = []
    try:
        try:
            ws.extract(files)
        except km.DryRunError as exc:
            raise SwitchError(str(exc)) from None
        for item in conv.get("files") or []:
            src = target / item["file"]
            if _sha256(src) != item["sha256"]:
                raise SwitchError(f"{src} changed since the prepare: prepare again")
            engine = item["engine"]
            try:
                result = ws.validate(engine, json.loads(src.read_text()), secrets, str(item["path"]))
            except km.DryRunError as exc:
                raise SwitchError(f"{km.DAEMONS[engine]}: {exc}") from None
            if not result["ok"]:
                raise SwitchError(
                    f"{km.DAEMONS[engine]} {result['version']} refuses {item['path']}: "
                    f"{km.error_line(result['output'])}"
                )
            out.append(
                f"{km.DAEMONS[engine]} {km.TEST_FLAG[engine]} {item['path']}: accepted ({result['version']})"
            )
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if not out:
        raise SwitchError("no converted file to check on this node: prepare again")
    return {"checked": out}


# Reconcile: the real state read back, then the leftovers removed ------------------------------------


def _series(version: str) -> str:
    v = version.split(":", 1)[-1]
    return ".".join(v.split(".")[:2])


def check(env: Any, details: dict[str, Any]) -> dict[str, Any]:
    """`kea-mig-check`: whether this node runs the previous series as before the migration: its Kea
    packages (no ISC package installed, the exact versions noted at the prepare when known), each
    daemon's file accepted by the installed daemon, each unit running. Nothing changes here."""
    engines = [e for e in details.get("engines") or [] if e in km.DAEMONS]
    want = str(details.get("from_series") or "2.6")
    problems: list[str] = []
    notes: list[str] = []
    installed = km.installed_packages(env.runner, env.distro)
    isc = sorted(n for n in installed if _ISC_PACKAGE.match(n))
    if isc:
        problems.append("ISC packages installed: " + ", ".join(isc))
    before = [p for p in details.get("packages_before") or [] if isinstance(p, dict) and p.get("name")]
    for p in before:
        if installed.get(p["name"]) != p.get("version"):
            problems.append(f"{p['name']} {installed.get(p['name'], 'absent')} instead of {p.get('version')}")
    versions = {}
    for engine in engines:
        pkg = km.engine_package(env.runner, env.distro, engine)
        version = (pkg or {}).get("version") or ""
        versions[engine] = version
        if _series(version.rsplit("-", 1)[0] if "-" in version else version) != want:
            problems.append(f"{km.DAEMONS[engine]} is {version or 'not installed'}, not Kea {want}")
            continue
        ok, output = _kea_check(env, km.DAEMONS[engine], env.paths.kea_conf(km.DAEMONS[engine]), "-t")
        if not ok:
            problems.append(f"{km.DAEMONS[engine]} -t refuses its file: {km.error_line(output)}")
        unit = env.kea_unit(engine)
        if not env.services.is_active(unit):
            problems.append(f"{unit} is not running")
    try:
        mdir: Path | None = kmc.state_dir(env.node_paths, str(details.get("migration_id") or ""))
    except kmc.MigrationStateError:
        mdir = None
    for path in _differing(mdir) if mdir else []:
        notes.append(f"{path} differs from the file saved at the prepare (kept as it is)")
    left = _apparmor_disabled(env)
    if left:
        notes.append("AppArmor disabled here: " + ", ".join(left))
    if problems:
        raise SwitchError(f"this node is not back on Kea {want}: " + "; ".join(problems))
    return {"versions": versions, "packages": installed, "notes": notes}


def _differing(mdir: Path) -> list[Path]:
    """Files of /etc/kea whose content is no longer what the prepare of `mdir` saved."""
    from pelagos.installer.kea_migration_steps import _sha256

    try:
        manifest = json.loads((mdir / "manifest.json").read_text())
    except (OSError, ValueError):
        return []
    out = []
    for entry in manifest.get("saved") or []:
        path = Path(str(entry.get("path") or ""))
        if (
            entry.get("sha256")
            and path.is_file()
            and not path.is_symlink()
            and _sha256(path) != entry["sha256"]
        ):
            out.append(path)
    return out


def cleanup(env: Any, details: dict[str, Any]) -> dict[str, Any]:
    """`kea-mig-cleanup`: once the node is back on the previous series, the AppArmor profiles the
    migration disabled enabled again, the removed ISC packages purged (purge_leftovers), the HA
    maintenance windows closed and every migration directory of the node removed. Kea files stay;
    when /etc/kea differs from the prepare's copy, that copy (private/before) is moved aside first."""
    out: list[str] = []
    root = Path(env.node_paths.kea_migration_state)
    noted: set[str] = set()
    for d in sorted(root.glob("*")) if root.is_dir() else []:
        noted |= set(_state(d).get("apparmor_disabled") or []) if kmc.ID_RE.match(d.name) else set()
    out += reenable_apparmor(env, sorted(noted))
    out += purge_leftovers(env)
    for engine in HA_ENGINES:
        ha_maintenance.close(env.node_paths, engine)
    for d in sorted(root.glob("*")) if root.is_dir() else []:
        before = d / "private" / "before"
        if kmc.ID_RE.match(d.name) and before.is_dir() and _differing(d):
            # /etc/kea is not what the prepare saved: its only copy of the 2.6 files outlives the folder.
            kept = root / f"before-{d.name}-{time.strftime('%Y%m%dT%H%M%S')}"
            shutil.move(str(before), str(kept))
            out.append(f"{kept} kept: /etc/kea differs from the files saved at the prepare")
    public = Path(env.node_paths.var) / kmc.DIR
    for top in (root, public):
        for d in sorted(top.glob("*")) if top.is_dir() else []:
            if kmc.ID_RE.match(d.name) and d.is_dir() and not d.is_symlink():
                shutil.rmtree(d)
                out.append(f"{d} removed")
    return {"log": out}
