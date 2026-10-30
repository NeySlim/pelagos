# SPDX-License-Identifier: Apache-2.0
"""Helper steps of the Kea 3.x migration that change a node (architecture section 28, batches K4, K5).

Time 1 (design 13.4 decision 5): `ha-maintenance-start` on the serving peer, Kea stopped on the
standby, the target packages installed from the cache prepared earlier, the converted files put in
place and checked by the installed daemons, then the partner's converted files checked by them too.
Time 2: the primary stops and leaves a compacted copy of its lease files, which replaces the
standby's. Time 3: the detection delays shortened for the window are put back.
The return puts the exact 2.6 packages, the saved files, the AppArmor profiles, the dpkg stat
overrides and the directory modes back, then starts what ran before.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import shutil
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
    mdir = kmc.migration_dir(env.node_paths.var, str(details.get("migration_id") or ""))
    if not (mdir / "manifest.json").is_file():
        raise SwitchError(f"{mdir} has no manifest: prepare this node again")
    return mdir


def _manifest(mdir: Path) -> dict[str, Any]:
    return json.loads((mdir / "manifest.json").read_text())


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
    units = kea_units(env)
    before = {}
    for unit in units:
        active, enabled = env.services.unit_state(unit)
        before[unit] = {"active": active == "active", "enabled": enabled == "enabled"}
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
    from pelagos.installer.kea_migration_steps import _sha256

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
        tmp = copy.with_name(f".{copy.name}.part")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f, result.open("rb") as src:
            shutil.copyfileobj(src, f)
        os.replace(tmp, copy)
        shutil.rmtree(work, ignore_errors=True)
        out[family] = {"sha256": _sha256(copy), "size": copy.stat().st_size, "source": str(path)}
    return out


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


def received_meta(mdir: Path, family: str) -> dict[str, Any]:
    try:
        data = json.loads((mdir / kmc.received_meta_name(family)).read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def leases_in(env: Any, details: dict[str, Any]) -> dict[str, Any]:
    """`kea-mig-leases-in`: the partner's lease copy fetched by this node's service (sum checked again
    against what the fetch noted) replaces this node's lease file and its `.1` / `.2` leftovers,
    which go to the migration's private directory. Kea must be stopped here."""
    from pelagos.installer.kea_migration_steps import _sha256

    mdir = _mdir(env, details)
    _all_stopped(env)
    source = str(details.get("from_node") or "")
    engines = [e for e in details.get("engines") or [] if e in FAMILY_OF]
    families = [str(f) for f in details.get("families") or []]
    out: dict[str, Any] = {}
    for engine in engines:
        family = FAMILY_OF[engine]
        if family not in families:
            continue
        copy = mdir / kmc.received_name(family)
        meta = received_meta(mdir, family)
        if not copy.is_file() or copy.is_symlink():
            if meta.get("skipped"):
                out[family] = {"skipped": meta["skipped"]}
                continue
            raise SwitchError(f"no lease copy for DHCPv{family} fetched from the partner")
        if meta.get("from_node") != source:
            raise SwitchError(f"the DHCPv{family} lease copy does not come from {source}")
        digest = _sha256(copy)
        if digest != meta.get("sha256") or copy.stat().st_size != meta.get("size"):
            raise SwitchError(f"the DHCPv{family} lease copy changed since it was fetched")
        if not _lines(copy)[:1] or not _lines(copy)[0].startswith(LEASE_HEADER):
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
        _write_like(path, copy.read_bytes(), mode, uid, gid)
        env.relabel([path])
        out[family] = {"path": str(path), "sha256": digest, "size": copy.stat().st_size}
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
    if env.distro.is_debian:
        specs = [f"{p['name']}={p['version']}" for p in target]
        res = _apt(env, ["install", *specs, *(f"{n}-" for n in remove)])
    elif env.distro.is_rhel:
        files = [str(Path(p["file"])) for p in target]
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
    files = []
    for p in previous:
        path = mdir / "packages" / "previous" / p["file"]
        if not path.is_file():
            raise SwitchError(f"{path} is missing: the return needs the kept package")
        files.append(path)
    if env.distro.is_debian:
        res = _apt(
            env, ["--allow-downgrades", "install", *(str(f) for f in files), *(f"{n}-" for n in extra)]
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


def with_standby_delays(cfg: dict[str, Any], engine: str, delay_ms: int) -> dict[str, Any]:
    """The standby's 3.x file during the migration: a short failure detection so that it serves alone
    soon after the primary stops (time 2); kea-mig-delays puts the original values back."""
    out = json.loads(json.dumps(cfg))
    for rel in mig.ha_relationships(out, engine):
        rel["max-response-delay"] = int(delay_ms)
        rel["max-unacked-clients"] = 0
    return out


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


def reenable_apparmor(env: Any, names: list[str]) -> list[str]:
    out = []
    for name in names:
        link = _root(env, "etc/apparmor.d/disable") / name
        profile = _root(env, "etc/apparmor.d") / name
        if link.is_symlink():
            link.unlink()
        if profile.is_file():
            env.runner.run(["apparmor_parser", "-r", str(profile)], privileged=True, check=False, timeout=60)
            out.append(f"AppArmor profile {name} enabled again")
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
    manifest = _manifest(mdir)
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
        state = _state(mdir)
        out += (
            restore_statoverrides(env, state.get("statoverrides") or []) if "statoverrides" in state else []
        )
        out.append(install_previous_packages(env, manifest, mdir))
        out += restore_files(env, manifest, mdir)
        out += remove_target_conffiles(env, manifest)
        out += restore_dirs(env, state.get("dirs") or {})
        out += reenable_apparmor(env, state.get("apparmor_disabled") or [])
        out += remove_repo_files(env, manifest)
        state = _state(mdir)
        state.pop("delays", None)
        _save_state(mdir, state)
        if details.get("short_delays") and _delay(details):
            out += shorten_files(env, mdir, engines, int(_delay(details) or 0))
        env.services.daemon_reload()
        out += check_files(env, engines, test_flag=False)
        version = next(iter((manifest.get("from_versions") or {}).values()), "")
    else:
        raise ValueError(f"unknown install direction {direction!r}")
    return {"direction": direction, "version": version, "log": out}


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


def _partner_bundle(env: Any, details: dict[str, Any]) -> dict[str, Any]:
    from pelagos.core.config_store import ConfigStore
    from pelagos.core.secrets import SecretBox

    paths = env.node_paths
    migration_id = str(details.get("migration_id") or "")
    partner = str(details.get("partner") or "")
    cluster = ConfigStore(paths.node_toml, paths.cluster_toml).load_cluster()
    record = kmc.read_migration(cluster.settings)
    if record is None or record["id"] != migration_id:
        raise SwitchError(f"migration {migration_id} is not in this node's cluster.toml")
    node = next((n for n in record["nodes"] if n["node_id"] == partner), None)
    if node is None or not node.get("files_sealed"):
        raise SwitchError(f"the partner's converted files are not in migration {migration_id}: prepare again")
    try:
        return kmc.open_files(
            SecretBox.from_file(paths.master_key), migration_id, partner, node["files_sealed"]
        )
    except Exception as exc:
        raise SwitchError(f"the partner's converted files do not open here: {exc}") from None


def _own_tls(env: Any, engine: str) -> dict[str, str]:
    cfg = _load(env.paths.kea_conf(km.DAEMONS[engine]))
    out: dict[str, str] = {}
    for rel in mig.ha_relationships(cfg, engine):
        for key in TLS_KEYS:
            if isinstance(rel.get(key), str):
                out.setdefault(key, rel[key])
        for peer in rel.get("peers") or []:
            for key in TLS_KEYS:
                if isinstance(peer, dict) and isinstance(peer.get(key), str):
                    out.setdefault(key, peer[key])
    return out


def _for_this_host(
    env: Any, engine: str, cfg: dict[str, Any], work: Path, secrets: dict[str, str]
) -> dict[str, Any]:
    """The partner's file made checkable here: hooks by name (the pair may mix architectures), HA TLS
    files this host lacks replaced by its own (the same cluster CA), secret files as copies."""
    out = json.loads(json.dumps(cfg))
    root = out.get(mig.ROOTS[engine]) or {}
    for hook in root.get("hooks-libraries") or []:
        if isinstance(hook, dict) and isinstance(hook.get("library"), str):
            hook["library"] = posixpath.basename(hook["library"])
    own = _own_tls(env, engine) if engine in HA_ENGINES else {}
    for rel in mig.ha_relationships(out, engine):
        for holder in [rel, *(p for p in rel.get("peers") or [] if isinstance(p, dict))]:
            for key in TLS_KEYS:
                value = holder.get(key)
                if isinstance(value, str) and not Path(value).exists() and key in own:
                    holder[key] = own[key]
    for i, key in enumerate(root.get("tsig-keys") or []):
        if isinstance(key, dict) and key.get("secret-file") in secrets:
            copy = work / f"secret-{i}.tsig"
            copy.write_text(secrets[key["secret-file"]])
            key["secret-file"] = str(copy)
    return out


def validate_partner(env: Any, details: dict[str, Any]) -> dict[str, Any]:
    """`kea-mig-validate-partner`: the partner's converted files (sealed in the migration record by
    its prepare step) checked by this node's installed 3.x daemons in a temporary directory."""
    bundle = _partner_bundle(env, details)
    secrets = {str(k): str(v) for k, v in (bundle.get("secrets") or {}).items()}
    configs = bundle["configs"]
    work = Path(tempfile.mkdtemp(prefix="pelagos-kea-partner-"))
    out = []
    try:
        for engine in [e for e in km.DAEMONS if e in configs]:
            daemon = km.DAEMONS[engine]
            if not env.binary(daemon):
                raise SwitchError(
                    f"{daemon} is not installed here: the partner's {engine} file cannot be checked"
                )
            d = work / engine
            d.mkdir()
            cfg = _for_this_host(env, engine, configs[engine], d, secrets)
            conf = d / f"{daemon}.conf"
            conf.write_text(json.dumps(cfg, indent=2) + "\n")
            _share(env, work, d)
            ok, output = _kea_check(env, daemon, conf, km.TEST_FLAG[engine])
            if not ok:
                raise SwitchError(f"{daemon} refuses the partner's file: {km.error_line(output)}")
            out.append(f"{daemon} {km.TEST_FLAG[engine]}: the partner's file is accepted")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return {"checked": out}


def _share(env: Any, work: Path, d: Path) -> None:
    """The Kea user reads the check directory through its group, nothing more."""
    if os.geteuid() != 0:
        return
    import grp

    try:
        gid = grp.getgrnam(env.paths.kea_group).gr_gid
    except KeyError:
        return
    for path in (work, d, *d.iterdir()):
        os.chown(path, 0, gid)
        path.chmod(0o750 if path.is_dir() else 0o640)
