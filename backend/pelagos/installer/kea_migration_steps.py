# SPDX-License-Identifier: Apache-2.0
"""Kea 3.x migration on a node (architecture section 28): the `kea.migration` plans this node's
helper builds and records (`plan_kea_migration`), and the helper steps it runs as root.

Prepare (batch K3, design 13.4 decision 4) changes nothing Kea runs with: the target packages go
into the package manager's cache (`apt-get install --download-only`, `dnf download`), the exact
2.6 packages are kept for the return, the 2.6 files are saved and the converted 3.x files written
under `<var>/kea-migration/<id>/`, never in `/etc/kea`. What holds secrets (the saved files, the
converted ones and their TSIG secret files) stays in its `private/` directory, root only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

from pelagos.connectors.kea import migration as mig
from pelagos.core import kea_migration as kmc
from pelagos.domain import Change, ChangeOp, Plan, PlanScope, PlanState, messages, to_rfc3339, utcnow
from pelagos.installer import kea_migration as km
from pelagos.installer.jobs import Step
from pelagos.platform.packages import isc_repo_files

PRIVATE = "private"  # root only, left out when the helper gives the var tree back to pelagos
MANIFEST = "manifest.json"
APT_ARCHIVES = "var/cache/apt/archives"
SAFE_NODE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_SH_CD = 'cd "$1" && shift && exec "$@"'


class PrepareError(RuntimeError):
    """The node cannot be prepared: nothing Kea runs with was changed."""


# The plan ------------------------------------------------------------------------------------


def _node_row(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or not SAFE_NODE.match(str(raw.get("node_id") or "")):
        raise ValueError("nodes: each node needs a node_id")
    engines = [e for e in raw.get("engines") or [] if e in km.DAEMONS]
    if not engines:
        raise ValueError(f"node {raw['node_id']}: no Kea daemon to migrate")
    role = raw.get("role") if raw.get("role") in kmc.ROLES else "single"
    order = raw.get("order") if isinstance(raw.get("order"), int) else 0
    return {
        "node_id": str(raw["node_id"]),
        "name": str(raw.get("name") or raw["node_id"]),
        "role": role,
        "order": order,
        "engines": engines,
        "from_version": str(raw.get("from_version") or ""),
    }


def build_plan(env: Any, request: dict[str, Any], created_by: str = "") -> Plan:
    """The composite plan of one phase, built on the driving node (this one). Prepare: the archive of
    every node (a driver step), then its prepare step; each change carries what the record needs."""
    phase = request.get("phase")
    if phase != kmc.PREPARE:
        raise ValueError(f"the {phase} phase of the Kea migration is not available in this release")
    migration_id = str(request.get("migration_id") or "")
    if not kmc.ID_RE.match(migration_id):
        raise ValueError(f"invalid migration id {migration_id!r}")
    series, source = str(request.get("series") or ""), str(request.get("source") or "")
    if (series, source) not in (("3.2", "isc"), ("3.0", "isc"), ("3.0", "backports")):
        raise ValueError(f"no Kea {series} from {source}")
    nodes = sorted((_node_row(n) for n in request.get("nodes") or []), key=lambda n: (n["order"], n["name"]))
    if not nodes or len({n["node_id"] for n in nodes}) != len(nodes):
        raise ValueError("nodes: at least one node, each once")
    base = {
        "migration_id": migration_id,
        "phase": phase,
        "series": series,
        "source": source,
        "target_version": str(request.get("target_version") or ""),
        "from_series": str(request.get("from_series") or "2.6"),
    }
    changes = []
    for step, what in (
        (kmc.D_ARCHIVE, "archive of the node before the migration"),
        (kmc.H_PREPARE, f"Kea {series} ({source}) packages downloaded, converted files written aside"),
    ):
        for node in nodes:
            after = {
                "step": step,
                "details": {**base, "node": {k: v for k, v in node.items() if k != "node_id"}},
                "summary": f"{node['name']}: {what}",
            }
            changes.append(
                Change(
                    ChangeOp.REPLACE,
                    kmc.target(step, node["node_id"]),
                    after=after,
                    node_ids=[node["node_id"]],
                )
            )
    names = ", ".join(n["name"] for n in nodes)
    summary = messages.msg(f"plan.kea_migration.{phase}", nodes=names, series=series, source=source)
    return Plan(
        scope=PlanScope.KEA_MIGRATION,
        node_id=env.node_id,
        summary=messages.render(summary),
        summary_message=summary,
        created_by=created_by,
        changes=changes,
        diff="\n".join(f"~ {c.target}: {c.after['summary']}" for c in changes),
        target_node_ids=sorted(n["node_id"] for n in nodes),
        requires_confirmation=True,
        state=PlanState.VALIDATED,
    )


def migration_steps(plan: Plan, env: Any) -> list[Step]:
    """The helper steps of `plan` this node runs; a driver step never comes here."""
    out = []
    for change in plan.changes:
        if env.node_id not in change.node_ids:
            continue
        after = change.after if isinstance(change.after, dict) else {}
        step = after.get("step")
        if change.target != kmc.target(str(step), env.node_id):
            raise ValueError(f"step {change.target} is not this node's")
        details = after.get("details") if isinstance(after.get("details"), dict) else {}
        if step == kmc.H_PREPARE:
            out.append(Step(change.target, lambda d=details: json.dumps(prepare(env, d), sort_keys=True), 10))
        elif step in kmc.DRIVER_STEPS:
            raise ValueError(f"{step} runs in the driving node's service, not in the helper")
        else:
            raise ValueError(f"{step} is not available in this release")
    if not out:
        raise ValueError("no Kea migration step for this node")
    return out


def result_of(output: str) -> dict[str, Any]:
    """The JSON result a step printed as its output ({} when there is none)."""
    try:
        data = json.loads(output)
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


# Prepare -------------------------------------------------------------------------------------


def private_paths(var: Path) -> list[Path]:
    """Every entry under the private directories of the migrations: they stay root's."""
    out: list[Path] = []
    for private in sorted((var / kmc.DIR).glob(f"*/{PRIVATE}")):
        if private.is_symlink() or not private.is_dir():
            continue
        out.append(private)
        for top, dirs, files in os.walk(private):
            out += [Path(top) / n for n in (*dirs, *files)]
    return out


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _mkdir(path: Path, mode: int = 0o700) -> Path:
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    path.chmod(mode)
    return path


def _write(path: Path, data: str, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w") as f:
        f.write(data)
    path.chmod(mode)


def save_files(env: Any, dest: Path) -> list[dict[str, Any]]:
    """A copy of the Kea configuration directory (owners, modes, links kept) for the return to 2.6."""
    src = env.paths.kea_conf_dir
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest, symlinks=True)
    out = []
    for top, dirs, files in os.walk(src):
        for name in (*dirs, *files):
            path = Path(top) / name
            st = path.lstat()
            copy = dest / path.relative_to(src)
            if os.geteuid() == 0:
                os.chown(copy, st.st_uid, st.st_gid, follow_symlinks=False)
            entry = {"path": str(path), "mode": oct(st.st_mode & 0o7777), "uid": st.st_uid, "gid": st.st_gid}
            if path.is_symlink():
                entry["link"] = os.readlink(path)
            elif path.is_file():
                entry["sha256"] = _sha256(path)
            out.append(entry)
    return out


def write_converted(
    env: Any, conversions: dict[str, mig.Conversion], dest: Path
) -> dict[str, list[dict[str, str]]]:
    """The converted files (and the TSIG secret files the conversion adds) under `dest`; where each
    one goes at the switch is in the manifest."""
    _mkdir(dest)
    files: list[dict[str, str]] = []
    for engine, conv in conversions.items():
        target = env.paths.kea_conf(km.DAEMONS[engine])
        name = f"{km.DAEMONS[engine]}.conf"
        _write(dest / name, json.dumps(conv.after, indent=2) + "\n")
        files.append({"engine": engine, "path": str(target), "file": name, "sha256": _sha256(dest / name)})
    secrets: list[dict[str, str]] = []
    for i, (path, secret) in enumerate(
        sorted((p, s) for conv in conversions.values() for p, s in conv.files.items())
    ):
        name = f"secret-{i}.tsig"
        _write(dest / name, secret if secret.endswith("\n") else secret + "\n")
        secrets.append({"path": path, "file": name, "sha256": _sha256(dest / name)})
    return {"files": files, "secrets": secrets}


def _deb_prefix(name: str, version: str) -> str:
    """apt names an archive `<name>_<version, ':' as %3a>_<arch>.deb`."""
    return f"{name}_{version.replace(':', '%3a')}_"


def _run(env: Any, argv: list[str], timeout: float = 1800) -> Any:
    return env.runner.run(argv, privileged=True, check=False, timeout=timeout)


def add_sources(env: Any, series: str, source: str) -> list[str]:
    """The target's repository next to the node's own (ISC Cloudsmith with its key, or Debian
    backports), then the index refreshed; returns the files it added (removed by the return)."""
    added: list[str] = []
    distro = env.distro
    files = []
    if source == "isc":
        files = isc_repo_files(distro, series)
    elif distro.is_debian:
        codename = distro.codename
        apt = env.paths.root / "etc/apt"
        lists = [apt / "sources.list", *sorted((apt / "sources.list.d").glob("*"))]
        if not any(f"{codename}-backports" in _read(p) for p in lists if p.is_file()):
            from pelagos.platform.packages import RepoFile

            line = f"deb [signed-by={km.DEBIAN_KEYRING}] {km.DEBIAN_MIRROR} {codename}-backports main\n"
            files = [
                RepoFile(
                    Path(f"/etc/apt/sources.list.d/pelagos-{codename}-backports.list"),
                    content="# pelagos:managed v1 (Debian backports, Kea migration)\n" + line,
                )
            ]
    for f in files:
        target = env.paths.root / f.path.relative_to("/")
        data = f.content.encode() if f.content is not None else env.t.fetch(str(f.url))
        if target.exists() and target.read_bytes() == data:
            continue
        existed = target.exists()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(f.mode)
        if not existed:
            added.append(str(f.path))
    try:
        env.packages.refresh()
    except Exception as exc:
        raise PrepareError(f"package index refresh failed: {str(exc)[-400:]}") from None
    return added


def _read(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return ""


def keep_previous(env: Any, installed: dict[str, str], dest: Path) -> list[dict[str, str]]:
    """The installed Kea packages at their exact versions, as files under `dest`, so the return to
    2.6 needs neither the network nor a version the archive may have dropped since."""
    _mkdir(dest)
    out: list[dict[str, str]] = []
    if env.distro.is_debian:
        cache = env.paths.root / APT_ARCHIVES
        missing = []
        for name, version in sorted(installed.items()):
            found = sorted(cache.glob(_deb_prefix(name, version) + "*.deb")) if cache.is_dir() else []
            if found:
                shutil.copy2(found[0], dest / found[0].name)
            else:
                missing.append(f"{name}={version}")
        if missing:
            argv = ["sh", "-c", _SH_CD, "sh", str(dest), "apt-get", "-q", "-o", "APT::Sandbox::User=root"]
            res = _run(env, [*argv, "download", *missing])
            if not res.ok:
                raise PrepareError(f"previous packages not downloadable ({res.output.strip()[-300:]})")
        for name, version in sorted(installed.items()):
            found = sorted(dest.glob(_deb_prefix(name, version) + "*.deb"))
            if not found:
                raise PrepareError(
                    f"{name} {version} is not available: the return to 2.6 would be impossible"
                )
            out.append({"name": name, "version": version, "file": found[0].name, "sha256": _sha256(found[0])})
    elif env.distro.is_rhel:
        specs = [f"{n}-{v}" for n, v in sorted(installed.items())]
        res = _run(env, ["dnf", "-q", "download", f"--destdir={dest}", *specs])
        if not res.ok:
            raise PrepareError(f"previous packages not downloadable ({res.output.strip()[-300:]})")
        for name, version in sorted(installed.items()):
            found = sorted(dest.glob(f"{name}-{version}.*.rpm"))
            if not found:
                raise PrepareError(
                    f"{name} {version} is not available: the return to 2.6 would be impossible"
                )
            out.append({"name": name, "version": version, "file": found[0].name, "sha256": _sha256(found[0])})
    else:
        raise PrepareError(f"no package manager for {env.distro.id}")
    return out


def download_target(env: Any, packages: list[dict[str, str]], dest: Path) -> list[dict[str, str]]:
    """The target packages at their exact versions in the package manager's cache (apt; dnf into
    `dest`), dependencies included, so the switch needs no network. Nothing is installed."""
    specs = [p for p in packages if p.get("version")]
    if len(specs) != len(packages):
        raise PrepareError("a target package has no version: analyze again")
    out = []
    if env.distro.is_debian:
        argv = ["apt-get", "install", "--download-only", "-y", "-q"]
        res = _run(env, [*argv, *(f"{p['name']}={p['version']}" for p in specs)])
        if not res.ok:
            raise PrepareError(f"download of the target packages failed: {res.output.strip()[-400:]}")
        cache = env.paths.root / APT_ARCHIVES
        for p in specs:
            found = sorted(cache.glob(_deb_prefix(p["name"], p["version"]) + "*.deb"))
            if not found:
                raise PrepareError(
                    f"{p['name']} {p['version']} is not in the package cache after the download"
                )
            out.append({**p, "file": str(found[0]), "sha256": _sha256(found[0])})
    elif env.distro.is_rhel:
        _mkdir(dest)
        argv = ["dnf", "-q", "download", "--resolve", f"--destdir={dest}"]
        res = _run(env, [*argv, *(f"{p['name']}-{p['version']}" for p in specs)])
        if not res.ok:
            raise PrepareError(f"download of the target packages failed: {res.output.strip()[-400:]}")
        for p in specs:
            found = sorted(dest.glob(f"{p['name']}-{p['version']}.*.rpm"))
            if not found:
                raise PrepareError(f"{p['name']} {p['version']} was not downloaded")
            out.append({**p, "file": str(found[0]), "sha256": _sha256(found[0])})
    else:
        raise PrepareError(f"no package manager for {env.distro.id}")
    return out


def _upstream(version: str) -> str:
    v = version.split(":", 1)[-1]
    return v.rsplit("-", 1)[0] if "-" in v else v


def prepare(env: Any, details: dict[str, Any]) -> dict[str, Any]:
    """`kea-mig-prepare`: converts and checks this node's files with the target's binaries, saves
    the 2.6 files and packages, writes the 3.x files aside and downloads the target packages.
    Returns {"packages_before","packages_target","packages_remove","rollback_ready","prepared_at",
    "from_version","target_version","validation","repo_files_added"}; raises PrepareError."""
    migration_id = str(details.get("migration_id") or "")
    series, source = str(details.get("series") or ""), str(details.get("source") or "")
    km.check_target(env.distro, series, source)
    node = details.get("node") if isinstance(details.get("node"), dict) else {}
    engines = [e for e in node.get("engines") or [] if e in km.DAEMONS]
    if not engines:
        raise ValueError("no Kea daemon to prepare on this node")
    mdir = kmc.migration_dir(env.node_paths.var, migration_id)
    if mdir.exists():
        shutil.rmtree(mdir)  # a prepare run again starts over
    _mkdir(mdir.parent, 0o750)
    _mkdir(mdir)
    private = _mkdir(mdir / PRIVATE)
    configs = km.read_configs(env, engines)
    absent = [e for e in engines if e not in configs]
    if absent:
        raise PrepareError(f"no configuration file for {', '.join(absent)} on this node")
    installed = km.installed_packages(env.runner, env.distro)
    if not installed:
        raise PrepareError("no Kea package installed on this node")
    keep: dict[str, Any] = {}
    report = km.analyze(env, series, source, configs, env.node_id, None, keep=keep)
    if keep.get("fetch_error"):
        raise PrepareError(f"target packages: {keep['fetch_error'][-400:]}")
    blocking = [f for f in report["findings"] if f.get("severity") == "blocking"]
    if blocking:
        what = "; ".join(messages.render(f["message"]) if f.get("message") else f["code"] for f in blocking)
        raise PrepareError(f"blocking findings on this node: {what[:600]}")
    target = [p for p in report["packages"].get("install") or [] if p.get("name")]
    target_version = _upstream(next((p["version"] for p in target if p.get("version")), ""))
    wanted = str(details.get("target_version") or "")
    if wanted and _upstream(wanted) != target_version:
        raise PrepareError(
            f"Kea {target_version} is offered now, the analysis checked {wanted}: analyze again"
        )
    saved = save_files(env, private / "before")
    converted = write_converted(env, keep["conversions"], private / "target")
    added = add_sources(env, series, source)
    previous = keep_previous(env, installed, mdir / "packages" / "previous")
    downloaded = download_target(env, target, mdir / "packages" / "target")
    now = to_rfc3339(utcnow())
    versions = {e: v for e in engines if (v := _engine_version(env, e))}
    manifest = {
        "migration_id": migration_id,
        "node_id": env.node_id,
        "series": series,
        "source": source,
        "target_version": target_version,
        "prepared_at": now,
        "engines": engines,
        "from_versions": versions,
        "saved": saved,
        "converted": converted,
        "packages_before": previous,
        "packages_target": downloaded,
        "packages_remove": report["packages"].get("remove") or [],
        "repo_files_added": added,
        "validation": {e: v.get("mode") for e, v in report["validation"].items()},
    }
    _write(mdir / MANIFEST, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return {
        "packages_before": [{"name": p["name"], "version": p["version"]} for p in previous],
        "packages_target": [{"name": p["name"], "version": p["version"]} for p in downloaded],
        "packages_remove": manifest["packages_remove"],
        "rollback_ready": True,
        "prepared_at": now,
        "from_version": next(iter(versions.values()), ""),
        "target_version": target_version,
        "validation": manifest["validation"],
        "repo_files_added": added,
    }


def _engine_version(env: Any, engine: str) -> str:
    pkg = km.engine_package(env.runner, env.distro, engine)
    return _upstream(pkg["version"]) if pkg and pkg.get("version") else ""
