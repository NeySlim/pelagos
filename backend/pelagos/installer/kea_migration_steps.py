# SPDX-License-Identifier: Apache-2.0
"""Kea 3.x migration on a node (architecture section 28): the `kea.migration` plans this node's
helper builds and records (`plan_kea_migration`), and the helper steps it runs as root.

Prepare (batch K3, design 13.4 decision 4) changes nothing Kea runs with: the target packages go
into the package manager's cache (`apt-get install --download-only`, `dnf download`), the exact
2.6 packages are kept for the return, the 2.6 files are saved and the converted 3.x files written
aside, never in `/etc/kea`. All of it (manifest, `private/`, `packages/`) lives in root's
`kmc.state_dir` (0700), outside the tree the service user owns; the service user's
`<var>/kea-migration/<id>/` only holds the lease copies of the window.
"""

from __future__ import annotations

import hashlib
import json
import logging
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

log = logging.getLogger(__name__)

PRIVATE = "private"
MANIFEST = "manifest.json"
SOURCES = "sources.json"  # private/: repository files this migration added, noted as soon as written
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
    if phase not in kmc.PHASES:
        raise ValueError(f"unknown Kea migration phase {phase!r}")
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
        "options": _options(request.get("options")),
    }
    if phase != kmc.PREPARE:
        return _switch_plan(env, phase, base, nodes, request, created_by)
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


def _options(raw: Any) -> dict[str, Any]:
    """The options a phase carries (section 28): checked here, the record keeps them."""
    raw = raw if isinstance(raw, dict) else {}
    out: dict[str, Any] = {}
    delay = raw.get("response_delay_milliseconds")
    if delay is not None:
        if not isinstance(delay, int) or isinstance(delay, bool) or not 1000 <= delay <= 60000:
            raise ValueError("response_delay_milliseconds must be an integer from 1000 to 60000")
        out["response_delay_milliseconds"] = delay
    if raw.get("auto_rollback") is not None:
        if not isinstance(raw["auto_rollback"], bool):
            raise ValueError("auto_rollback must be true or false")
        out["auto_rollback"] = raw["auto_rollback"]
    if raw.get("https_sockets"):
        # Not built: kea-ctrl-agent clients get their per-daemon control-sockets by hand (warning).
        raise ValueError("https_sockets is not available in this release: add control-sockets by hand")
    return out


# The migrate phase (K4 time 1, K5 the window and time 3) and the returns.
TURN_ROLES = ("backup", "standby")
FAMILY_OF = {"kea4": "4", "kea6": "6"}
Row = tuple[str, dict[str, Any], dict[str, Any], str, str]  # step, node, details, summary, stage


def _families(source: dict[str, Any], dest: dict[str, Any]) -> list[str]:
    return [FAMILY_OF[e] for e in source["engines"] if e in FAMILY_OF and e in dest["engines"]]


def _window(
    base: dict[str, Any],
    server: dict[str, Any],
    taker: dict[str, Any],
    others: list[dict[str, Any]],
    restore: bool,
) -> list[Row]:
    """Time 2: `server` stops and leaves its compacted leases, `taker` (stopped, files ready) takes
    them and starts alone until it is partner-down; the other nodes take the same leases."""
    w = "window"
    rows: list[Row] = [
        (kmc.H_STOP, server, {"export_leases": True, "outage_start": True}, "Kea stopped, leases exported", w)
    ]
    for node in [*others, taker]:
        fam = _families(server, node)
        src = {"from_node": server["node_id"], "from_name": server["name"], "families": fam}
        rows += [
            (kmc.D_FETCH_LEASES, node, src, f"{server['name']}'s lease file copied over mTLS", w),
            (kmc.H_LEASES_IN, node, src, f"{server['name']}'s lease file in place", w),
        ]
    start = {"engines": taker["engines"], **({"restore": True} if restore else {})}
    rows += [
        (kmc.H_START, taker, start, "Kea started alone", w),
        (kmc.D_WAIT_PARTNER_DOWN, taker, {"outage_end": True}, "partner-down and leases answering", w),
    ]
    for node in others:
        rows.append(
            (
                kmc.H_START,
                node,
                {"engines": node["engines"], **({"restore": True} if restore else {})},
                "Kea started",
                w,
            )
        )
    return rows


def _settle(nodes: list[dict[str, Any]], waits: list[dict[str, Any]], stage: str) -> list[Row]:
    rows: list[Row] = [(kmc.D_WAIT_HA, n, {}, "HA back to its normal state", stage) for n in waits]
    rows += [(kmc.H_DELAYS, n, {}, "HA detection delays back", stage) for n in nodes]
    return rows


def _migrate_rows(
    base: dict[str, Any],
    primary: dict[str, Any],
    standby: dict[str, Any],
    backups: list[dict[str, Any]],
    stage: Any,
) -> list[Row]:
    series = base["series"]
    turns = [*backups, standby]
    rows: list[Row] = []
    if stage == "primary":
        # Resume of a time 3 that failed: the standby serves alone, the primary is done again.
        rows.append((kmc.H_STOP, primary, {}, "Kea stopped", "primary"))
    else:
        rows.append(
            (
                kmc.H_MAINTENANCE,
                primary,
                {"action": "start"},
                "HA maintenance: serves alone while its partner changes",
                "standby",
            )
        )
        for node in turns:
            rows += [
                (kmc.H_STOP, node, {}, "Kea stopped", "standby"),
                (
                    kmc.H_INSTALL,
                    node,
                    {"direction": "target"},
                    f"Kea {series} installed, files checked",
                    "standby",
                ),
                (
                    kmc.H_VALIDATE_PARTNER,
                    node,
                    {"partner": primary["node_id"], "partner_name": primary["name"]},
                    f"{primary['name']}'s Kea {series} files checked with its daemons",
                    "standby",
                ),
            ]
        rows += _window(base, primary, standby, backups, restore=False)
    rows += [
        (
            kmc.H_INSTALL,
            primary,
            {"direction": "target"},
            f"Kea {series} installed, files checked",
            "primary",
        ),
        (
            kmc.H_START,
            primary,
            {"engines": primary["engines"]},
            "Kea started, syncs from its partner",
            "primary",
        ),
    ]
    rows += _settle([standby, *backups, primary], [primary, standby], "primary")
    rows += [
        (kmc.H_FINISH, n, {}, "files only the way forward needed removed", "primary")
        for n in [*turns, primary]
    ]
    return rows


def _return_rows(
    base: dict[str, Any],
    primary: dict[str, Any],
    standby: dict[str, Any],
    backups: list[dict[str, Any]],
    stage: Any,
    touched: set[str],
) -> list[Row]:
    """Back to the previous series. Before time 3 (K4): the touched standby and backups return while
    the primary, still on it, serves or starts again. From time 3 on, the whole pair returns with the
    same short window: the node still serving changes last."""
    old = base["from_series"]
    turns = [*backups, standby]
    if stage not in ("primary", "done"):
        rows: list[Row] = []
        for node in turns:
            if node["node_id"] not in touched:
                continue
            rows += [
                (kmc.H_STOP, node, {}, "Kea stopped", "standby"),
                (
                    kmc.H_INSTALL,
                    node,
                    {"direction": "previous"},
                    f"Kea {old} packages and files back",
                    "standby",
                ),
                (kmc.H_START, node, {"engines": node["engines"], "restore": True}, "Kea started", "standby"),
            ]
        return [
            *rows,
            (
                kmc.H_START,
                primary,
                {"engines": primary["engines"], "restore": True},
                "Kea running",
                "standby",
            ),
            (
                kmc.H_MAINTENANCE,
                primary,
                {"action": "cancel"},
                "HA maintenance over, pair back to normal",
                "standby",
            ),
        ]
    back = {"direction": "previous"}
    if stage == "done":
        # The pair runs the target: the primary serves while its standby returns first.
        server, taker, first = primary, standby, turns
        rows = [(kmc.H_MAINTENANCE, primary, {"action": "start"}, "HA maintenance: serves alone", "standby")]
    else:
        # Time 3 failed: the standby serves alone (partner-down), the primary returns first.
        server, taker, first = standby, primary, [primary, *backups]
        rows = []
    for node in first:
        short = {"short_delays": node is taker}
        rows += [
            (kmc.H_STOP, node, {}, "Kea stopped", "standby"),
            (kmc.H_INSTALL, node, {**back, **short}, f"Kea {old} packages and files back", "standby"),
        ]
    rows += _window(base, server, taker, [n for n in first if n is not taker], restore=True)
    rows += [
        (kmc.H_INSTALL, server, back, f"Kea {old} packages and files back", "primary"),
        (kmc.H_START, server, {"engines": server["engines"], "restore": True}, "Kea started", "primary"),
    ]
    rows += _settle([taker, *[n for n in first if n is not taker], server], [primary, standby], "primary")
    return rows


def _single_rows(
    base: dict[str, Any], phase: str, nodes: list[dict[str, Any]], stage: Any, touched: set[str]
) -> list[Row]:
    """Nodes without HA: each one stops, changes and starts; its outage is that restart."""
    rows: list[Row] = []
    for node in nodes:
        if phase == kmc.MIGRATE:
            direction, what = "target", f"Kea {base['series']} installed, files checked"
            start = {"engines": node["engines"]}
        else:
            if stage != "done" and node["node_id"] not in touched:
                continue
            direction, what = "previous", f"Kea {base['from_series']} packages and files back"
            start = {"engines": node["engines"], "restore": True}
        rows += [
            (kmc.H_STOP, node, {"outage_start": True}, "Kea stopped", "window"),
            (kmc.H_INSTALL, node, {"direction": direction}, what, "window"),
            (kmc.H_START, node, start, "Kea started", "window"),
            (
                kmc.D_WAIT_PARTNER_DOWN,
                node,
                {"outage_end": True, "single": True},
                "leases answering",
                "window",
            ),
        ]
        if phase == kmc.MIGRATE:
            rows.append((kmc.H_FINISH, node, {}, "files only the way forward needed removed", "window"))
    return rows


def _switch_plan(
    env: Any,
    phase: str,
    base: dict[str, Any],
    nodes: list[dict[str, Any]],
    request: dict[str, Any],
    created_by: str,
) -> Plan:
    stage = request.get("stage")
    singles = [n for n in nodes if n["role"] == "single"]
    primaries = [n for n in nodes if n["role"] == "primary"]
    standbys = [n for n in nodes if n["role"] == "standby"]
    backups = [n for n in nodes if n["role"] == "backup"]
    raw = request.get("touched")
    touched = set(raw) if isinstance(raw, list) else {n["node_id"] for n in nodes if n["role"] != "primary"}
    if singles and len(singles) != len(nodes):
        raise ValueError("this release migrates one HA pair or nodes without HA, not both at once")
    if singles:
        rows = _single_rows(base, phase, singles, stage, touched)
    elif len(primaries) != 1 or len(standbys) != 1:
        raise ValueError("this release migrates one HA pair (a primary, its standby and its backups) only")
    elif phase == kmc.MIGRATE:
        if stage == "window":
            raise ValueError("a migration stopped in its window is rolled back, not resumed")
        rows = _migrate_rows(base, primaries[0], standbys[0], backups, stage)
    else:
        rows = _return_rows(base, primaries[0], standbys[0], backups, stage, touched)
    if not rows:
        raise ValueError("nothing to return: no node changed")
    changes = []
    for step, node, extra, what, row_stage in rows:
        node_row = {k: v for k, v in node.items() if k != "node_id"}
        details = {**base, "stage": row_stage, "node": node_row, "engines": node["engines"], **extra}
        after = {"step": step, "details": details, "summary": f"{node['name']}: {what}"}
        changes.append(
            Change(
                ChangeOp.REPLACE, kmc.target(step, node["node_id"]), after=after, node_ids=[node["node_id"]]
            )
        )
    names = ", ".join(n["name"] for n in nodes)
    series = base["series"] if phase == kmc.MIGRATE else base["from_series"]
    delay = base["options"].get("response_delay_milliseconds") or 10000
    summary = messages.msg(
        f"plan.kea_migration.{phase}",
        nodes=names,
        series=series,
        source=base["source"],
        outage=delay // 1000 + 10,
    )
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
        guarded = step in (kmc.H_PREPARE, kmc.H_STOP) or (
            step == kmc.H_MAINTENANCE and details.get("action") == "start"
        )
        if step == kmc.H_PREPARE:
            out.append(
                Step(
                    change.target,
                    lambda d=details: _no_rollout(env) or json.dumps(prepare(env, d), sort_keys=True),
                    10,
                )
            )
        elif step in SWITCH_STEPS:
            run = SWITCH_STEPS[step]
            out.append(
                Step(
                    change.target,
                    lambda d=details, r=run, g=guarded: (
                        (g and _no_rollout(env)) or json.dumps(r(env, d, plan.id), sort_keys=True)
                    ),
                    10,
                )
            )
        elif step in kmc.DRIVER_STEPS:
            raise ValueError(f"{step} runs in the driving node's service, not in the helper")
        else:
            raise ValueError(f"{step} is not available in this release")
    if not out:
        raise ValueError("no Kea migration step for this node")
    return out


def _no_rollout(env: Any) -> None:
    """Raises while an update rollout is active: a step that starts changing Kea waits for it
    (a rollout restarts the services that drive this migration). Later steps always run."""
    from pelagos.core import update_rollout
    from pelagos.core.config_store import ConfigStore

    paths = env.node_paths
    if not paths.cluster_toml.exists():
        return None
    try:
        settings = ConfigStore(paths.node_toml, paths.cluster_toml).load_cluster().settings
    except (OSError, ValueError) as exc:
        raise ValueError(f"cluster.toml unreadable: {exc}") from None
    why = update_rollout.rollout_blocks(settings if isinstance(settings, dict) else {})
    if why:
        raise ValueError(why)
    return None


def result_of(output: str) -> dict[str, Any]:
    """The JSON result a step printed as its output ({} when there is none)."""
    try:
        data = json.loads(output)
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


# Prepare -------------------------------------------------------------------------------------


def state_dir(env: Any, migration_id: str, create: bool = False) -> Path:
    """Root's directory of the migration (0700 root, beside the service user's tree)."""
    mdir = kmc.state_dir(env.node_paths, migration_id)
    if create:
        top = mdir.parent.parent
        if not top.is_dir():
            top.mkdir(mode=0o755, parents=True)
        _mkdir(mdir.parent)
        _mkdir(mdir)
    return mdir


def public_dir(env: Any, migration_id: str) -> Path:
    """The service user's directory of the migration, emptied: the lease copies of the window."""
    pub = kmc.migration_dir(env.node_paths.var, migration_id)
    if pub.is_symlink() or pub.is_file():
        pub.unlink()
    elif pub.exists():
        shutil.rmtree(pub)
    _mkdir(pub.parent, 0o750)
    pub.mkdir(mode=0o750)
    return pub


def bare_name(name: Any) -> str:
    """A file name of the manifest: one path component, never a way out of its directory."""
    name = str(name or "")
    if not name or name in (".", "..") or "/" in name or "\\" in name or "\0" in name:
        raise ValueError(f"{name!r} is not a bare file name")
    return name


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


def repo_files(env: Any, series: str, source: str) -> list[Any]:
    """The repository files a migration to (series, source) may add on this node."""
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
    return files


def add_sources(env: Any, series: str, source: str, added: list[str] | None = None) -> list[str]:
    """The target's repository next to the node's own (ISC Cloudsmith with its key, or Debian
    backports), then the index refreshed; returns the files it added (removed by the return).
    `added` receives each file as soon as it is written, so a failure later still knows it."""
    added = [] if added is None else added
    for f in repo_files(env, series, source):
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


def apt_archives(dest: Path) -> list[str]:
    """apt options that make `dest` its package cache: apt's autoclean never reaches it."""
    return ["-o", f"Dir::Cache::archives={dest}/", "-o", "APT::Sandbox::User=root"]


def download_target(env: Any, packages: list[dict[str, str]], dest: Path) -> list[dict[str, str]]:
    """The target packages at their exact versions in root's `dest` (apt's cache for this run, dnf's
    destdir), dependencies included, so the switch needs no network. Nothing is installed."""
    specs = [p for p in packages if p.get("version")]
    if len(specs) != len(packages):
        raise PrepareError("a target package has no version: analyze again")
    out = []
    _mkdir(dest)
    if env.distro.is_debian:
        _mkdir(dest / "partial")
        argv = ["apt-get", "install", "--download-only", "-y", "-q", *apt_archives(dest)]
        res = _run(env, [*argv, *(f"{p['name']}={p['version']}" for p in specs)])
        if not res.ok:
            raise PrepareError(f"download of the target packages failed: {res.output.strip()[-400:]}")
        for p in specs:
            found = sorted(dest.glob(_deb_prefix(p["name"], p["version"]) + "*.deb"))
            if not found:
                raise PrepareError(f"{p['name']} {p['version']} was not downloaded")
            out.append({**p, "file": found[0].name, "sha256": _sha256(found[0])})
    elif env.distro.is_rhel:
        argv = ["dnf", "-q", "download", "--resolve", f"--destdir={dest}"]
        res = _run(env, [*argv, *(f"{p['name']}-{p['version']}" for p in specs)])
        if not res.ok:
            raise PrepareError(f"download of the target packages failed: {res.output.strip()[-400:]}")
        for p in specs:
            found = sorted(dest.glob(f"{p['name']}-{p['version']}.*.rpm"))
            if not found:
                raise PrepareError(f"{p['name']} {p['version']} was not downloaded")
            out.append({**p, "file": found[0].name, "sha256": _sha256(found[0])})
    else:
        raise PrepareError(f"no package manager for {env.distro.id}")
    return out


def package_files(dest: Path) -> list[dict[str, str]]:
    """Every package file of `dest` (the target and its dependencies) with its sum."""
    return [
        {"file": p.name, "sha256": _sha256(p)}
        for p in sorted(dest.iterdir())
        if p.suffix in (".deb", ".rpm") and p.is_file() and not p.is_symlink()
    ]


def _noted_sources(mdir: Path) -> list[str]:
    try:
        data = json.loads((mdir / PRIVATE / SOURCES).read_text())
    except (OSError, ValueError):
        return []
    return [str(p) for p in data if isinstance(p, str)] if isinstance(data, list) else []


def remove_sources(env: Any, names: list[str]) -> None:
    """The repository files a failed prepare added, removed and the index refreshed."""
    for name in names:
        path = env.paths.root / name.lstrip("/")
        if path.is_file() or path.is_symlink():
            path.unlink()
    if names:
        try:
            env.packages.refresh()
        except Exception as exc:  # the next refresh catches up; the sources are gone either way
            log.warning("package index refresh after removing %s failed: %s", names, exc)


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
    mdir = state_dir(env, migration_id)
    leftover = _noted_sources(mdir)  # an earlier run of this prepare that stopped half way
    if mdir.exists():
        shutil.rmtree(mdir)  # a prepare run again starts over
    state_dir(env, migration_id, create=True)
    public_dir(env, migration_id)
    private = _mkdir(mdir / PRIVATE)
    if leftover:
        _write(private / SOURCES, json.dumps(leftover) + "\n")
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
    added: list[str] = list(leftover)
    try:
        news: list[str] = []
        try:
            add_sources(env, series, source, news)
        finally:
            added += [n for n in news if n not in added]
            _write(private / SOURCES, json.dumps(added) + "\n")
        previous = keep_previous(env, installed, mdir / "packages" / "previous")
        downloaded = download_target(env, target, mdir / "packages" / "target")
        target_files = package_files(mdir / "packages" / "target")
    except BaseException:
        remove_sources(env, added)
        (private / SOURCES).unlink(missing_ok=True)
        raise
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
        "target_files": target_files,
        "packages_remove": report["packages"].get("remove") or [],
        "repo_files_added": added,
        "validation": {e: v.get("mode") for e, v in report["validation"].items()},
    }
    _write(mdir / MANIFEST, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    sealed = _seal_for_partner(env, migration_id, keep["conversions"])
    return {
        "files_sealed": sealed,
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


def _seal_for_partner(env: Any, migration_id: str, conversions: dict[str, mig.Conversion]) -> str | None:
    """The converted files and their TSIG secrets under the cluster master key: the standby checks
    them with its installed 3.x daemons before the window (kea-mig-validate-partner)."""
    key = env.node_paths.master_key
    if not key.exists():
        return None
    from pelagos.core.secrets import SecretBox

    bundle = {
        "configs": {engine: conv.after for engine, conv in conversions.items()},
        "secrets": {p: s for conv in conversions.values() for p, s in conv.files.items()},
    }
    return kmc.seal_files(SecretBox.from_file(key), migration_id, env.node_id, bundle)


def _engine_version(env: Any, engine: str) -> str:
    pkg = km.engine_package(env.runner, env.distro, engine)
    return _upstream(pkg["version"]) if pkg and pkg.get("version") else ""


def _switch_steps() -> dict[str, Any]:
    from pelagos.installer import kea_migration_switch as sw

    return {
        kmc.H_MAINTENANCE: lambda env, d, plan_id: sw.maintenance(env, d, plan_id),
        kmc.H_STOP: lambda env, d, _p: sw.stop(env, d),
        kmc.H_INSTALL: lambda env, d, _p: sw.install(env, d),
        kmc.H_VALIDATE_PARTNER: lambda env, d, _p: sw.validate_partner(env, d),
        kmc.H_START: lambda env, d, _p: sw.start(env, d),
        kmc.H_LEASES_IN: lambda env, d, _p: sw.leases_in(env, d),
        kmc.H_DELAYS: lambda env, d, plan_id: sw.delays(env, d, plan_id),
        kmc.H_FINISH: lambda env, d, _p: sw.finish(env, d),
    }


SWITCH_STEPS = _switch_steps()
