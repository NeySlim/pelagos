# SPDX-License-Identifier: Apache-2.0
"""Updates from the UI, root side (docs/architecture.md section 29, batch U2).

The helper operations `update_verify`, `update_start`, `update_status`, `journal_errors`, and
`pelagos upgrade apply`, which the transient unit `pelagos-upgrade-<rollout id>` runs: stop the
services, back up the node state, install, check the version. The checks after the install (health,
convergence, journal) belong to the new processes (U3). Root's files live in `Paths.upgrade_dir`,
outside the service user's tree; only `incoming/` is the service user's, and it is read without
following links. Every module the apply needs is imported here: the package swaps the code under it.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import stat
import tarfile
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pelagos.core import engine_packages
from pelagos.core import release as rel
from pelagos.core.config_store import ConfigStore
from pelagos.domain.updates import (
    CHECKSUMS,
    JOURNAL_UNITS,
    PACKAGE_NAME,
    ROLLOUT_ID_RE,
    SANDBOX_DENIED,
    SIGNATURE,
    Rollout,
    RolloutKind,
    parse_checksums,
    safe_file,
    valid_version,
)
from pelagos.platform import versions

UNIT_PREFIX = "pelagos-upgrade-"
SERVICES = ("pelagos.service", "pelagos-collector.service")
PELAGOS_BIN = "/usr/bin/pelagos"
JOURNAL_MAX_LINES = 200
JOURNAL_SCAN = 20000
MAX_RELEASE_BYTES = 1 << 30
KEEP_DEFAULT = 2
# After the install both units must stay active, without a restart, this long (within the
# timeout): a web unit in a restart loop also restarts the collector (PartOf=), so no process
# would be left to run the checks and roll back. Root does it here instead.
UNITS_STABLE_SECONDS = 20.0
UNITS_TIMEOUT_SECONDS = 180.0
_ENGINE_PACKAGE_VERSION = re.compile(r"^[A-Za-z0-9.+~:_-]{1,64}$")
_DEB = re.compile(r"^pelagos_(?P<version>[^_/]+)_(?P<arch>amd64|arm64)\.deb$")
_RPM = re.compile(r"^pelagos-(?P<version>[^-/]+-[^/]+?)\.(?P<arch>x86_64|aarch64)\.rpm$")


class UpdateRefused(ValueError):
    """Bad input or a release the rules refuse; the message starts with the reason code."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_root() -> bool:
    return os.geteuid() == 0


def _pelagos_gid() -> int | None:
    import grp

    try:
        return grp.getgrnam(PACKAGE_NAME).gr_gid
    except KeyError:
        return None


# Layout -------------------------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class Layout:
    root: Path  # root:pelagos 0750
    incoming: Path  # the service user's

    @property
    def packages_root(self) -> Path:
        return self.root / "packages"

    def packages(self, version: str) -> Path:
        return self.packages_root / version

    @property
    def backups(self) -> Path:
        return self.root / "backups"

    def rollout_dir(self, rollout_id: str) -> Path:
        return self.root / rollout_id

    def progress(self, rollout_id: str, node_id: str) -> Path:
        return self.rollout_dir(rollout_id) / f"{node_id}.json"

    def request(self, rollout_id: str) -> Path:
        return self.rollout_dir(rollout_id) / "request.json"

    @property
    def installed(self) -> Path:
        """{"release", "package_version"} of the last install through this helper."""
        return self.root / "installed.json"

    @property
    def previous(self) -> Path:
        """{"release", "package_version"} of what that install replaced: the rollback target."""
        return self.root / "previous.json"


def layout(env: Any) -> Layout:
    return Layout(env.node_paths.upgrade_dir, env.node_paths.upgrade_incoming)


def _mkdir(path: Path, mode: int, group: bool, keep_mode: bool = False) -> None:
    """A root-owned folder (group pelagos when `group`); a symlink or foreign owner is refused.
    With `keep_mode`, an existing folder keeps its mode but must not be writable by others."""
    existed = os.path.lexists(path)
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode):
        raise UpdateRefused("layout", f"{path} is not a folder")
    if existed and keep_mode:
        if st.st_uid != os.geteuid() or st.st_mode & 0o022:
            raise UpdateRefused("layout", f"{path} is writable by another user")
        return
    if _is_root():
        gid = _pelagos_gid() if group else 0
        os.chown(path, 0, gid if gid is not None else 0, follow_symlinks=False)
    elif st.st_uid != os.geteuid():
        raise UpdateRefused("layout", f"{path} is not owned by this user")
    os.chmod(path, mode)


def ensure_layout(env: Any) -> Layout:
    lay = layout(env)
    _mkdir(lay.root.parent, 0o755, False, keep_mode=True)
    _mkdir(lay.root, 0o750, True)
    _mkdir(lay.packages_root, 0o750, True)
    _mkdir(lay.backups, 0o700, False)
    return lay


def _write_json(path: Path, data: dict[str, Any], mode: int, group: bool) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=1, sort_keys=True, default=str)
        fh.write("\n")
    if _is_root():
        gid = _pelagos_gid() if group else 0
        os.chown(tmp, 0, gid if gid is not None else 0)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


# Node facts -----------------------------------------------------------------------------------------


@dataclass(slots=True)
class NodeFacts:
    package_format: str  # deb | rpm
    arch: str
    installed: str | None  # package version of pelagos, None when not installed by a package


def node_facts(env: Any) -> NodeFacts:
    kind = env.distro.package_manager
    if kind == "apt":
        arch = env.runner.run(["dpkg", "--print-architecture"], check=False, mutates=False, timeout=30)
        fmt = "deb"
    elif kind == "dnf":
        arch = env.runner.run(["rpm", "--eval", "%{_arch}"], check=False, mutates=False, timeout=30)
        fmt = "rpm"
    else:
        raise UpdateRefused("arch", f"no deb or rpm package manager on {env.distro.id}")
    return NodeFacts(fmt, arch.stdout.strip() or "unknown", installed_version(env, fmt))


def installed_version(env: Any, package_format: str, package: str = PACKAGE_NAME) -> str | None:
    if package_format == "deb":
        argv = ["dpkg-query", "-W", "-f=${Status}|${Version}", package]
    else:
        argv = ["rpm", "-q", "--qf", "installed|%{VERSION}-%{RELEASE}", package]
    res = env.runner.run(argv, check=False, mutates=False, timeout=30)
    if not res.ok:
        return None
    status, _, version = res.stdout.strip().partition("|")
    if package_format == "deb" and not status.endswith(" installed"):
        return None
    return version or None


def inspect_package(env: Any, package_format: str, path: Path) -> dict[str, str]:
    """Name, version and architecture read from the package itself, never from its file name."""
    if package_format == "deb":
        argv = ["dpkg-deb", "-f", str(path), "Package", "Version", "Architecture"]
        res = env.runner.run(argv, check=False, mutates=False, timeout=60)
        fields = dict(
            (k.strip().lower(), v.strip())
            for k, _, v in (line.partition(":") for line in res.stdout.splitlines())
        )
        out = {
            "name": fields.get("package", ""),
            "version": fields.get("version", ""),
            "arch": fields.get("architecture", ""),
        }
    else:
        qf = "%{NAME}|%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}|%{ARCH}"
        res = env.runner.run(
            ["rpm", "-qp", "--nosignature", "--nodigest", "--qf", qf, str(path)],
            check=False,
            mutates=False,
            timeout=60,
        )
        parts = res.stdout.strip().split("|")
        out = dict(zip(("name", "version", "arch"), parts, strict=False)) if len(parts) == 3 else {}
    if not res.ok or not out.get("name"):
        raise UpdateRefused("name", f"{path.name} is not a readable {package_format} package")
    return out


# Copy of an uploaded release ------------------------------------------------------------------------


def _open_in(dirfd: int, name: str) -> int | None:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirfd)
    except FileNotFoundError:
        return None
    except OSError as exc:  # ELOOP: a symlink
        raise UpdateRefused("missing", f"{name} is not a regular file ({exc.strerror})") from None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise UpdateRefused("missing", f"{name} is not a regular file")
    return fd


def _copy_release(source: Path, dest: Path) -> int:
    """Copies SHA256SUMS, its signature and the files it lists from `source` (the service user's,
    read without following links) into the new folder `dest`, root:pelagos 0750, files 0640."""
    try:
        dirfd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise UpdateRefused("missing", f"no release folder {source.name} ({exc.strerror})") from None
    total = 0
    try:
        fd = _open_in(dirfd, CHECKSUMS)
        if fd is None:
            raise UpdateRefused("missing", f"no {CHECKSUMS}")
        with os.fdopen(fd, "rb") as fh:
            sums_bytes = fh.read((1 << 20) + 1)
        if len(sums_bytes) > 1 << 20:
            raise UpdateRefused("checksum", f"{CHECKSUMS} is too large")
        try:
            names = list(parse_checksums(sums_bytes.decode("utf-8")))
        except (UnicodeDecodeError, ValueError) as exc:
            raise UpdateRefused("checksum", str(exc)) from None
        gid = _pelagos_gid() if _is_root() else None
        for name in dict.fromkeys([CHECKSUMS, SIGNATURE, *names]):
            if not safe_file(name):
                raise UpdateRefused("checksum", f"unsafe file name {name!r}")
            fd = _open_in(dirfd, name)
            if fd is None:
                continue  # a missing listed file: verify_release refuses it
            target = dest / name
            out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
            with os.fdopen(fd, "rb") as src, os.fdopen(out, "wb") as dst:
                while chunk := src.read(1 << 20):
                    total += len(chunk)
                    if total > MAX_RELEASE_BYTES:
                        raise UpdateRefused("checksum", f"release larger than {MAX_RELEASE_BYTES >> 20} MiB")
                    dst.write(chunk)
            if gid is not None:
                os.chown(target, 0, gid)
            os.chmod(target, 0o640)
    finally:
        os.close(dirfd)
    return total


# Rules ----------------------------------------------------------------------------------------------


@dataclass(slots=True)
class Verified:
    version: str
    folder: Path
    file: str
    sha256: str
    package_version: str
    direction: str  # upgrade | rollback
    facts: NodeFacts
    check: Any  # core.release.ReleaseCheck

    def answer(self) -> dict[str, Any]:
        m = self.check.manifest
        return {
            "version": self.version,
            "package": self.file,
            "sha256": self.sha256,
            "signature": self.check.signature.value,
            "key_id": self.check.key_id,
            "state_schema": m.state_schema if m else None,
            "min_upgrade_from": m.min_upgrade_from if m else None,
            "arch": self.facts.arch,
            "package_format": self.facts.package_format,
            "package_version": self.package_version,
            "installed": self.facts.installed,
            "direction": self.direction,
            "checksums_sha256": self.check.checksums_sha256,
            "warnings": list(self.check.warnings),
        }


def release_keys() -> dict[str, Any]:
    return rel.load_public_keys()


def _pick(check: Any, facts: NodeFacts) -> tuple[str, str | None]:
    """The package file for this node's format and architecture, with the version it declares."""
    if check.manifest is not None:
        pkg = check.manifest.package_for(facts.package_format, facts.arch)
        if pkg is None:
            raise UpdateRefused("arch", f"no {facts.package_format} package for {facts.arch} in this release")
        return pkg.file, pkg.version
    pattern = _DEB if facts.package_format == "deb" else _RPM
    found = [n for n in check.checksums if (m := pattern.fullmatch(n)) and m["arch"] == facts.arch]
    if len(found) != 1:
        raise UpdateRefused(
            "arch", f"{len(found)} {facts.package_format} packages for {facts.arch} in this release"
        )
    return found[0], None


def verify(env: Any, version: str, allow_unsigned: bool, keys: dict[str, Any] | None = None) -> Verified:
    """`update_verify`: the verified copy in packages/<version> (from incoming/<version> when there
    is one), checked against the sums, the signature, the manifest and this node's rules."""
    if not isinstance(version, str) or not valid_version(version):
        raise UpdateRefused("version", f"invalid version {version!r}")
    lay = ensure_layout(env)
    dest = lay.packages(version)
    keys = release_keys() if keys is None else keys
    source = lay.incoming / version
    if os.path.lexists(source):
        tmp = Path(tempfile.mkdtemp(prefix=f".{version}.", dir=lay.packages_root))
        try:
            _copy_release(source, tmp)
            check = _check(tmp, keys, allow_unsigned)
            verified = _rules(env, lay, version, tmp, check)
            if _is_root() and (gid := _pelagos_gid()) is not None:
                os.chown(tmp, 0, gid)
            os.chmod(tmp, 0o750)  # noqa: S103 - the web process serves the release to peers
            if dest.exists():
                shutil.rmtree(dest)
            os.rename(tmp, dest)
        finally:
            if tmp.exists():
                shutil.rmtree(tmp, ignore_errors=True)
        shutil.rmtree(source, ignore_errors=True)
        verified.folder = dest
        return verified
    if not dest.is_dir():
        raise UpdateRefused("missing", f"release {version} was neither uploaded nor fetched on this node")
    return _rules(env, lay, version, dest, _check(dest, keys, allow_unsigned))


def _check(folder: Path, keys: dict[str, Any], allow_unsigned: bool) -> Any:
    try:
        check = rel.verify_release(folder, keys)
        check.require_accepted(allow_unsigned)
    except rel.ReleaseRefused as exc:
        raise UpdateRefused(exc.reason, exc.detail) from None
    return check


def _rules(env: Any, lay: Layout, version: str, folder: Path, check: Any) -> Verified:
    if check.manifest is not None and check.manifest.version != version:
        raise UpdateRefused("version", f"release.json says {check.manifest.version}, not {version}")
    facts = node_facts(env)
    name, declared = _pick(check, facts)
    path = folder / name
    sha = rel.file_sha256(path)
    if sha != check.checksums[name]:
        raise UpdateRefused("checksum", f"{name} does not match {CHECKSUMS}")
    fields = inspect_package(env, facts.package_format, path)
    if fields["name"] != PACKAGE_NAME:
        raise UpdateRefused("name", f"{name} is the package {fields['name']!r}, not {PACKAGE_NAME}")
    if fields["arch"] != facts.arch:
        raise UpdateRefused("arch", f"{name} is for {fields['arch']}, this node is {facts.arch}")
    pkg_version = fields["version"]
    if declared is not None and declared != pkg_version:
        raise UpdateRefused("manifest", f"{name} is version {pkg_version}, release.json says {declared}")
    fmt, installed = facts.package_format, facts.installed
    if installed is None or versions.compare(fmt, pkg_version, installed) > 0:
        direction = "upgrade"
        floor = check.manifest.min_upgrade_from if check.manifest else None
        if floor and installed and versions.compare(fmt, versions.upstream(fmt, installed), floor) < 0:
            raise UpdateRefused(
                "version", f"{version} needs at least {floor} installed, this node has {installed}"
            )
    elif (_read_json(lay.previous) or {}).get("package_version") == pkg_version and pkg_version != installed:
        direction = "rollback"
    else:
        raise UpdateRefused(
            "version",
            f"{pkg_version} is neither newer than the installed {installed} nor the kept previous version",
        )
    return Verified(version, folder, name, sha, pkg_version, direction, facts, check)


# Start, status ------------------------------------------------------------------------------------


def _active_upgrade_units(env: Any) -> list[str]:
    res = env.runner.run(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=active,activating,deactivating,reloading",
            "--plain",
            "--no-legend",
            "--no-pager",
            f"{UNIT_PREFIX}*",
        ],
        check=False,
        mutates=False,
        timeout=30,
    )
    return [line.split()[0] for line in res.stdout.splitlines() if line.strip().startswith(UNIT_PREFIX)]


def _rollout_of(env: Any) -> Rollout | None:
    """The rollout cluster.toml holds; the helper starts nothing that is not in it."""
    paths = env.node_paths
    try:
        cluster = ConfigStore(paths.node_toml, paths.cluster_toml).load_cluster()
    except (OSError, ValueError) as exc:
        raise UpdateRefused("rollout", f"cluster.toml unreadable: {exc}") from None
    updates = cluster.settings.get("updates") if isinstance(cluster.settings, dict) else None
    return Rollout.from_toml((updates or {}).get("rollout") or {})


def _engine_packages(env: Any, packages: Any) -> dict[str, str]:
    """Engine packages of this host's layout, each at a version the package manager will accept.
    A BIND or Kea name of another distribution (a mixed cluster) is left out, anything else refused."""
    if not isinstance(packages, dict) or not packages:
        raise UpdateRefused("name", "no engine package")
    p = env.paths
    allowed = set(p.bind_packages) | set(p.kea_packages_distro) | set(p.kea_packages_isc)
    out: dict[str, str] = {}
    for name, version in packages.items():
        if name not in allowed and engine_packages.family_of(str(name)) is None:
            raise UpdateRefused("name", f"{name} is not a BIND or Kea package of this host")
        if not isinstance(version, str) or not _ENGINE_PACKAGE_VERSION.fullmatch(version):
            raise UpdateRefused("version", f"invalid version {version!r} for {name}")
        if name in allowed:
            out[name] = version
    return out


def _engine_targets(env: Any, fmt: str, packages: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    """({package: version} to install, {package: installed version}): the requested packages
    installed here, plus their installed siblings of the same source package at the same version
    (kea-common, bind9-libs), so the package manager never has to remove one. Within the series only:
    a change of Kea series is the migration of design 13.4."""
    present = {n: v for n, v in packages.items() if installed_version(env, fmt, n)}
    if not present:
        raise UpdateRefused("nothing", f"none of {', '.join(sorted(packages))} is installed here")
    installed: dict[str, str] = {}
    for name, version in present.items():
        now = str(installed_version(env, fmt, name))
        if versions.compare(fmt, version, now) <= 0:
            raise UpdateRefused("version", f"{name} {version} is not newer than the installed {now}")
        if engine_packages.series(version) != engine_packages.series(now):
            raise UpdateRefused(
                "version", f"{name} {now} to {version} changes series: that is the Kea migration"
            )
        installed[name] = now
    targets = dict(present)
    for name, version in _siblings(env, fmt, present).items():
        if name not in targets:
            targets[name] = version
            installed[name] = str(installed_version(env, fmt, name))
    return targets, installed


def _siblings(env: Any, fmt: str, present: dict[str, str]) -> dict[str, str]:
    if fmt == "deb":
        fields = "${db:Status-Abbrev}\t${Package}\t${source:Package}\t${Version}\n"
        argv = ["dpkg-query", "-W", f"-f={fields}"]
    else:
        argv = ["rpm", "-qa", "--qf", "%{NAME}\t%{SOURCERPM}\t%{VERSION}\n"]
    res = env.runner.run(argv, check=False, mutates=False, timeout=60)
    rows: list[tuple[str, str]] = []
    for line in res.stdout.splitlines() if res.ok else []:
        parts = line.split("\t")
        if fmt == "deb" and len(parts) >= 3 and parts[0].startswith("ii"):
            rows.append((parts[1], parts[2].split(" ")[0]))
        elif fmt == "rpm" and len(parts) >= 2:
            rows.append((parts[0], parts[1]))
    source_of = dict(rows)
    out: dict[str, str] = {}
    for name, version in present.items():
        source = source_of.get(name)
        if not source:
            continue
        for other, other_source in rows:
            if other_source != source or other in present or other in out:
                continue
            if fmt == "rpm" or _apt_candidate(env, other) == version:
                out[other] = version
    return out


def _apt_candidate(env: Any, name: str) -> str | None:
    res = env.runner.run(["apt-cache", "policy", name], check=False, mutates=False, timeout=60)
    for line in res.stdout.splitlines() if res.ok else []:
        key, _, value = line.strip().partition(":")
        if key == "Candidate":
            value = value.strip()
            return None if value in ("", "(none)") else value
    return None


def start(env: Any, request: dict[str, Any], keys: dict[str, Any] | None = None) -> dict[str, Any]:
    """`update_start`: verifies again, writes the request root keeps, runs the transient unit."""
    rid = str(request.get("rollout_id") or "")
    if not ROLLOUT_ID_RE.fullmatch(rid):
        raise UpdateRefused("rollout", f"invalid rollout id {rid!r}")
    try:
        kind = RolloutKind(str(request.get("kind") or ""))
    except ValueError:
        raise UpdateRefused("rollout", f"unknown kind {request.get('kind')!r}") from None
    allow_unsigned = request.get("allow_unsigned") is True
    running = _active_upgrade_units(env)
    if running:
        raise UpdateRefused("busy", f"an update is already running here ({', '.join(running)})")
    rollout = _rollout_of(env)
    if rollout is None or rollout.id != rid or not rollout.active():
        raise UpdateRefused("rollout", f"rollout {rid} is not the active rollout of cluster.toml")
    if env.node_id not in rollout.order and env.node_id not in rollout.nodes:
        raise UpdateRefused("rollout", f"this node is not part of rollout {rid}")
    keep = request.get("keep_packages")
    keep = keep if isinstance(keep, int) and not isinstance(keep, bool) and 1 <= keep <= 20 else KEEP_DEFAULT
    record: dict[str, Any] = {
        "rollout_id": rid,
        "node_id": env.node_id,
        "kind": kind.value,
        "keep_packages": keep,
        "created_at": _now(),
    }
    if kind is RolloutKind.ENGINE_PACKAGES:
        if rollout.kind != RolloutKind.ENGINE_PACKAGES.value:
            raise UpdateRefused("rollout", f"rollout {rid} is not an engine packages rollout")
        requested = request.get("packages")
        packages = _engine_packages(env, requested)
        if any(rollout.packages.get(n) != v for n, v in requested.items()):
            raise UpdateRefused("version", f"packages differ from rollout {rid}")
        facts = node_facts(env)
        targets, installed = _engine_targets(env, facts.package_format, packages)
        record.update(
            packages=targets,
            requested=sorted(packages),
            package_format=facts.package_format,
            from_versions=installed,
        )
    else:
        version = str(request.get("version") or "")
        if kind is RolloutKind.PELAGOS and (rollout.kind != kind.value or rollout.version != version):
            raise UpdateRefused("version", f"rollout {rid} installs {rollout.version}, not {version}")
        if kind is RolloutKind.ROLLBACK and rollout.kind == kind.value and rollout.version != version:
            raise UpdateRefused("version", f"rollout {rid} goes back to {rollout.version}, not {version}")
        if kind is RolloutKind.ROLLBACK and rollout.kind == RolloutKind.ENGINE_PACKAGES.value:
            raise UpdateRefused("rollout", f"rollout {rid} is an engine packages rollout")
        v = verify(env, version, allow_unsigned, keys)
        wanted = "rollback" if kind is RolloutKind.ROLLBACK else "upgrade"
        if v.direction != wanted:
            raise UpdateRefused("version", f"{v.package_version} is a {v.direction}, not a {wanted}")
        # An unsigned upgrade needs the extra confirmation recorded in the rollout; going back to
        # the version this node ran before does not.
        if (
            v.check.signature.needs_acceptance
            and kind is RolloutKind.PELAGOS
            and not rollout.unsigned_accepted_by
        ):
            raise UpdateRefused("unsigned_not_accepted", f"rollout {rid} does not record the acceptance")
        record.update(
            auto_rollback=kind is RolloutKind.PELAGOS
            and rollout.auto_rollback
            and not rollout.state_schema_changed,
            version=version,
            package=str(v.folder / v.file),
            sha256=v.sha256,
            package_version=v.package_version,
            package_format=v.facts.package_format,
            from_version=v.facts.installed,
            signature=v.check.signature.value,
            key_id=v.check.key_id,
        )
    lay = ensure_layout(env)
    _mkdir(lay.rollout_dir(rid), 0o750, True)
    _write_json(lay.request(rid), record, 0o600, False)
    progress = lay.progress(rid, env.node_id)
    unit = f"{UNIT_PREFIX}{rid}"
    env.runner.run(["systemctl", "reset-failed", f"{unit}.service"], check=False, timeout=30)
    argv = [
        "systemd-run",
        f"--unit={unit}",
        f"--description=Pelagos update {rid}",
        "--property=RuntimeMaxSec=7200",
        *[f"--setenv={k}={os.environ[k]}" for k in _PATH_ENV if os.environ.get(k)],
        _pelagos_bin(),
        "upgrade",
        "apply",
        "--rollout",
        rid,
    ]
    res = env.runner.run(argv, privileged=True, check=False, timeout=60)
    if not res.ok:
        raise RuntimeError(f"systemd-run failed: {res.output}")
    return {"unit": f"{unit}.service", "progress": str(progress)}


_PATH_ENV = ("PELAGOS_HOME", "PELAGOS_ETC", "PELAGOS_VAR", "PELAGOS_RUN", "PELAGOS_OPT")


def _pelagos_bin() -> str:
    return PELAGOS_BIN if os.path.exists(PELAGOS_BIN) else shutil.which("pelagos") or PELAGOS_BIN


def unit_state(env: Any, rollout_id: str) -> str:
    """`active`, `inactive`, `failed` or `gone` (no such unit: never started, collected, rebooted)."""
    res = env.runner.run(
        ["systemctl", "show", "-p", "LoadState", "-p", "ActiveState", f"{UNIT_PREFIX}{rollout_id}.service"],
        check=False,
        mutates=False,
        timeout=30,
    )
    props = dict(line.partition("=")[::2] for line in res.stdout.splitlines())
    active = props.get("ActiveState", "")
    if not res.ok or props.get("LoadState", "not-found") == "not-found":
        return "gone"
    if active in ("active", "activating", "deactivating", "reloading"):
        return "active"
    return "failed" if active == "failed" else "inactive"


def package_audit(env: Any, package_format: str) -> dict[str, Any]:
    """`dpkg --audit` or `rpm -V pelagos`: a package left half installed by a reboot."""
    argv = ["dpkg", "--audit"] if package_format == "deb" else ["rpm", "-V", PACKAGE_NAME]
    res = env.runner.run(argv, check=False, mutates=False, timeout=120)
    return {"command": " ".join(argv), "ok": res.ok and not res.stdout.strip(), "output": res.output[-4000:]}


def status(env: Any, request: dict[str, Any]) -> dict[str, Any]:
    """`update_status`: the progress file, the unit state, and the package audit for a progress
    left `running` by a unit that no longer runs."""
    rid = str(request.get("rollout_id") or "")
    if not ROLLOUT_ID_RE.fullmatch(rid):
        raise UpdateRefused("rollout", f"invalid rollout id {rid!r}")
    lay = layout(env)
    progress = _read_json(lay.progress(rid, env.node_id))
    state = unit_state(env, rid)
    out: dict[str, Any] = {
        "rollout_id": rid,
        "unit": f"{UNIT_PREFIX}{rid}.service",
        "unit_state": state,
        "progress": progress,
        "package_audit": None,
    }
    if progress and progress.get("result") == "running" and state != "active":
        record = _read_json(lay.request(rid)) or {}
        fmt = record.get("package_format") or ("deb" if env.distro.package_manager == "apt" else "rpm")
        out["package_audit"] = package_audit(env, fmt)
        out["installed"] = installed_version(env, fmt)
    return out


# Journal --------------------------------------------------------------------------------------------


def _since_epoch(since: Any) -> int:
    if isinstance(since, bool):
        raise UpdateRefused("since", "since must be a time")
    if isinstance(since, int | float):
        value = float(since)
    elif isinstance(since, str):
        try:
            value = float(since)
        except ValueError:
            try:
                value = datetime.fromisoformat(since.replace("Z", "+00:00")).timestamp()
            except ValueError:
                raise UpdateRefused("since", f"invalid time {since!r}") from None
    else:
        raise UpdateRefused("since", "since must be an epoch or an ISO 8601 time")
    if not 0 < value < time.time() + 86400:
        raise UpdateRefused("since", f"time {since!r} out of range")
    return int(value)


def journal_errors(env: Any, request: dict[str, Any]) -> dict[str, Any]:
    """`journal_errors`: lines of priority err or above, or logged by Python at ERROR (the units log
    on stderr, which the journal stores at info), from the node's own units since `since`."""
    since = _since_epoch(request.get("since"))
    argv = ["journalctl", "--no-pager", "-o", "json", "--since", f"@{since}", "-n", str(JOURNAL_SCAN)]
    for unit in JOURNAL_UNITS:
        argv += ["-u", unit]
    res = env.runner.run(argv, check=False, mutates=False, timeout=120)
    lines: list[dict[str, Any]] = []
    count = 0
    for raw in res.stdout.splitlines():
        try:
            entry = json.loads(raw)
        except ValueError:
            continue
        msg = entry.get("MESSAGE")
        msg = bytes(msg).decode("utf-8", "replace") if isinstance(msg, list) else str(msg or "")
        try:
            priority = int(entry.get("PRIORITY", 6))
        except (TypeError, ValueError):
            priority = 6
        denied = any(d in msg for d in SANDBOX_DENIED)
        if priority > 3 and " ERROR " not in msg and not msg.startswith("ERROR ") and not denied:
            continue
        count += 1
        if len(lines) >= JOURNAL_MAX_LINES:
            continue
        try:
            at = datetime.fromtimestamp(int(entry["__REALTIME_TIMESTAMP"]) / 1e6, UTC).isoformat()
        except (KeyError, TypeError, ValueError):
            at = None
        lines.append(
            {
                "time": at,
                "unit": entry.get("_SYSTEMD_UNIT"),
                "invocation_id": entry.get("_SYSTEMD_INVOCATION_ID"),
                "priority": priority,
                "message": msg[:2000],
                "denied": denied,
            }
        )
    return {"lines": lines, "count": count, "truncated": count > len(lines), "since": since}


# Apply (the transient unit) ---------------------------------------------------------------------------


class Progress:
    """The progress file root writes for the new processes (root:pelagos 0640)."""

    def __init__(self, path: Path, record: dict[str, Any]) -> None:
        self.path = path
        self.data: dict[str, Any] = {
            "rollout_id": record["rollout_id"],
            "node_id": record["node_id"],
            "kind": record["kind"],
            "from_version": record.get("from_version"),
            "to_version": record.get("package_version"),
            "packages": record.get("packages"),
            "started_at": _now(),
            "finished_at": None,
            "result": "running",
            "steps": [],
            "backup": None,
            "error": None,
        }
        self.save()

    def save(self) -> None:
        _write_json(self.path, self.data, 0o640, True)

    def step(self, name: str) -> dict[str, Any]:
        entry = {"step": name, "state": "running", "started_at": _now(), "finished_at": None, "output": ""}
        self.data["steps"].append(entry)
        self.save()
        return entry

    def end(self, entry: dict[str, Any], ok: bool, output: str = "") -> None:
        entry.update(state="done" if ok else "failed", finished_at=_now(), output=output[-8000:])
        self.save()

    def finish(self, result: str, error: str | None = None) -> None:
        self.data.update(result=result, finished_at=_now(), error=error)
        self.save()


class StepFailed(Exception):
    pass


def _services(env: Any, verb: str) -> str:
    res = env.runner.run(["systemctl", verb, *SERVICES], check=False, timeout=300)
    if not res.ok:
        raise StepFailed(f"systemctl {verb} failed: {res.output}")
    return f"systemctl {verb} {' '.join(SERVICES)}"


def backup_state(env: Any, lay: Layout, from_version: str | None) -> Path:
    """/etc/pelagos and /var/lib/pelagos without the series cache and the uploads, 0600 root:
    it holds the master key and the CA."""
    paths = env.node_paths
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    target = lay.backups / f"pelagos-state-{stamp}-{from_version or 'none'}.tar.gz"
    skip = {paths.var / "upgrade"}

    def keep(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        name = Path("/" + info.name)
        if name.name.startswith(paths.series_db.name) and name.parent == paths.var:
            return None
        if any(name == s or s in name.parents for s in skip):
            return None
        return info

    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for root in (paths.etc, paths.var):
                if root.exists():
                    tar.add(root, arcname=str(root).lstrip("/"), filter=keep)
    return target


def _install_argv(fmt: str, package: str, downgrade: bool) -> list[str]:
    if fmt == "deb":
        return [
            "apt-get",
            "install",
            "-y",
            "-q",
            "-o",
            "Dpkg::Options::=--force-confold",
            "-o",
            "DPkg::Lock::Timeout=300",
            *(["--allow-downgrades"] if downgrade else []),
            package,
        ]
    return ["dnf", "-y", "-q", "downgrade" if downgrade else "install", package]


def _engine_argv(fmt: str, packages: dict[str, str]) -> list[str]:
    if fmt == "deb":
        return [
            "apt-get",
            "install",
            "-y",
            "-q",
            "--only-upgrade",
            "--no-remove",
            "-o",
            "Dpkg::Options::=--force-confold",
            "-o",
            "DPkg::Lock::Timeout=300",
            *[f"{n}={v}" for n, v in sorted(packages.items())],
        ]
    return ["dnf", "-y", "-q", "upgrade", *[f"{n}-{v}" for n, v in sorted(packages.items())]]


def _run_step(env: Any, progress: Progress, name: str, fn: Any) -> Any:
    entry = progress.step(name)
    try:
        result = fn()
    except StepFailed as exc:
        progress.end(entry, False, str(exc))
        raise
    except Exception as exc:  # anything else fails the step the same way
        progress.end(entry, False, f"{type(exc).__name__}: {exc}")
        raise StepFailed(f"{name}: {exc}") from exc
    output = result[1] if isinstance(result, tuple) else str(result or "")
    progress.end(entry, True, output)
    return result[0] if isinstance(result, tuple) else result


def apply(env: Any, rollout_id: str) -> int:
    """`pelagos upgrade apply --rollout <id>`: 0 installed, 1 failed (the progress file says why)."""
    if not ROLLOUT_ID_RE.fullmatch(rollout_id or ""):
        raise UpdateRefused("rollout", f"invalid rollout id {rollout_id!r}")
    lay = ensure_layout(env)
    record = _read_json(lay.request(rollout_id))
    if record is None or record.get("rollout_id") != rollout_id:
        raise UpdateRefused("rollout", f"no request for rollout {rollout_id}: the helper starts it")
    progress = Progress(lay.progress(rollout_id, str(record["node_id"])), record)
    try:
        if record["kind"] == RolloutKind.ENGINE_PACKAGES.value:
            _apply_engines(env, record, progress)
        else:
            _apply_pelagos(env, lay, record, progress)
    except StepFailed as exc:
        progress.finish("failed", str(exc))
        return 1
    progress.finish("installed")
    return 0


def _apply_pelagos(env: Any, lay: Layout, record: dict[str, Any], progress: Progress) -> None:
    fmt = record["package_format"]
    package = Path(record["package"])
    rollback = record["kind"] == RolloutKind.ROLLBACK.value
    if rel.file_sha256(package) != record["sha256"]:
        raise StepFailed(f"{package.name} changed since it was verified")
    from_version = installed_version(env, fmt)

    def backup() -> tuple[Path, str]:
        out = _services(env, "stop")
        try:
            path = backup_state(env, lay, from_version)
        except Exception:
            _services(env, "start")
            raise
        progress.data["backup"] = str(path)
        return path, f"{out}\nstate saved in {path}"

    _run_step(env, progress, "backup", backup)

    def install() -> str:
        res = env.runner.run(
            _install_argv(fmt, str(package), rollback),
            check=False,
            timeout=1800,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        )
        if not res.ok:
            restarted = _services(env, "start")
            raise StepFailed(
                f"install failed, previous package left in place ({restarted}): {res.output[-4000:]}"
            )
        out = res.output
        if rollback:
            for p in env.node_paths.var.glob(env.node_paths.series_db.name + "*"):
                p.unlink(missing_ok=True)
            out += f"\n{env.node_paths.series_db.name} deleted (cache)"
        # The package scripts skip units that are not enabled: started here, a no-op otherwise.
        return f"{out}\n{_services(env, 'start')}"

    _run_step(env, progress, "rollback" if rollback else "install", install)

    def check_version() -> str:
        now = installed_version(env, fmt)
        if now != record["package_version"]:
            raise StepFailed(f"installed version is {now}, expected {record['package_version']}")
        return f"pelagos {now} installed"

    _run_step(env, progress, "version", check_version)
    if not rollback:
        before = _read_json(lay.installed) or {}
        previous = {
            "package_version": from_version,
            "release": before.get("release") if before.get("package_version") == from_version else None,
        }
        _write_json(lay.previous, previous, 0o640, True)
    _write_json(
        lay.installed,
        {"package_version": record["package_version"], "release": record["version"]},
        0o640,
        True,
    )
    if not rollback:
        try:
            _run_step(env, progress, "restart", lambda: wait_units_up(env))
        except StepFailed as exc:
            raise StepFailed(f"{exc}; {_roll_back_here(env, lay, record, progress)}") from None
    purge(lay, int(record.get("keep_packages") or KEEP_DEFAULT))


def _unit_props(env: Any, unit: str) -> tuple[str, str]:
    res = env.runner.run(
        ["systemctl", "show", "-p", "ActiveState", "-p", "NRestarts", unit],
        check=False,
        mutates=False,
        timeout=30,
    )
    props = dict(line.partition("=")[::2] for line in res.stdout.splitlines())
    return props.get("ActiveState", "") or "unknown", props.get("NRestarts", "")


def wait_units_up(env: Any, stable: float | None = None, timeout: float | None = None) -> str:
    """Both units active with the same restart count for `stable` seconds, else StepFailed."""
    stable = UNITS_STABLE_SECONDS if stable is None else stable
    timeout = UNITS_TIMEOUT_SECONDS if timeout is None else timeout
    start = time.monotonic()
    since: float | None = None
    last: dict[str, tuple[str, str]] | None = None
    while True:
        states = {u: _unit_props(env, u) for u in SERVICES}
        up = all(state == "active" for state, _ in states.values())
        now = time.monotonic()
        if up and states == last and since is not None and now - since >= stable:
            return f"{', '.join(SERVICES)} active for {int(now - since)} s"
        if states != last or not up:
            since = now if up else None
        last = states
        if now - start > timeout:
            shown = ", ".join(f"{u} {a} (restarts {n or '?'})" for u, (a, n) in states.items())
            raise StepFailed(f"the services do not stay up after the install: {shown}")
        time.sleep(1.0)


def _roll_back_here(env: Any, lay: Layout, record: dict[str, Any], progress: Progress) -> str:
    """The previous release reinstalled by the unit itself; `rolled_back` names it in the progress."""
    previous = str((_read_json(lay.previous) or {}).get("release") or "")
    if not record.get("auto_rollback") or not previous:
        return "no automatic rollback (disabled, state format changed, or no kept previous release)"
    try:
        v = verify(env, previous, True)
        if v.direction != "rollback":
            return f"no automatic rollback: {v.package_version} is a {v.direction}"
        fmt = record["package_format"]

        def back() -> str:
            _services(env, "stop")
            res = env.runner.run(
                _install_argv(fmt, str(v.folder / v.file), True),
                check=False,
                timeout=1800,
                env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
            )
            if not res.ok:
                raise StepFailed(f"reinstall of {v.package_version} failed: {res.output[-4000:]}")
            for p in env.node_paths.var.glob(env.node_paths.series_db.name + "*"):
                p.unlink(missing_ok=True)
            return f"{res.output}\n{_services(env, 'start')}"

        _run_step(env, progress, "rollback", back)
    except (StepFailed, UpdateRefused) as exc:
        _services_quietly(env, "start")
        return f"automatic rollback failed: {exc}"
    _write_json(lay.installed, {"package_version": v.package_version, "release": previous}, 0o640, True)
    progress.data["rolled_back"] = previous
    progress.save()
    return f"rolled back to {previous}"


def _services_quietly(env: Any, verb: str) -> None:
    try:
        _services(env, verb)
    except StepFailed:
        pass


def _apply_engines(env: Any, record: dict[str, Any], progress: Progress) -> None:
    fmt, packages = record["package_format"], dict(record["packages"])
    units = _engine_units(env, engine_packages.families(packages))
    before = {u: _invocation(env, u) for u in units}

    def install() -> str:
        res = env.runner.run(
            _engine_argv(fmt, packages),
            check=False,
            timeout=1800,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        )
        if not res.ok:
            raise StepFailed(f"install failed: {res.output[-4000:]}")
        return res.output

    _run_step(env, progress, "install", install)

    def check_versions() -> str:
        now = {n: installed_version(env, fmt, n) for n in packages}
        bad = {n: v for n, v in now.items() if v != packages[n]}
        if bad:
            raise StepFailed("; ".join(f"{n} is {v}, expected {packages[n]}" for n, v in bad.items()))
        return ", ".join(f"{n} {v}" for n, v in now.items())

    _run_step(env, progress, "version", check_versions)

    def restart() -> str:
        # The package scripts restart the daemons or not, depending on the packaging: a unit that
        # still runs the process from before the install is restarted here.
        lines = []
        for unit, old in before.items():
            if old and _invocation(env, unit) != old:
                lines.append(f"{unit}: restarted by the package")
                continue
            res = env.runner.run(["systemctl", "restart", unit], check=False, timeout=300)
            if not res.ok:
                raise StepFailed(f"systemctl restart {unit} failed: {res.output[-2000:]}")
            lines.append(f"{unit}: restarted")
        return "\n".join(lines) or "no engine unit runs here"

    _run_step(env, progress, "restart", restart)


def _engine_units(env: Any, families: set[str]) -> list[str]:
    """The active units of the engines the packages run (BIND, the Kea daemons) on this host."""
    p = env.paths
    names: list[str] = []
    if engine_packages.BIND in families:
        names.append(p.bind_service)
    if engine_packages.KEA in families:
        for engine in ("kea4", "kea6", "d2"):
            names.extend(p.kea_service_candidates(engine))
    out = []
    for unit in dict.fromkeys(names):
        res = env.runner.run(
            ["systemctl", "show", "-p", "ActiveState", "--value", unit],
            check=False,
            mutates=False,
            timeout=30,
        )
        if res.ok and res.stdout.strip() == "active":
            out.append(unit if unit.endswith(".service") else f"{unit}.service")
    return list(dict.fromkeys(out))


def _invocation(env: Any, unit: str) -> str:
    res = env.runner.run(
        ["systemctl", "show", "-p", "InvocationID", "--value", unit], check=False, mutates=False, timeout=30
    )
    return res.stdout.strip() if res.ok else ""


def purge(lay: Layout, keep: int) -> list[str]:
    """Keeps the `keep` newest releases and state backups, and always the installed and previous
    releases; returns what was removed."""
    removed: list[str] = []
    pinned = {(_read_json(p) or {}).get("release") for p in (lay.installed, lay.previous)}
    folders = sorted(
        (p for p in lay.packages_root.iterdir() if p.is_dir() and not p.name.startswith(".")),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for p in folders[keep:]:
        if p.name not in pinned:
            shutil.rmtree(p, ignore_errors=True)
            removed.append(str(p))
    backups = sorted(
        lay.backups.glob("pelagos-state-*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True
    )
    for p in backups[keep:]:
        p.unlink(missing_ok=True)
        removed.append(str(p))
    return removed


def handle(env: Any, op: str, request: dict[str, Any], keys: dict[str, Any] | None = None) -> Any:
    """The helper operations of section 29; UpdateRefused is a `value` error."""
    if op == "update_verify":
        return verify(
            env, str(request.get("version") or ""), request.get("allow_unsigned") is True, keys
        ).answer()
    if op == "update_start":
        return start(env, request, keys)
    if op == "update_status":
        return status(env, request)
    if op == "journal_errors":
        return journal_errors(env, request)
    raise UpdateRefused("operation", f"unknown operation {op}")


def cmd_upgrade(args: Any) -> int:
    """`pelagos upgrade apply --rollout <id>` (the transient unit), `pelagos upgrade status`."""
    import sys

    from pelagos.core.paths import Paths
    from pelagos.installer.env import InstallerEnv

    if args.action == "apply" and not _is_root():
        print("pelagos upgrade apply must run as root (the helper starts it)", file=sys.stderr)
        return 2
    if getattr(args, "home", None):
        os.environ["PELAGOS_HOME"] = str(Path(args.home).resolve())
    env = InstallerEnv.detect(node_paths=Paths.from_env())
    try:
        if args.action == "apply":
            code = apply(env, args.rollout)
            print(json.dumps(_read_json(layout(env).progress(args.rollout, env.node_id)), indent=1))
            return code
        print(json.dumps(status(env, {"rollout_id": args.rollout}), indent=1, default=str))
        return 0
    except UpdateRefused as exc:
        print(f"pelagos upgrade: {exc}", file=sys.stderr)
        return 2


def add_parser(sub: Any) -> Any:
    u = sub.add_parser("upgrade", help="updates from the UI: what the helper's transient unit runs")
    u.add_argument("action", choices=("apply", "status"))
    u.add_argument("--rollout", required=True, help="rollout id (ULID)")
    u.set_defaults(func=cmd_upgrade)
    return u
