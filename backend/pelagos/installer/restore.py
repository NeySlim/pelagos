# SPDX-License-Identifier: Apache-2.0
"""Offline rebuild of a node from an archive: `pelagos restore` (design 13.2 mode 3, architecture
section 23).

Runs as root on a host with the Pelagos package and the engines installed, with no running cluster
needed: the archive is checked against its `.sha256`, decrypted with the identities given (the
cluster identity or an operator one), extracted into a private folder, and every archived file goes
back to its path with its mode and owner. Dynamic zones are written from their AXFR snapshot (the
journals removed), DNSSEC keys and Kea leases come back as files. The services are stopped first,
the engines' configurations checked once the files are in place (a failed check puts every file
back), then the services are started: the node returns with its identity and resyncs with its peers.
"""

from __future__ import annotations

import grp
import os
import pwd
import shutil
import stat
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pelagos import __version__
from pelagos.archives import age, bundle
from pelagos.archives.model import ArchiveError, Manifest

GROUPS = ("bind", "kea", "pelagos")
KEA_PARTS = {"kea4.config": "kea4", "kea6.config": "kea6", "d2.config": "d2"}
PART_LEASES = "kea.leases"
PART_PELAGOS = "pelagos"
DAEMONS = {"kea4": "kea-dhcp4", "kea6": "kea-dhcp6", "d2": "kea-dhcp-ddns"}
PELAGOS_UNITS = ("pelagos.service", "pelagos-collector.service")
# Files beside a zone file that stop matching it once it is replaced.
ZONE_STALE = (".jnl", ".signed", ".signed.jnl")
ZONE_MODE = 0o644
# Records named rebuilds from the keys of a dnssec-policy zone (inline signing keeps them out of
# the raw file); TYPE65534 is its private signing state.
DNSSEC_TYPES = frozenset({"RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "DNSKEY", "CDS", "CDNSKEY", "TYPE65534"})
DIR_MODE = 0o750
TMP_SUFFIX = ".pelagos-restore"
APPARMOR = "/sys/kernel/security/apparmor"


class RestoreError(Exception):
    """The restore cannot start (bad archive, wrong identity, missing engine or account)."""


def group_of(part: str) -> str | None:
    if part.startswith("bind."):
        return "bind"
    if part in KEA_PARTS or part == PART_LEASES:
        return "kea"
    if part == PART_PELAGOS:
        return "pelagos"
    return None


def read_identities(sources: list[str], stdin: Any = None) -> list[str]:
    """Identities from age identity files (`-` reads stdin); comments and blank lines skipped."""
    out: list[str] = []
    for src in sources:
        try:
            text = (stdin.read() if stdin is not None else "") if src == "-" else Path(src).read_text()
        except OSError as exc:
            raise RestoreError(f"identity file {src}: {exc.strerror or exc}") from None
        try:
            found = age.parse_identities(text)
        except age.AgeError as exc:
            raise RestoreError(f"identity file {src}: {exc}") from None
        if not found:
            raise RestoreError(f"identity file {src} holds no AGE-SECRET-KEY-1 line")
        out += found
    return out


def _ids(owner: str) -> tuple[int, int]:
    """uid and gid of `user:group` (names or numbers); KeyError names the missing account."""
    user, _, group = owner.partition(":")
    uid = int(user) if user.isdigit() else pwd.getpwnam(user).pw_uid
    if not group:
        return uid, pwd.getpwuid(uid).pw_gid
    try:
        gid = int(group) if group.isdigit() else grp.getgrnam(group).gr_gid
    except KeyError:
        raise KeyError(group) from None
    return uid, gid


@dataclass
class Write:
    path: str
    source: Path  # the extracted copy, or the zone snapshot
    mode: int
    owner: str
    part: str
    size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "mode": f"{self.mode:04o}",
            "owner": self.owner,
            "part": self.part,
            "size": self.size,
        }


@dataclass
class RestorePlan:
    archive: Path
    manifest: Manifest
    groups: list[str]
    writes: list[Write] = field(default_factory=list)
    removes: list[str] = field(default_factory=list)
    zones: list[dict[str, Any]] = field(default_factory=list)
    units: list[str] = field(default_factory=list)  # in start order
    named_conf: str | None = None
    kea_confs: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    in_place: bool = False

    def parts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for w in self.writes:
            out[w.part] = out.get(w.part, 0) + 1
        return dict(sorted(out.items()))

    def to_dict(self) -> dict[str, Any]:
        m = self.manifest
        return {
            "archive": str(self.archive),
            "archive_id": m.archive_id,
            "node_id": m.node_id,
            "node_name": m.node_name,
            "created_at": m.created_at.isoformat(),
            "versions": dict(m.versions),
            "complete": m.complete,
            "unreadable": list(m.unreadable),
            "groups": list(self.groups),
            "parts": self.parts(),
            "files": [w.to_dict() for w in self.writes],
            "zones": list(self.zones),
            "remove": list(self.removes),
            "units": list(self.units),
            "in_place": self.in_place,
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }


@dataclass
class RestoreResult:
    ok: bool
    written: int = 0
    removed: int = 0
    checks: list[dict[str, Any]] = field(default_factory=list)
    started: list[str] = field(default_factory=list)
    stopped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    rolled_back: bool = False
    backup_dir: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "written": self.written,
            "removed": self.removed,
            "checks": self.checks,
            "stopped": self.stopped,
            "started": self.started,
            "errors": self.errors,
            "rolled_back": self.rolled_back,
            "backup_dir": self.backup_dir,
        }


# (what, ok, output) of one check on the restored files.
Checker = Callable[["RestorePlan"], list[dict[str, Any]]]


def _unsigned(snapshot: Path) -> Path:
    """The AXFR text without its DNSSEC records: named signs the zone again with the restored keys."""
    out = snapshot.with_name(snapshot.name + ".unsigned")
    lines = snapshot.read_text().splitlines(keepends=True)
    # Lines are `name ttl IN type rdata` (collector.archive_collect.zone_text).
    kept = [line for line in lines if [*line.split(None, 4), "", "", "", ""][3] not in DNSSEC_TYPES]
    out.write_text("".join(kept))
    return out


def _major_minor(version: str | None) -> str | None:
    if not version:
        return None
    parts = version.split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else version


class OfflineRestore:
    """One restore: `prepare()` opens the archive and builds the plan, `apply()` carries it out,
    `close()` removes the clear copies (also on error: use as a context manager)."""

    def __init__(
        self,
        env: Any,
        archive: Path,
        identities: list[str],
        only: list[str] | None = None,
        workdir: Path | None = None,
        backup_root: Path = Path("/var/backups"),
        force: bool = False,
        checker: Checker | None = None,
        log: Callable[[str], None] = lambda _line: None,
    ) -> None:
        self.env = env
        self.archive = Path(archive)
        self.identities = list(identities)
        unknown = sorted(set(only or ()) - set(GROUPS))
        if unknown:
            raise RestoreError(f"--only takes {', '.join(GROUPS)}, not {', '.join(unknown)}")
        self.only = list(only) if only else list(GROUPS)
        self.workdir_base = workdir
        self.backup_root = backup_root
        self.force = force
        self.checker = checker
        self.log = log
        self.root = os.geteuid() == 0
        self.workdir: Path | None = None

    # Opening -------------------------------------------------------------------------------

    def _make_workdir(self) -> Path:
        base = self.workdir_base
        if base is None:
            # A tmpfs keeps the clear copies off the disks when it has room for them.
            size = self.archive.stat().st_size
            run = Path("/run")
            try:
                roomy = shutil.disk_usage(run).free > 4 * size
            except OSError:
                roomy = False
            base = run if roomy and os.access(run, os.W_OK) else Path(tempfile.gettempdir())
        return Path(tempfile.mkdtemp(prefix="pelagos-restore-", dir=base))

    def prepare(self) -> RestorePlan:
        if not self.archive.is_file():
            raise RestoreError(f"{self.archive}: no such archive file")
        warnings: list[str] = []
        if bundle.sum_path(self.archive).exists():
            try:
                good = bundle.verify_sum(self.archive)
            except ArchiveError as exc:
                raise RestoreError(str(exc)) from None
            if not good:
                raise RestoreError(f"{self.archive.name} does not match its .sha256: damaged or altered")
        else:
            warnings.append("no .sha256 beside the archive: integrity rests on decryption alone")
        if not self.identities:
            raise RestoreError("no identity to open the archive: give --identity")
        self.workdir = self._make_workdir()
        try:
            manifest = bundle.extract(self.archive, self.identities, self.workdir)
        except age.AgeNoMatchError:
            raise RestoreError("none of the identities given opens this archive") from None
        except age.AgeError as exc:
            raise RestoreError(f"the archive cannot be decrypted: {exc}") from None
        except ArchiveError as exc:
            raise RestoreError(f"the archive is damaged: {exc}") from None
        plan = RestorePlan(self.archive, manifest, [], warnings=warnings)
        self._plan(plan)
        return plan

    def close(self) -> None:
        if self.workdir is not None:
            shutil.rmtree(self.workdir, ignore_errors=True)
            self.workdir = None

    def __enter__(self) -> OfflineRestore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def copy_of(self, path: str) -> Path:
        assert self.workdir is not None
        return self.workdir / bundle.file_member(path)

    # Planning ------------------------------------------------------------------------------

    def _plan(self, plan: RestorePlan) -> None:
        m = plan.manifest
        present = {group_of(f.part) for f in m.files} | ({"bind"} if m.zones else set())
        plan.groups = [g for g in GROUPS if g in self.only and g in present]
        missing = [g for g in self.only if g not in present]
        if missing and self.only != list(GROUPS):
            plan.warnings.append(f"the archive holds nothing for {', '.join(missing)}")
        for f in m.files:
            if group_of(f.part) in plan.groups:
                plan.writes.append(Write(f.path, self.copy_of(f.path), f.mode, f.owner, f.part, f.size))
        if not m.complete:
            plan.warnings.append(
                "the archive is incomplete; not archived: " + (", ".join(m.unreadable) or "unknown")
            )
        if "bind" in plan.groups:
            self._plan_bind(plan)
        if "kea" in plan.groups:
            self._plan_kea(plan)
        if "pelagos" in plan.groups:
            self._plan_pelagos(plan)
        self._plan_accounts(plan)
        self._plan_versions(plan)
        self._plan_units(plan)

    def _reader(self, archived: set[str]) -> Callable[[Path], str]:
        def read(path: Path) -> str:
            name = os.path.normpath(str(path))
            return (self.copy_of(name) if name in archived else Path(name)).read_text()

        return read

    def _plan_bind(self, plan: RestorePlan) -> None:
        from pelagos.connectors.bind.namedconf.resolve import ConfigFiles, build_tree

        m = plan.manifest
        archived = {f.path for f in m.files}
        conf_files = [f.path for f in m.files if f.part in ("bind.user_files", "bind.managed")]
        default = os.path.normpath(str(self.env.paths.named_conf))
        named_conf = default if default in archived else next(iter(conf_files), None)
        plan.named_conf = named_conf
        if self.env.binary("named") is None:
            plan.errors.append(
                "named is not installed: install " + " ".join(self.env.paths.bind_packages) + " first"
            )
        snapshots = [z for z in m.zones if z.source == "axfr" and z.sha256]
        if not snapshots and not any(f.part.startswith("bind.zone:") for f in m.files):
            return
        files_of: dict[tuple[str, str], Path] = {}
        policy: set[tuple[str, str]] = set()
        if named_conf is not None:
            try:
                files = ConfigFiles.load(Path(named_conf), reader=self._reader(archived))
                tree = build_tree(files, m.node_id)
                directory = files.directory or Path(named_conf).parent
                for zone in tree.zones:
                    key = (zone.view, zone.name.rstrip(".").lower() or ".")
                    if zone.dnssec_policy and zone.dnssec_policy != "none":
                        policy.add(key)
                    if zone.file:
                        path = Path(zone.file)
                        files_of[key] = path if path.is_absolute() else directory / path
            except Exception as exc:
                plan.warnings.append(f"the archived named.conf could not be read: {exc}")
        owner = f"{self.env.paths.bind_user}:{self.env.paths.bind_group}"
        restored: list[str] = []
        for z in snapshots:
            target = files_of.get((z.view, z.zone.lower()))
            if target is None:
                plan.warnings.append(
                    f"zone {z.zone} ({z.view}) has no file in the archived configuration: not restored"
                )
                continue
            source = self.workdir / bundle.zone_member(z.view, z.zone)  # type: ignore[operator]
            if (z.view, z.zone.lower()) in policy:
                source = _unsigned(source)
            part = f"bind.zone:{z.view}/{z.zone}"
            plan.writes.append(Write(str(target), source, ZONE_MODE, owner, part, source.stat().st_size))
            plan.zones.append({"view": z.view, "zone": z.zone, "serial": z.serial, "path": str(target)})
            restored.append(str(target))
        for f in m.files:
            if f.part.startswith("bind.zone:") and not f.path.endswith(".jnl"):
                restored.append(f.path)
        for path in restored:
            for suffix in ZONE_STALE:
                stale = path + suffix
                if stale not in archived and os.path.lexists(stale):
                    plan.removes.append(stale)

    def _kea_engines(self, plan: RestorePlan) -> list[str]:
        return [e for e in ("d2", "kea4", "kea6") if any(KEA_PARTS.get(w.part) == e for w in plan.writes)]

    def _plan_kea(self, plan: RestorePlan) -> None:
        for engine in self._kea_engines(plan):
            part = next(p for p, e in KEA_PARTS.items() if e == engine)
            confs = [w.path for w in plan.writes if w.part == part and w.path.endswith(".conf")]
            default = os.path.normpath(str(self.env.paths.kea_conf(DAEMONS[engine])))
            conf = default if default in confs else next(iter(confs), None)
            if conf is not None:
                plan.kea_confs[engine] = conf
            if self.env.binary(DAEMONS[engine]) is None:
                packages = self.env.paths.kea_packages_for([engine], False)
                plan.errors.append(f"{DAEMONS[engine]} is not installed: install {' '.join(packages)} first")

    def _plan_pelagos(self, plan: RestorePlan) -> None:
        local = self.env.local_node_id() if self.env.node_paths.node_toml.exists() else None
        if local is None:
            return
        if local == plan.manifest.node_id:
            plan.in_place = True
            plan.warnings.append("this host already is this node: its Pelagos files are replaced")
        elif not self.force:
            plan.errors.append(
                f"this host is already node {local}, not {plan.manifest.node_id} "
                f"({plan.manifest.node_name}): --force replaces its identity"
            )
        else:
            plan.warnings.append(f"node {local} on this host is replaced by {plan.manifest.node_name}")

    def _plan_accounts(self, plan: RestorePlan) -> None:
        if not self.root:
            return
        missing: dict[str, set[str]] = {}
        for w in plan.writes:
            try:
                _ids(w.owner)
            except KeyError as exc:
                missing.setdefault(str(exc.args[0]), set()).add(w.part.split(":")[0])
        for name, parts in sorted(missing.items()):
            plan.errors.append(
                f"account {name} does not exist (owner of {', '.join(sorted(parts))}): "
                "install the packages that create it first"
            )

    def _plan_versions(self, plan: RestorePlan) -> None:
        archived = plan.manifest.versions
        try:
            installed = {
                "bind": self.env.t.named_version() if "bind" in plan.groups else None,
                "kea": self.env.t.kea_version("kea-dhcp4") if "kea" in plan.groups else None,
            }
        except Exception:
            installed = {}
        for engine, now in installed.items():
            was = archived.get(engine)
            if now and was and _major_minor(now) != _major_minor(was):
                plan.warnings.append(f"{engine} {was} in the archive, {now} installed: check the files")
        was = archived.get("pelagos")
        if was and _major_minor(was) != _major_minor(__version__):
            plan.warnings.append(f"archive written by Pelagos {was}, this host runs {__version__}")

    def _plan_units(self, plan: RestorePlan) -> None:
        units: list[str] = []
        if "bind" in plan.groups and plan.named_conf:
            units.append(self.env.bind_unit())
        if "kea" in plan.groups:
            units += [self.env.kea_unit(e) for e in self._kea_engines(plan)]
        units += list(PELAGOS_UNITS)
        plan.units = [u for u in units if self.env.services.exists(u)]

    # Applying ------------------------------------------------------------------------------

    def check_copy(self, plan: RestorePlan) -> list[dict[str, Any]]:
        """Dry run: named-checkconf, named-checkzone and `kea-* -t` on a copy of the engine files."""
        from pelagos.collector.archives import test_restore

        conf_paths = dict(plan.kea_confs)
        if plan.named_conf:
            conf_paths["bind"] = plan.named_conf
        if not conf_paths:
            return []
        work = Path(tempfile.mkdtemp(prefix="pelagos-restore-check-", dir=self.workdir))
        try:
            result = test_restore(self.archive, self.identities, plan.manifest, work, conf_paths)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        bind = "bind" in plan.groups
        checks = [c for c in result.get("checks") or [] if bind or not str(c["what"]).startswith("named-")]
        for c in checks:
            if c["ok"] is False and "Unable to open file" in str(c.get("output")) and Path(APPARMOR).exists():
                # Debian confines kea-* -t to /etc/kea: the real files are checked before the start.
                c["ok"] = None
                c["output"] = "not checked on the copy (AppArmor): checked in place before the start"
        return checks

    def _default_checks(self, plan: RestorePlan) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if plan.named_conf:
            tool = self.env.binary("named-checkconf")
            if tool is None:
                out.append({"what": "named-checkconf -z", "ok": None, "output": "tool not found"})
            else:
                res = self.env.runner.run(
                    [tool, "-z", plan.named_conf], privileged=True, check=False, mutates=False, timeout=120
                )
                out.append({"what": "named-checkconf -z", "ok": res.ok, "output": res.output[-4000:]})
        for engine, conf in plan.kea_confs.items():
            try:
                ok, output = self.env.t.kea_test(DAEMONS[engine], Path(conf))
            except FileNotFoundError as exc:
                ok, output = False, str(exc)
            out.append({"what": f"{DAEMONS[engine]} -t", "ok": ok, "output": output[-4000:]})
        return out

    def _mkdirs(self, directory: Path, owner: str, created: list[Path]) -> None:
        missing = []
        d = directory
        while not d.exists():
            missing.append(d)
            d = d.parent
        for d in reversed(missing):
            d.mkdir(mode=DIR_MODE)
            created.append(d)
            if self.root:
                os.chown(d, *_ids(owner))

    def _install(self, w: Write, created: list[Path]) -> None:
        dest = Path(w.path)
        self._mkdirs(dest.parent, w.owner, created)
        tmp = dest.parent / f".{dest.name}{TMP_SUFFIX}"
        tmp.unlink(missing_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as out, open(w.source, "rb") as src:
                shutil.copyfileobj(src, out)
                out.flush()
                if self.root:
                    os.chown(out.fileno(), *_ids(w.owner))
                os.chmod(out.fileno(), w.mode)
                os.fsync(out.fileno())
            os.replace(tmp, dest)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

    def _save(self, paths: list[str], backup: Path) -> list[str]:
        """Copies the files about to be replaced or removed; returns those that did not exist."""
        absent = []
        for p in paths:
            src = Path(p)
            if not src.exists() or not stat.S_ISREG(src.lstat().st_mode):
                absent.append(p)
                continue
            dest = backup / p.lstrip("/")
            dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copy2(src, dest, follow_symlinks=False)
            if self.root:
                st = src.lstat()
                os.chown(dest, st.st_uid, st.st_gid)
        return absent

    def _rollback(self, written: list[str], removed: list[str], absent: list[str], created: list[Path],
                  backup: Path) -> None:  # fmt: skip
        for p in [*written, *removed]:
            saved = backup / p.lstrip("/")
            if saved.exists():
                shutil.copy2(saved, p, follow_symlinks=False)
                if self.root:
                    st = saved.lstat()
                    os.chown(p, st.st_uid, st.st_gid)
            elif p in absent:
                Path(p).unlink(missing_ok=True)
        for d in reversed(created):
            try:
                d.rmdir()
            except OSError:
                pass

    def apply(self, plan: RestorePlan, start: bool = True) -> RestoreResult:
        if plan.errors:
            return RestoreResult(ok=False, errors=list(plan.errors))
        result = RestoreResult(ok=False)
        svc = self.env.services
        for unit in plan.units:
            if svc.is_active(unit):
                self.log(f"stopping {unit}")
                svc.stop(unit)
                result.stopped.append(unit)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        backup = self.backup_root / f"pelagos-restore-{stamp}"
        backup.mkdir(parents=True, exist_ok=True, mode=0o700)
        result.backup_dir = str(backup)
        targets = [w.path for w in plan.writes]
        absent = self._save([*targets, *plan.removes], backup)
        written: list[str] = []
        removed: list[str] = []
        created: list[Path] = []
        try:
            for w in plan.writes:
                self._install(w, created)
                written.append(w.path)
            for p in plan.removes:
                Path(p).unlink(missing_ok=True)
                removed.append(p)
            self.env.relabel([Path(p) for p in written] + created)
            result.written, result.removed = len(written), len(removed)
            self.log(f"{len(written)} files written, {len(removed)} removed")
            result.checks = (self.checker or self._default_checks)(plan)
        except Exception as exc:
            result.errors.append(f"writing the files failed: {exc}")
        failed = [c for c in result.checks if c.get("ok") is False]
        if result.errors or failed:
            result.errors += [f"{c['what']} failed: {c.get('output', '')[-600:]}" for c in failed]
            self._rollback(written, removed, absent, created, backup)
            result.rolled_back = True
            for unit in result.stopped:
                try:
                    svc.start(unit)
                except Exception as exc:
                    result.errors.append(f"{unit} not started again: {exc}")
            return result
        if "pelagos" in plan.groups or self.env.node_paths.node_toml.exists():
            self._audit(plan, result)
        if self.root and "pelagos" in plan.groups:
            from pelagos.platform import PELAGOS_USER, give_tree_to

            p = self.env.node_paths
            give_tree_to(PELAGOS_USER, [p.audit_log.parent], skip=[p.etc / "pelagos.env"])
        result.ok = True
        if start:
            for unit in plan.units:
                if unit in PELAGOS_UNITS and not self.env.node_paths.node_toml.exists():
                    continue
                self.log(f"starting {unit}")
                try:
                    svc.enable_now(unit)
                    result.started.append(unit)
                except Exception as exc:
                    result.ok = False
                    result.errors.append(f"{unit} did not start: {exc}")
        return result

    def _audit(self, plan: RestorePlan, result: RestoreResult) -> None:
        from pelagos.core.audit_log import AuditLog
        from pelagos.domain import AuditEntry

        p = self.env.node_paths
        if not p.audit_log.parent.is_dir():
            return
        m = plan.manifest
        node_id = m.node_id if "pelagos" in plan.groups else self.env.local_node_id()
        entry = AuditEntry(
            node_id=node_id,
            action="restore.apply",
            target=f"archive:{m.archive_id}",
            user="cli",
            request={"mode": "offline", "archive": plan.archive.name, "groups": list(plan.groups)},
            response={
                "files": result.written,
                "removed": result.removed,
                "zones": [f"{z['zone']} ({z['view']})" for z in plan.zones],
                "archive_node": m.node_name,
                "created_at": m.created_at.isoformat(),
            },
            message=f"offline restore from {plan.archive.name}",
        )
        try:
            AuditLog(p.audit_log, p.locks_dir / "audit.lock").append(entry)
        except OSError as exc:
            result.errors.append(f"audit entry not written: {exc}")
