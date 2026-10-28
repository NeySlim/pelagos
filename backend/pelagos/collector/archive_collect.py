# SPDX-License-Identifier: Apache-2.0
"""What one node archive holds (design 13.2, architecture section 23).

BIND: named.conf and every file it includes, the managed folder, rndc files, static zone files,
DNSSEC key files, and each dynamic primary zone by AXFR (a consistent snapshot at one serial, no
freeze). Kea: each daemon's configuration and includes, D2 secret files, memfile leases. Pelagos:
node.toml, cluster.toml, the audit log, PKI, master key, TLS and web certificate state.

Each engine's files are read under its engine lock (no half-written plan is archived); AXFR and
leases are taken outside it. A file this process cannot read goes through the privileged helper,
and what still cannot be read is listed in the manifest, which marks the archive incomplete.
"""

from __future__ import annotations

import base64
import fnmatch
import logging
import os
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from pelagos import __version__
from pelagos.archives.bundle import ArchiveWriter
from pelagos.archives.model import ArchiveMeta, Manifest
from pelagos.core.context import NodeContext
from pelagos.domain import RRset, ZoneKind

log = logging.getLogger(__name__)

PART_BIND_MANAGED = "bind.managed"
PART_BIND_USER = "bind.user_files"
PART_BIND_DNSSEC = "bind.dnssec"
PART_LEASES = "kea.leases"
PART_PELAGOS = "pelagos"
KEA_PARTS = {"kea4": "kea4.config", "kea6": "kea6.config", "d2": "d2.config"}
DEFAULT_LEASE_DIR = "/var/lib/kea"
ENGINE_LOCK_TIMEOUT = 300.0
# memfile keeps leases in the file and, between two cleanups (LFC), in `.1` and `.2`.
LEASE_SUFFIXES = ("", ".1", ".2")


def zone_part(view: str, zone: str) -> str:
    return f"bind.zone:{view}/{zone}"


def zone_text(rrsets: list[RRset]) -> tuple[bytes, int | None]:
    """Master-file text of a transfer, SOA first, absolute names; with its serial."""
    serial = None
    lines = []
    ordered = sorted(rrsets, key=lambda r: (r.rtype != "SOA", r.name, r.rtype))
    for rr in ordered:
        for rdata in rr.rdata:
            lines.append(f"{rr.name} {rr.ttl} IN {rr.rtype} {rdata}")
            if rr.rtype == "SOA" and serial is None:
                parts = rdata.split()
                if len(parts) >= 3 and parts[2].isdigit():
                    serial = int(parts[2])
    return ("\n".join(lines) + "\n").encode(), serial


class FileSource:
    """Adds files to an archive; the ones this process cannot open are fetched in one batch from
    the privileged helper by `flush()`, or listed as unreadable without it."""

    def __init__(self, writer: ArchiveWriter, helper: Any = None) -> None:
        self.writer = writer
        self.helper = helper
        self.added: set[str] = set()
        self._pending: dict[str, str] = {}
        self._patterns: list[tuple[str, str, str]] = []
        # Contents the helper already sent (a named.conf include read for the parser).
        self._fetched: dict[str, tuple[bytes, int, str]] = {}

    def add(self, path: str | Path, part: str) -> None:
        name = os.path.normpath(str(path))
        if name in self.added or name in self._pending:
            return
        if name in self._fetched:
            data, mode, owner = self._fetched.pop(name)
            self.writer.add_bytes(name, data, part, mode=mode, owner=owner)
            self.added.add(name)
            return
        if not os.path.lexists(name):
            return
        if os.path.isdir(name):
            return
        # Not opened here (permissions, a confinement os.access does not see): the helper tries it.
        if os.access(name, os.R_OK) and self.writer.add_file(name, part, mark=False):
            self.added.add(name)
            return
        self._pending[name] = part

    def add_glob(self, folder: str | Path, glob: str, part: str) -> None:
        try:
            names = sorted(os.listdir(folder))
        except FileNotFoundError:
            return
        except OSError:
            self._patterns.append((str(folder), glob, part))
            return
        for n in names:
            if fnmatch.fnmatchcase(n, glob):
                self.add(Path(folder) / n, part)

    def add_tree(self, folder: Path, part: str, skip: tuple[Path, ...] = ()) -> None:
        if not folder.is_dir():
            return
        for root, dirs, files in os.walk(folder):
            dirs[:] = sorted(d for d in dirs if Path(root, d) not in skip)
            for f in sorted(files):
                self.add(Path(root) / f, part)

    def read_text(self, path: Path) -> str:
        """For the named.conf parser: the file as this process reads it, else through the helper."""
        try:
            return path.read_text()
        except PermissionError:
            if self.helper is None:
                raise
        got = self._helper_read([str(path)], [])
        if str(path) not in got:
            raise PermissionError(f"{path}: not readable, even through the helper")
        data, mode, owner = got[str(path)]
        self._fetched[os.path.normpath(str(path))] = (data, mode, owner)
        return data.decode("utf-8", errors="replace")

    def _helper_read(
        self, paths: list[str], patterns: list[dict[str, str]]
    ) -> dict[str, tuple[bytes, int, str]]:
        try:
            answer = self.helper.archive_read(paths, patterns)
        except Exception as exc:
            log.warning("privileged helper read failed: %s", exc)
            return {}
        out = {}
        for item in answer.get("files") or []:
            out[str(item["path"])] = (
                base64.b64decode(item["data"]),
                int(item.get("mode", 0o600)),
                str(item.get("owner", "")),
            )
        return out

    def flush(self) -> None:
        if not self._pending and not self._patterns:
            return
        pending, self._pending = self._pending, {}
        patterns, self._patterns = self._patterns, []
        got: dict[str, tuple[bytes, int, str]] = {}
        if self.helper is not None:
            got = self._helper_read(list(pending), [{"dir": d, "glob": g} for d, g, _part in patterns])
        for name, part in pending.items():
            if name in got:
                data, mode, owner = got.pop(name)
                self.writer.add_bytes(name, data, part, mode=mode, owner=owner)
                self.added.add(name)
            else:
                self.writer.mark_unreadable(name)
        for name, (data, mode, owner) in sorted(got.items()):
            part = next((p for d, g, p in patterns if Path(name).parent == Path(d)), PART_BIND_DNSSEC)
            if name not in self.added:
                self.writer.add_bytes(name, data, part, mode=mode, owner=owner)
                self.added.add(name)
        if self.helper is None:
            for d, g, _part in patterns:
                self.writer.mark_unreadable(str(Path(d) / g))


@dataclass
class Collected:
    meta: ArchiveMeta
    manifest: Manifest
    notes: list[str] = field(default_factory=list)


def _engine_lock(locks_dir: Path | None, engine: str) -> Any:
    if locks_dir is None:
        return nullcontext()
    from pelagos.services.engine_lock import engine_lock

    return engine_lock(locks_dir, engine, timeout=ENGINE_LOCK_TIMEOUT)


def _bind_version(backend: Any) -> str | None:
    try:
        version = backend.rndc.status().get("version", "")
    except Exception:
        return None
    return (
        version.split()[1].split("-")[0]
        if version.startswith("BIND ") and " " in version
        else version or None
    )


def _key_dirs(files: Any, directory: Path) -> list[Path]:
    dirs = [directory]
    for res in files.statements():
        if res.node.name == "key-directory" and res.node.args:
            value = Path(res.node.args[0])
            dirs.append(value if value.is_absolute() else directory / value)
    return list(dict.fromkeys(dirs))


class Builder:
    """Builds the archive of one node from its connectors (collector.main.Backends)."""

    def __init__(
        self,
        ctx: NodeContext,
        backends: Any,
        backend_lock: Any = None,
        helper: Any = None,
        locks_dir: Path | None = None,
    ) -> None:
        self.ctx = ctx
        self.backends = backends
        self.backend_lock = backend_lock if backend_lock is not None else nullcontext()
        self.helper = helper
        self.locks_dir = locks_dir

    @contextmanager
    def _backend(self) -> Iterator[None]:
        with self.backend_lock:
            yield

    def engines(self) -> list[str]:
        b = self.backends
        out = []
        for name, backend in (("bind", b.dns), ("kea4", b.kea4), ("kea6", b.kea6), ("d2", b.d2)):
            if backend is not None:
                out.append(name)
        return out

    def versions(self) -> dict[str, str]:
        out = {"pelagos": __version__}
        if self.backends.dns is not None:
            v = _bind_version(self.backends.dns)
            if v:
                out["bind"] = v
        for backend in self.backends.dhcp:
            try:
                with self._backend():
                    v = backend.version()
            except Exception:
                v = None
            if v:
                out["kea"] = str(v)
                break
        return out

    def hashes(self) -> dict[str, str]:
        out = {}
        b = self.backends
        for name, backend in (("kea4", b.kea4), ("kea6", b.kea6), ("d2", b.d2)):
            if backend is None:
                continue
            try:
                with self._backend():
                    out[name] = str(backend.config_hash())
            except Exception as exc:
                log.info("config-hash-get of %s failed: %s", name, exc)
        return out

    def build(
        self, directory: Path, recipients: list[str], include_leases: bool, created_at: datetime | None = None
    ) -> Collected:
        notes: list[str] = []
        with ArchiveWriter(
            directory,
            node_id=self.ctx.node.id,
            node_name=self.ctx.node.name,
            recipients=recipients,
            versions=self.versions(),
            engines=self.engines(),
            created_at=created_at,
        ) as writer:
            writer.manifest.hashes = self.hashes()
            src = FileSource(writer, self.helper)
            if self.backends.dns is not None:
                self._bind(src, notes)
            b = self.backends
            for name, backend in (("kea4", b.kea4), ("kea6", b.kea6), ("d2", b.d2)):
                if backend is not None:
                    self._kea(name, backend, src, include_leases)
            self._pelagos(src)
            src.flush()
            meta = writer.finish(["local"])
            return Collected(meta, writer.manifest, notes)

    # BIND -------------------------------------------------------------------------------------

    def _bind(self, src: FileSource, notes: list[str]) -> None:
        from pelagos.connectors.bind import staticzone
        from pelagos.connectors.bind.namedconf.resolve import ConfigFiles

        backend = self.backends.dns
        with self._backend():
            zones = [z for z in backend.list_zones() if z.kind is ZoneKind.PRIMARY]
            static = {(z.view, z.name) for z in zones if backend.static_zone(z.name, z.view) is not None}
            try:
                rpz_dir = Path(backend.rpz_dir())
            except Exception:
                rpz_dir = None
        dynamic: list[Any] = []
        with _engine_lock(self.locks_dir, "bind"):
            files = ConfigFiles.load(backend.named_conf, reader=src.read_text)
            include_dir = Path(backend.include_dir)
            for name in files.order:
                part = PART_BIND_MANAGED if Path(name).is_relative_to(include_dir) else PART_BIND_USER
                src.add(name, part)
            for name in files.unreadable:
                src.writer.mark_unreadable(name)
            src.add_glob(include_dir, "*", PART_BIND_MANAGED)
            for path in (backend.rndc.conf_path, backend.rndc.key_path):
                if path:
                    part = PART_BIND_MANAGED if Path(path).is_relative_to(include_dir) else PART_BIND_USER
                    src.add(path, part)
            directory = files.directory or Path(backend.named_conf).parent
            key_dirs = _key_dirs(files, directory)
            for zone in zones:
                file = staticzone.zone_path(zone, directory) if zone.file else None
                if file is not None and rpz_dir is not None and file.is_relative_to(rpz_dir):
                    continue  # RPZ lists are rebuilt from their feeds
                label = zone.name.rstrip(".") or "."
                if (zone.view, zone.name) in static:
                    if file is not None:
                        src.add(file, zone_part(zone.view, label))
                    src.writer.add_zone(zone.view, label, self._serial(zone), "file")
                else:
                    dynamic.append((zone, file))
                if (zone.dnssec_policy and zone.dnssec_policy != "none") or zone.inline_signing:
                    for d in key_dirs:
                        src.add_glob(d, f"K{label}.+*", PART_BIND_DNSSEC)
            src.flush()
        for zone, file in dynamic:
            self._axfr(zone, file, src, notes)
        src.flush()

    def _serial(self, zone: Any) -> int | None:
        try:
            with self._backend():
                return self.backends.dns.soa_serial(zone.name, zone.view)
        except Exception:
            return None

    def _axfr(self, zone: Any, file: Path | None, src: FileSource, notes: list[str]) -> None:
        label = zone.name.rstrip(".") or "."
        try:
            with self._backend():
                # A refusal the polls remember (after a key change) must not leave the archive without it.
                getattr(self.backends.dns, "_axfr_refused", {}).pop((zone.name, zone.view), None)
                rrsets = self.backends.dns.read_zone(zone.name, zone.view)
            text, serial = zone_text(rrsets)
        except Exception as exc:
            # named down or the transfer refused: the file and its journal, flagged incomplete.
            notes.append(f"AXFR of {label} ({zone.view}) failed: {exc}")
            src.writer.mark_unreadable(f"axfr:{zone.view}/{label}")
            if file is not None:
                with _engine_lock(self.locks_dir, "bind"):
                    src.add(file, zone_part(zone.view, label))
                    src.add(f"{file}.jnl", zone_part(zone.view, label))
                    src.flush()
            src.writer.add_zone(zone.view, label, None, "file")
            return
        src.writer.add_zone(zone.view, label, serial, "axfr", text)

    # Kea --------------------------------------------------------------------------------------

    def _kea(self, engine: str, backend: Any, src: FileSource, include_leases: bool) -> None:
        part = KEA_PARTS[engine]
        value: dict[str, Any] = {}
        with _engine_lock(self.locks_dir, engine):
            conf = Path(backend.file.path)
            try:
                doc = backend.file.document()
            except Exception as exc:
                log.info("%s configuration not parsed: %s", engine, exc)
                doc = None
            if doc is not None:
                value = dict(doc.value.get(backend.file.root) or {})
                for path in backend.file.files(doc):
                    src.add(path, part)
            else:
                value = _parse_kea_text(src, conf, backend.file.root)
                src.add(conf, part)
            if engine == "d2":
                for key in value.get("tsig-keys") or []:
                    if isinstance(key, dict) and key.get("secret-file"):
                        src.add(str(key["secret-file"]), part)
            for path in tls_files(value):
                src.add(path, part)
            src.flush()
        if include_leases and engine in ("kea4", "kea6"):
            for name in _lease_files(engine, value, backend):
                for suffix in LEASE_SUFFIXES:
                    src.add(f"{name}{suffix}", PART_LEASES)
            src.flush()

    # Pelagos ----------------------------------------------------------------------------------

    def _pelagos(self, src: FileSource) -> None:
        p = self.ctx.paths
        for path in (p.node_toml, p.master_key, p.cluster_toml):
            src.add(path, PART_PELAGOS)
        src.add_tree(p.tls_dir, PART_PELAGOS)
        src.add_tree(p.audit_log.parent, PART_PELAGOS)
        src.add_tree(p.pki_dir, PART_PELAGOS)
        src.add_tree(p.var / "webcert", PART_PELAGOS)


def _parse_kea_text(src: FileSource, conf: Path, root: str) -> dict[str, Any]:
    """The configuration's root object when only the helper could read the file."""
    from pelagos.core.keadoc import KeaDocument

    try:
        text = src.read_text(conf)
        return dict(KeaDocument.from_text(text, conf).value.get(root) or {})
    except Exception:
        return {}


def _lease_files(engine: str, value: dict[str, Any], backend: Any) -> list[str]:
    db = value.get("lease-database") or {}
    if not isinstance(db, dict) or db.get("type", "memfile") != "memfile" or db.get("persist") is False:
        return []
    name = db.get("name")
    if not name:
        lease_dir = backend.ctx.engine_config.get("lease_dir", DEFAULT_LEASE_DIR)
        name = f"{lease_dir}/kea-leases{engine[-1]}.csv"
    return [str(name)]


TLS_KEYS = ("trust-anchor", "cert-file", "key-file")


def tls_files(value: dict[str, Any]) -> list[str]:
    """TLS files a Kea configuration loads (HA relationships and peers, HTTP control sockets), so a
    rebuilt node gets them back; a trust anchor that is a folder is skipped by `FileSource.add`."""
    entries: list[Any] = []
    for hook in value.get("hooks-libraries") or []:
        if isinstance(hook, dict) and "libdhcp_ha" in str(hook.get("library", "")):
            for rel in (hook.get("parameters") or {}).get("high-availability") or []:
                if isinstance(rel, dict):
                    entries += [rel, *(rel.get("peers") or [])]
    sockets = value.get("control-sockets") or []
    entries += [value.get("control-socket"), *(sockets if isinstance(sockets, list) else [])]
    out: list[str] = []
    for entry in entries:
        if isinstance(entry, dict):
            out += [str(entry[k]) for k in TLS_KEYS if str(entry.get(k) or "").startswith("/")]
    return list(dict.fromkeys(out))


_INCLUDE_BIND = re.compile(r'(include\s+")(/[^"]+)(")')
_INCLUDE_KEA = re.compile(r'(<\?include\s+")(/[^"]+)("\s*\?>)')


def rewrite_includes(text: str, kea: bool, resolve: Callable[[str], str | None]) -> str:
    """Points absolute includes at the extracted copies (`resolve` returns None to keep a path)."""

    def sub(m: re.Match[str]) -> str:
        target = resolve(m.group(2))
        return m.group(0) if target is None else f"{m.group(1)}{target}{m.group(3)}"

    return (_INCLUDE_KEA if kea else _INCLUDE_BIND).sub(sub, text)
