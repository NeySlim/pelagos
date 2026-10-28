# SPDX-License-Identifier: Apache-2.0
"""Archive files: a gzip tar streamed into age, never written in clear (architecture section 23).

Layout inside the tar: `files/<absolute path without the leading slash>`, `zones/<view>/<zone>.zone`
(names percent-encoded), then `manifest.json` last, since it carries the sum of every member.
"""

from __future__ import annotations

import grp
import hashlib
import io
import json
import os
import pwd
import stat
import tarfile
from collections.abc import Callable, Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO
from urllib.parse import quote

from pelagos.archives import age
from pelagos.archives.model import (
    MANIFEST,
    SUM_SUFFIX,
    ArchiveError,
    ArchiveMeta,
    Manifest,
    ManifestFile,
    ManifestZone,
    archive_filename,
)
from pelagos.domain.common import new_id, utcnow

_READ = 1024 * 1024


def file_member(path: str) -> str:
    rel = PurePosixPath(path)
    if not rel.is_absolute() or ".." in rel.parts:
        raise ArchiveError(f"archived paths must be absolute and normalized: {path!r}")
    return "files/" + str(rel)[1:]


def zone_member(view: str, zone: str) -> str:
    return f"zones/{quote(view, safe='')}/{quote(zone, safe='')}.zone"


def _owner(st: os.stat_result) -> str:
    try:
        user = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        user = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    return f"{user}:{group}"


class _HashingWriter:
    def __init__(self, out: BinaryIO) -> None:
        self.out = out
        self.hash = hashlib.sha256()
        self.size = 0

    def write(self, data: bytes) -> int:
        self.out.write(data)
        self.hash.update(data)
        self.size += len(data)
        return len(data)

    def flush(self) -> None:
        self.out.flush()


class _HashingReader:
    def __init__(self, src: BinaryIO) -> None:
        self.src = src
        self.hash = hashlib.sha256()
        self.size = 0

    def read(self, n: int = -1) -> bytes:
        data = self.src.read(n)
        self.hash.update(data)
        self.size += len(data)
        return data


class ArchiveWriter:
    """Writes one encrypted archive into `directory`, atomically (temporary name, then rename).

    Use as a context manager: `finish()` returns the ArchiveMeta, an exception discards the file."""

    def __init__(
        self,
        directory: Path,
        *,
        node_id: str,
        node_name: str,
        recipients: Sequence[str],
        versions: dict[str, str] | None = None,
        engines: Sequence[str] = (),
        created_at: datetime | None = None,
        archive_id: str | None = None,
    ) -> None:
        created = (created_at or utcnow()).astimezone(UTC).replace(microsecond=0)
        self.manifest = Manifest(
            archive_id=archive_id or new_id(),
            node_id=node_id,
            node_name=node_name,
            created_at=created,
            versions=dict(versions or {}),
            engines=list(engines),
        )
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = directory / archive_filename(node_name, created)
        if self.path.exists():
            raise ArchiveError(f"{self.path.name} already exists")
        self._tmp = directory / f".{self.path.name}.{os.getpid()}.part"
        fd = os.open(self._tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self._raw = os.fdopen(fd, "wb")
        self._out = _HashingWriter(self._raw)
        self._enc = age.Encryptor(self._out, recipients)
        self._tar = tarfile.open(fileobj=self._enc, mode="w|gz", format=tarfile.PAX_FORMAT)  # type: ignore[arg-type]
        self._members: set[str] = set()
        self._done = False

    def _info(self, name: str, size: int, mode: int, mtime: float) -> tarfile.TarInfo:
        if name in self._members:
            raise ArchiveError(f"{name} added twice")
        self._members.add(name)
        info = tarfile.TarInfo(name)
        info.size, info.mode, info.mtime = size, mode & 0o7777, int(mtime)
        return info

    def add_file(self, path: Path | str, part: str) -> bool:
        """Archives a regular file; False (listed as unreadable) when it cannot be opened."""
        name = str(path)
        try:
            fh = open(name, "rb")
        except OSError:
            self.mark_unreadable(name)
            return False
        with fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode):
                self.mark_unreadable(name)
                return False
            reader = _HashingReader(fh)
            info = self._info(file_member(name), st.st_size, st.st_mode, st.st_mtime)
            self._tar.addfile(info, reader)  # type: ignore[arg-type]
        mode, digest = stat.S_IMODE(st.st_mode), reader.hash.hexdigest()
        self.manifest.files.append(ManifestFile(name, mode, _owner(st), digest, part, reader.size))
        return True

    def add_bytes(self, path: str, data: bytes, part: str, *, mode: int = 0o600, owner: str = "") -> None:
        """Archives content read another way (privileged helper, socket) as if it were `path`."""
        info = self._info(file_member(path), len(data), mode, utcnow().timestamp())
        self._tar.addfile(info, io.BytesIO(data))
        self.manifest.files.append(
            ManifestFile(path, mode, owner, hashlib.sha256(data).hexdigest(), part, len(data))
        )

    def add_zone(
        self, view: str, zone: str, serial: int | None, source: str, text: bytes | None = None
    ) -> None:
        """Records a zone; `text` (an AXFR snapshot in master format) is stored beside the files."""
        digest = ""
        if text is not None:
            name = zone_member(view, zone)
            self._tar.addfile(self._info(name, len(text), 0o600, utcnow().timestamp()), io.BytesIO(text))
            digest = hashlib.sha256(text).hexdigest()
        self.manifest.zones.append(ManifestZone(view, zone, serial, source, digest))

    def mark_unreadable(self, path: str) -> None:
        if path not in self.manifest.unreadable:
            self.manifest.unreadable.append(path)
        self.manifest.complete = False

    def finish(self, destinations: Sequence[str] = ()) -> ArchiveMeta:
        body = json.dumps(self.manifest.to_dict(), indent=2, sort_keys=True).encode()
        self._tar.addfile(self._info(MANIFEST, len(body), 0o600, utcnow().timestamp()), io.BytesIO(body))
        self._tar.close()
        self._enc.close()
        self._raw.flush()
        os.fsync(self._raw.fileno())
        self._raw.close()
        os.replace(self._tmp, self.path)
        digest = self._out.hash.hexdigest()
        write_sum(self.path, digest)
        _fsync_dir(self.path.parent)
        self._done = True
        return ArchiveMeta(
            id=self.manifest.archive_id,
            node_id=self.manifest.node_id,
            created_at=self.manifest.created_at,
            size=self._out.size,
            sha256=digest,
            destinations=list(destinations),
            complete=self.manifest.complete,
            versions=dict(self.manifest.versions),
            filename=self.path.name,
        )

    def abort(self) -> None:
        if self._done:
            return
        self._done = True
        try:
            self._raw.close()
        finally:
            self._tmp.unlink(missing_ok=True)

    def __enter__(self) -> ArchiveWriter:
        return self

    def __exit__(self, exc_type: Any, *exc: object) -> None:
        if exc_type is not None:
            self.abort()


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


# Sums ---------------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while data := fh.read(_READ):
            h.update(data)
    return h.hexdigest()


def sum_path(path: Path) -> Path:
    return path.with_name(path.name + SUM_SUFFIX)


def write_sum(path: Path, digest: str | None = None) -> Path:
    """`<file>.sha256` in `sha256sum` format, so `sha256sum -c` checks it without the key."""
    digest = digest or sha256_file(path)
    target = sum_path(path)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(f"{digest}  {path.name}\n")
    return target


def read_sum(path: Path) -> str:
    text = sum_path(path).read_text().split()
    if len(text) != 2 or text[1] != path.name or len(text[0]) != 64:
        raise ArchiveError(f"malformed {sum_path(path).name}")
    return text[0].lower()


def verify_sum(path: Path) -> bool:
    """True when the encrypted file matches its `.sha256`; no key needed."""
    return sha256_file(path) == read_sum(path)


# Reading ------------------------------------------------------------------------------


def _members(src: BinaryIO, identities: Sequence[str]) -> Iterator[tuple[tarfile.TarInfo, Any]]:
    dec = age.Decryptor(src, identities)
    try:
        with tarfile.open(fileobj=dec, mode="r|gz") as tar:  # type: ignore[call-overload]
            for info in tar:
                name = PurePosixPath(info.name)
                if name.is_absolute() or ".." in name.parts:
                    raise ArchiveError(f"unsafe member name {info.name!r}")
                if not info.isreg():
                    raise ArchiveError(f"unexpected member type for {info.name!r}")
                yield info, tar.extractfile(info)
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ArchiveError(f"damaged archive: {exc}") from exc


def _walk(
    path: Path, identities: Sequence[str], sink: Callable[[str, Any], str]
) -> tuple[Manifest, dict[str, str]]:
    """Feeds every member but the manifest to `sink` (returns its sha256), then checks the sums."""
    digests: dict[str, str] = {}
    manifest: Manifest | None = None
    with open(path, "rb") as fh:
        for info, member in _members(fh, identities):
            if info.name == MANIFEST:
                manifest = Manifest.from_dict(json.loads(member.read()))
            elif manifest is not None:
                raise ArchiveError("member after the manifest")
            else:
                digests[info.name] = sink(info.name, member)
    if manifest is None:
        raise ArchiveError("archive has no manifest")
    expected = {file_member(f.path): f.sha256 for f in manifest.files}
    expected.update({zone_member(z.view, z.zone): z.sha256 for z in manifest.zones if z.sha256})
    if expected != digests:
        bad = sorted(set(expected.items()) ^ set(digests.items()))
        raise ArchiveError(f"archive content does not match its manifest: {bad[:3]}")
    return manifest, digests


def _hash_stream(member: Any, out: BinaryIO | None = None) -> str:
    h = hashlib.sha256()
    while data := member.read(_READ):
        h.update(data)
        if out is not None:
            out.write(data)
    return h.hexdigest()


def read_manifest(path: Path, identities: Sequence[str]) -> Manifest:
    """Decrypts the whole archive (the manifest is last) and checks every member's sum."""
    manifest, _ = _walk(path, identities, lambda _name, member: _hash_stream(member))
    return manifest


def read_members(
    path: Path, identities: Sequence[str], select: Callable[[str], bool]
) -> tuple[Manifest, dict[str, bytes]]:
    """Members chosen by name, in memory (zone snapshots, small configuration files)."""
    out: dict[str, bytes] = {}

    def sink(name: str, member: Any) -> str:
        if not select(name):
            return _hash_stream(member)
        buf = io.BytesIO()
        digest = _hash_stream(member, buf)
        out[name] = buf.getvalue()
        return digest

    manifest, _ = _walk(path, identities, sink)
    return manifest, out


def extract(
    path: Path, identities: Sequence[str], dest: Path, select: Callable[[str], bool] | None = None
) -> Manifest:
    """Writes the chosen members under `dest` (0600 files, 0700 directories), sums checked.

    On a mismatch the extracted tree is left for inspection and ArchiveError is raised."""
    dest.mkdir(parents=True, exist_ok=True, mode=0o700)

    def sink(name: str, member: Any) -> str:
        if select is not None and not select(name):
            return _hash_stream(member)
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as out:
            return _hash_stream(member, out)

    manifest, _ = _walk(path, identities, sink)
    return manifest
