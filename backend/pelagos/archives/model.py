# SPDX-License-Identifier: Apache-2.0
"""Archive manifest, ArchiveMeta and file names (architecture section 23)."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from pelagos.domain.common import from_rfc3339, to_rfc3339

FORMAT = 1
SUFFIX = ".tar.gz.age"
SUM_SUFFIX = ".sha256"
MANIFEST = "manifest.json"
_STAMP = "%Y%m%dT%H%M%SZ"
_NAME_RE = re.compile(r"^(?P<node>.+)-(?P<stamp>\d{8}T\d{6}Z)" + re.escape(SUFFIX) + "$")
_SAFE_NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ArchiveError(Exception):
    """An archive that cannot be written, read or trusted."""


def archive_filename(node_name: str, created_at: datetime) -> str:
    """`<node name>-<YYYYMMDDTHHMMSSZ>.tar.gz.age`, the time in UTC."""
    if not _SAFE_NODE_RE.match(node_name):
        raise ArchiveError(f"node name {node_name!r} cannot name an archive file")
    return f"{node_name}-{created_at.astimezone(UTC).strftime(_STAMP)}{SUFFIX}"


def parse_filename(name: str) -> tuple[str, datetime] | None:
    """(node name, creation time) of an archive file name, None for anything else."""
    m = _NAME_RE.match(name)
    if not m:
        return None
    return m["node"], datetime.strptime(m["stamp"], _STAMP).replace(tzinfo=UTC)


@dataclass
class ManifestFile:
    path: str
    mode: int
    owner: str
    sha256: str
    part: str
    size: int = 0

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["mode"] = f"{self.mode:04o}"
        return out

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ManifestFile:
        mode = d.get("mode", 0)
        return cls(
            path=str(d["path"]),
            mode=int(mode, 8) if isinstance(mode, str) else int(mode),
            owner=str(d.get("owner", "")),
            sha256=str(d["sha256"]),
            part=str(d.get("part", "")),
            size=int(d.get("size", 0)),
        )


@dataclass
class ManifestZone:
    view: str
    zone: str
    serial: int | None
    source: str  # "axfr" | "file"
    sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ManifestZone:
        serial = d.get("serial")
        return cls(
            view=str(d["view"]),
            zone=str(d["zone"]),
            serial=None if serial is None else int(serial),
            source=str(d.get("source", "file")),
            sha256=str(d.get("sha256", "")),
        )


@dataclass
class Manifest:
    archive_id: str
    node_id: str
    node_name: str
    created_at: datetime
    versions: dict[str, str] = field(default_factory=dict)
    engines: list[str] = field(default_factory=list)
    # `config-hash-get` of each Kea daemon at archive time (engine -> hash).
    hashes: dict[str, str] = field(default_factory=dict)
    files: list[ManifestFile] = field(default_factory=list)
    zones: list[ManifestZone] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)
    complete: bool = True
    format: int = FORMAT

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "archive_id": self.archive_id,
            "node_id": self.node_id,
            "node_name": self.node_name,
            "created_at": to_rfc3339(self.created_at),
            "versions": dict(self.versions),
            "engines": list(self.engines),
            "hashes": dict(self.hashes),
            "files": [f.to_dict() for f in self.files],
            "zones": [z.to_dict() for z in self.zones],
            "unreadable": list(self.unreadable),
            "complete": self.complete,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Manifest:
        fmt = int(d.get("format", 0))
        if fmt != FORMAT:
            raise ArchiveError(f"unsupported archive format {fmt}")
        return cls(
            format=fmt,
            archive_id=str(d["archive_id"]),
            node_id=str(d["node_id"]),
            node_name=str(d.get("node_name", "")),
            created_at=from_rfc3339(d["created_at"]),
            versions={str(k): str(v) for k, v in (d.get("versions") or {}).items()},
            engines=[str(e) for e in d.get("engines") or []],
            hashes={str(k): str(v) for k, v in (d.get("hashes") or {}).items()},
            files=[ManifestFile.from_dict(f) for f in d.get("files") or []],
            zones=[ManifestZone.from_dict(z) for z in d.get("zones") or []],
            unreadable=[str(p) for p in d.get("unreadable") or []],
            complete=bool(d.get("complete", False)),
        )


@dataclass
class ArchiveMeta:
    id: str
    node_id: str
    created_at: datetime
    size: int
    sha256: str
    destinations: list[str] = field(default_factory=list)
    complete: bool = True
    versions: dict[str, str] = field(default_factory=dict)
    verified_at: datetime | None = None
    filename: str = ""
    # age recipients the file is encrypted to; None for an archive written before they were recorded.
    recipients: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "node_id": self.node_id,
            "created_at": to_rfc3339(self.created_at),
            "size": self.size,
            "sha256": self.sha256,
            "destinations": list(self.destinations),
            "complete": self.complete,
            "versions": dict(self.versions),
            "verified_at": to_rfc3339(self.verified_at) if self.verified_at else None,
            "filename": self.filename,
            "recipients": None if self.recipients is None else list(self.recipients),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ArchiveMeta:
        verified = d.get("verified_at")
        recipients = d.get("recipients")
        return cls(
            id=str(d["id"]),
            node_id=str(d["node_id"]),
            created_at=from_rfc3339(d["created_at"]),
            size=int(d["size"]),
            sha256=str(d["sha256"]),
            destinations=[str(x) for x in d.get("destinations") or []],
            complete=bool(d.get("complete", False)),
            versions={str(k): str(v) for k, v in (d.get("versions") or {}).items()},
            verified_at=from_rfc3339(verified) if verified else None,
            filename=str(d.get("filename", "")),
            recipients=[str(r) for r in recipients] if isinstance(recipients, list) else None,
        )
