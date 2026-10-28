# SPDX-License-Identifier: Apache-2.0
"""What every archive destination target does. One `archives.destinations` entry gives one target,
or one per node for a peer destination. At a destination a node's archives sit under the folder
named by its node id: `<file>`, `<file>.sha256`, then `<file>.json` (ArchiveMeta) written last."""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from pathlib import Path

from pelagos.archives.destinations.config import DestinationConfig
from pelagos.archives.model import SUFFIX, SUM_SUFFIX, ArchiveError, ArchiveMeta, parse_filename
from pelagos.archives.store import META_SUFFIX

NODE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
PROBE_PREFIX = ".pelagos-probe-"


class DestinationError(Exception):
    """A destination that cannot be reached, written or read; the message is shown to the admin."""


class DestinationMismatch(DestinationError):
    """The copy read back from the destination does not match the archive's sum."""


def checked_name(meta: ArchiveMeta) -> str:
    """The archive's file name, refused when it could leave its folder."""
    name = meta.filename
    if "/" in name or parse_filename(name) is None:
        raise ArchiveError(f"not an archive file name: {name!r}")
    if not NODE_ID_RE.match(meta.node_id):
        raise ArchiveError(f"not a node id: {meta.node_id!r}")
    return name


def sum_text(meta: ArchiveMeta) -> bytes:
    return f"{meta.sha256}  {checked_name(meta)}\n".encode()


def meta_bytes(meta: ArchiveMeta) -> bytes:
    return json.dumps(meta.to_dict(), indent=2, sort_keys=True).encode()


def parse_meta(data: bytes, name: str) -> ArchiveMeta | None:
    """The ArchiveMeta of a `<file>.json` sidecar, None when it is not one or names another file."""
    if not name.endswith(SUFFIX + META_SUFFIX):
        return None
    try:
        meta = ArchiveMeta.from_dict(json.loads(data))
    except (ValueError, KeyError, TypeError):
        return None
    if meta.filename + META_SUFFIX != name or parse_filename(meta.filename) is None:
        return None
    return meta


def sidecar_names(meta: ArchiveMeta) -> tuple[str, str, str]:
    name = checked_name(meta)
    return name, name + SUM_SUFFIX, name + META_SUFFIX


class Target(ABC):
    """One place an archive is copied to."""

    # False when the target applies retention itself (a peer, on receipt).
    deletes = True

    def __init__(self, config: DestinationConfig, label: str | None = None) -> None:
        self.config = config
        self.label = label or config.label

    @abstractmethod
    def put(self, archive: Path, meta: ArchiveMeta) -> None:
        """Copies the archive, its `.sha256` then its ArchiveMeta, replacing a former copy."""

    @abstractmethod
    def verify(self, meta: ArchiveMeta) -> None:
        """Reads the copy back and compares its sum; raises DestinationMismatch when it differs."""

    @abstractmethod
    def list(self, origin: str | None = None) -> list[ArchiveMeta]:
        """Archives at the destination, of one origin node or of every node (None)."""

    def delete(self, meta: ArchiveMeta) -> None:  # noqa: B027 (a peer never deletes)
        """Removes a copy (sidecar first, so a half-deleted copy is never listed)."""

    @abstractmethod
    def probe(self) -> None:
        """Writes, reads back and deletes a small file; raises DestinationError."""

    def close(self) -> None:  # noqa: B027
        """Releases what the target holds (temporary key files)."""
