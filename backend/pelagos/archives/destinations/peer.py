# SPDX-License-Identifier: Apache-2.0
"""Another cluster node, over the replication mTLS (`/repl/v1/archives`). The peer checks the sum
on receipt, files the archive under `peers/<origin>/` and applies the retention itself."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from pelagos.archives.destinations.base import DestinationError, DestinationMismatch, Target
from pelagos.archives.destinations.config import DestinationConfig
from pelagos.archives.model import ArchiveMeta


class _HashSink:
    def __init__(self) -> None:
        self.hash = hashlib.sha256()

    def write(self, data: bytes) -> int:
        self.hash.update(data)
        return len(data)


class PeerTarget(Target):
    deletes = False

    def __init__(self, config: DestinationConfig, client: Any, label: str) -> None:
        super().__init__(config, label)
        # A core.replication.ReplicationClient bound to that peer.
        self.client = client

    def _call(self, what: str, fn: Any, *args: Any) -> Any:
        from pelagos.core.replication import ReplicationError

        try:
            return fn(*args)
        except ReplicationError as exc:
            if exc.status == 404 and exc.code == "not_found" and what == "list":
                raise DestinationError(f"{self.label} does not take archives (older version?)") from exc
            raise DestinationError(str(exc)) from exc

    def put(self, archive: Path, meta: ArchiveMeta) -> None:
        self._call("put", self.client.put_archive, archive, meta.to_dict())

    def verify(self, meta: ArchiveMeta) -> None:
        sink = _HashSink()
        self._call("get", self.client.fetch_archive, meta.id, sink)
        if sink.hash.hexdigest() != meta.sha256:
            raise DestinationMismatch(f"the copy on {self.label} does not match its sum")

    def listing(self, origin: str | None = None) -> dict[str, Any]:
        return dict(self._call("list", self.client.list_archives, origin))

    def list(self, origin: str | None = None) -> list[ArchiveMeta]:
        out = []
        for item in self.listing(origin).get("items") or []:
            try:
                out.append(ArchiveMeta.from_dict(item))
            except (KeyError, TypeError, ValueError):
                continue
        return sorted(out, key=lambda m: m.created_at, reverse=True)

    def probe(self) -> None:
        self.listing()
