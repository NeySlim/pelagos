# SPDX-License-Identifier: Apache-2.0
"""The targets of one destination entry, built from the node context (keys, peers, TLS files)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from pelagos.archives.destinations.base import DestinationError, Target
from pelagos.archives.destinations.config import MOUNTED, PEER, SFTP, DestinationConfig, ssh_key_secret


def build_targets(config: DestinationConfig, ctx: Any, spool: Path | None = None) -> list[Target]:
    """Raises DestinationError when the destination cannot be used from this node."""
    if config.type == MOUNTED:
        from pelagos.archives.destinations.mounted import MountedTarget

        return [MountedTarget(config, ismount=os.path.ismount)]
    if config.type == SFTP:
        from pelagos.archives.destinations.sftp import SftpTarget

        try:
            key = ctx.get_secret(ssh_key_secret(config.id))
        except Exception as exc:
            raise DestinationError(f"the SSH key of {config.label} cannot be read: {exc}") from exc
        if not key:
            raise DestinationError(f"no SSH key stored for {config.label}")
        run = ctx.paths.run if ctx.paths.run.is_dir() else None
        return [SftpTarget(config, key, workdir=run, spool=spool)]
    if config.type == PEER:
        return peer_targets(config, ctx)
    raise DestinationError(f"unknown destination type {config.type}")


def peer_targets(config: DestinationConfig, ctx: Any) -> list[Target]:
    from pelagos.archives.destinations.peer import PeerTarget
    from pelagos.core.replication import ReplicationClient, client_ssl_context, node_enrolled, node_tls_files

    if not node_enrolled(ctx.paths):
        raise DestinationError("this node has no cluster certificate: a peer destination needs a cluster")
    me = ctx.node.id
    nodes = [p for p in ctx.cluster().nodes if p.id != me]
    wanted = config.params.get("node_ids") or []
    if wanted:
        missing = [i for i in wanted if i != me and not any(p.id == i for p in nodes)]
        if missing:
            raise DestinationError(f"unknown node(s) {', '.join(missing)}")
        nodes = [p for p in nodes if p.id in wanted]
    if not nodes:
        raise DestinationError("no other node in the cluster to send archives to")
    tls = client_ssl_context(*node_tls_files(ctx.paths))
    return [PeerTarget(config, ReplicationClient(p, tls, timeout=120.0), p.name or p.id) for p in nodes]
