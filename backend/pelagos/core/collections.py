# SPDX-License-Identifier: Apache-2.0
"""Generic replicated collections of cluster.toml (architecture section 10).

Shadows the standard `collections` only inside this directory: always import it as
`pelagos.core.collections`. Adding a collection is one line in COLLECTIONS plus its tests.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pelagos.core.replication import PeerStatus


@dataclass(frozen=True, slots=True)
class Collection:
    # Identity field: a non-empty string, immutable per record; never changed once released.
    key: str = "id"
    # Top-level fields holding a hash or a sealed value: masked in conflict audit entries.
    secret_fields: tuple[str, ...] = ()


# Name -> definition. Merged like `users` (core.cluster_merge.records()).
COLLECTIONS: dict[str, Collection] = {
    # B1-KEAOFFLINE: partial applies waiting for reconciliation, id "<engine>:<source>:<target>".
    "kea_partials": Collection(),
}


def peers_missing(name: str, statuses: Iterable[PeerStatus]) -> list[str]:
    """Reachable peers whose last status does not list `name` (an older node lists nothing)."""
    out = []
    for status in statuses:
        if not status.reachable:
            continue
        if status.collections is None or name not in status.collections:
            out.append(status.node_id)
    return sorted(out)
