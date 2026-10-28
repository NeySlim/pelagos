# SPDX-License-Identifier: Apache-2.0
"""Archive recipients and the cluster identity (architecture section 23, design decision 3).

Every archive is encrypted to all of `archives.recipients`. The one `cluster` entry has its
identity in `[secrets] archives/identity`, sealed by the master key; `operator` entries keep no
identity on the nodes. These helpers mutate a ClusterConfig inside `update_cluster`.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any

from pelagos.archives import age
from pelagos.core.secrets import SecretBox
from pelagos.domain.common import to_rfc3339, utcnow

IDENTITY_SECRET = "archives/identity"  # noqa: S105 (a secret name, not a value)
RETIRED_PREFIX = "archives/retired/"
CLUSTER = "cluster"
OPERATOR = "operator"


class ArchiveKeyError(ValueError):
    pass


def retired_secret(recipient: str) -> str:
    return RETIRED_PREFIX + recipient


def recipients(settings: dict[str, Any]) -> list[dict[str, Any]]:
    """The `archives.recipients` entries, as stored."""
    return [dict(r) for r in (settings.get("archives") or {}).get("recipients") or [] if isinstance(r, dict)]


def encryption_recipients(settings: dict[str, Any]) -> list[str]:
    """The `age1...` keys an archive is encrypted to, cluster first."""
    entries = sorted(recipients(settings), key=lambda r: r.get("kind") != CLUSTER)
    return [str(r["recipient"]) for r in entries if age.is_recipient(str(r.get("recipient", "")))]


def _entries(cfg: Any) -> list[dict[str, Any]]:
    arch = cfg.settings.setdefault("archives", {})
    entries = arch.get("recipients")
    if not isinstance(entries, list):
        entries = arch["recipients"] = []
    return entries


def _retire(cfg: Any, box: SecretBox, recipient: str) -> None:
    token = cfg.secrets.pop(IDENTITY_SECRET, None)
    if token is not None:
        # The secret name is the AEAD associated data: re-seal under the retired name.
        cfg.secrets[retired_secret(recipient)] = box.encrypt(
            retired_secret(recipient), box.decrypt(IDENTITY_SECRET, token)
        )


def generate_cluster_identity(
    cfg: Any, box: SecretBox, by: str, label: str = "cluster", now: datetime | None = None
) -> str:
    """Creates (or rotates) the cluster identity; returns it, to be shown to the operator once.

    A former identity stays as `archives/retired/<recipient>` until `prune_retired` drops it."""
    identity = age.generate_identity()
    recipient = age.recipient_of(identity)
    stamp = to_rfc3339(now or utcnow())
    entries = _entries(cfg)
    for old in [e for e in entries if e.get("kind") == CLUSTER]:
        _retire(cfg, box, str(old.get("recipient", "")))
        entries.remove(old)
    cfg.secrets[IDENTITY_SECRET] = box.encrypt(IDENTITY_SECRET, identity)
    entries.insert(
        0,
        {
            "recipient": recipient,
            "label": label,
            "kind": CLUSTER,
            "added_at": stamp,
            "added_by": by,
            "downloaded_at": stamp,
        },
    )
    return identity


def add_operator_recipient(
    cfg: Any, recipient: str, label: str, by: str, now: datetime | None = None
) -> dict[str, Any]:
    recipient = recipient.strip()
    if not age.is_recipient(recipient):
        raise ArchiveKeyError("not an age X25519 recipient (age1...)")
    entries = _entries(cfg)
    if any(e.get("recipient") == recipient for e in entries):
        raise ArchiveKeyError("recipient already present")
    entry = {
        "recipient": recipient,
        "label": label,
        "kind": OPERATOR,
        "added_at": to_rfc3339(now or utcnow()),
        "added_by": by,
    }
    entries.append(entry)
    return entry


def remove_recipient(cfg: Any, box: SecretBox, recipient: str) -> dict[str, Any]:
    """Drops a recipient; the cluster identity, when removed, is kept as retired."""
    entries = _entries(cfg)
    for entry in entries:
        if entry.get("recipient") == recipient:
            if entry.get("kind") == CLUSTER:
                _retire(cfg, box, recipient)
            entries.remove(entry)
            return entry
    raise ArchiveKeyError("unknown recipient")


def cluster_identities(cfg: Any, box: SecretBox) -> list[str]:
    """Identities the nodes hold: the current one first, then the retired ones."""
    out = []
    if IDENTITY_SECRET in cfg.secrets:
        out.append(box.decrypt(IDENTITY_SECRET, cfg.secrets[IDENTITY_SECRET]))
    for name in sorted(n for n in cfg.secrets if n.startswith(RETIRED_PREFIX)):
        out.append(box.decrypt(name, cfg.secrets[name]))
    return out


def prune_retired(cfg: Any, still_needed: Iterable[str]) -> list[str]:
    """Drops retired identities whose recipient no kept archive uses; returns the dropped ones."""
    keep = set(still_needed)
    dropped = [
        n[len(RETIRED_PREFIX) :]
        for n in cfg.secrets
        if n.startswith(RETIRED_PREFIX) and n[len(RETIRED_PREFIX) :] not in keep
    ]
    for recipient in dropped:
        del cfg.secrets[retired_secret(recipient)]
    return dropped
