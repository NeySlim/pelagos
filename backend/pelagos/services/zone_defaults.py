# SPDX-License-Identifier: Apache-2.0
"""Defaults of a primary zone created by Pelagos: the admin key may update it, the read key transfer it.

Record plans read a zone by AXFR with the read key and write it by UPDATE with the admin key, so a
new primary without them could never be edited. A field given in the request, even empty, is kept.
"""

from __future__ import annotations

from typing import Any

from pelagos.domain import Change, ChangeOp

DEFAULT_VIEW = "_default"


def key_names(settings: dict[str, Any], view: str | None) -> tuple[str, str]:
    """(admin key, read key) for `view`: `dns.view_keys.<view>` first, then `dns.admin_key/read_key`."""
    dns = dict(settings.get("dns") or {})
    admin = str(dns.get("admin_key") or "ddi-admin")
    read = str(dns.get("read_key") or "ddi-read")
    if view not in (None, "", DEFAULT_VIEW):
        entry = (dns.get("view_keys") or {}).get(view)
        if isinstance(entry, dict):
            admin = str(entry.get("admin") or admin)
            read = str(entry.get("read") or read)
        elif entry:
            admin = read = str(entry)
    return admin, read


def apply_key_defaults(change: Change, settings: dict[str, Any]) -> None:
    """Fill update_policy and allow_transfer of a new primary zone in place when they are absent."""
    if ChangeOp(change.op) is not ChangeOp.ADD or not isinstance(change.after, dict):
        return
    after = change.after
    if (after.get("kind") or "primary") != "primary":
        return
    view = after.get("view") or change.target.partition("/")[0] or DEFAULT_VIEW
    admin, read = key_names(settings, view)
    # BIND refuses update-policy next to allow-update: an explicit allow-update keeps its own rule.
    if "update_policy" not in after and "allow_update" not in after:
        after["update_policy"] = [f"grant {admin} zonesub ANY"]
    if "allow_transfer" not in after:
        after["allow_transfer"] = [f"key {read}"]
