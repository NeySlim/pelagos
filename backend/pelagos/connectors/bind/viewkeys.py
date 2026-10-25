# SPDX-License-Identifier: Apache-2.0
"""The TSIG key Pelagos uses per view: `settings.dns.view_keys.<view>`, a key name or {admin, read}."""

from __future__ import annotations

from typing import Any

from pelagos.connectors.base import NotSupported

DEFAULT_VIEW = "_default"
GLOBAL_KEYS = {"read": "ddi-read", "admin": "ddi-admin"}


def global_key_name(dns: dict[str, Any], role: str) -> str:
    return str(dns.get(f"{role}_key") or GLOBAL_KEYS[role])


def view_key_name(dns: dict[str, Any], role: str, view: str | None) -> str | None:
    """Key of `role` for `view`; None for the default view (the global key applies). A non-default view
    is selected by its own key (`match-clients { key ...; }`), so one without it raises NotSupported."""
    if view in (None, "", DEFAULT_VIEW):
        return None
    entry = (dns.get("view_keys") or {}).get(view)
    name = entry.get(role) if isinstance(entry, dict) else entry
    if not name:
        raise NotSupported(f"no TSIG key configured for view {view} (settings dns.view_keys)")
    return str(name)
