# SPDX-License-Identifier: Apache-2.0
"""Whether a primary zone takes dynamic updates, from its update rules as named.conf writes them.

Shared by the BIND connector (zone mode) and the installer audit so both classify zones alike.
"""

from __future__ import annotations


def _norm(element: str) -> str:
    return element.replace('"', "").replace(" ", "").lower()


def allow_update_permits(elements: list[str] | None) -> bool:
    """An allow-update list lets something update: `none` matches nothing, `!any` refuses the rest."""
    for e in elements or []:
        norm = _norm(e)
        if norm == "!any":
            return False
        if norm != "none":
            return True
    return False


def effective_allow_update(*levels: list[str] | None) -> list[str] | None:
    """allow-update applying to a zone: the first level that sets it (zone, then view, then options)."""
    for level in levels:
        if level is not None:
            return level
    return None


def takes_updates(has_update_policy: bool, allow_update: list[str] | None) -> bool:
    """update-policy (zone only) always makes the zone dynamic; otherwise the effective allow-update."""
    return has_update_policy or allow_update_permits(allow_update)
