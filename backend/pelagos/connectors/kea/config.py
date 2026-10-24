# SPDX-License-Identifier: Apache-2.0
"""Kea configuration round trip (section 9): projections between config-get JSON and domain objects.

WP-KEA implements the bodies. Rules: `raw` keeps the original object, to_kea()
overlays typed fields on raw, 2.6/3.x key names are normalized here only.
"""

from __future__ import annotations

from typing import Any

from pelagos.domain import ClientClass, Family, OptionData, Reservation, SharedNetwork, Subnet

PELAGOS_CONTEXT_KEY = "pelagos"


def option_from_kea(obj: dict[str, Any], space_default: str) -> OptionData:
    return OptionData(
        name=obj.get("name"),
        code=obj.get("code"),
        space=obj.get("space", space_default),
        data=str(obj.get("data", "")),
        csv_format=obj.get("csv-format"),
        always_send=obj.get("always-send"),
        never_send=obj.get("never-send"),
        raw=dict(obj),
    )


def option_to_kea(opt: OptionData) -> dict[str, Any]:
    out = dict(opt.raw)
    for key, value in (
        ("name", opt.name), ("code", opt.code), ("space", opt.space), ("data", opt.data),
        ("csv-format", opt.csv_format), ("always-send", opt.always_send), ("never-send", opt.never_send),
    ):  # fmt: skip
        if value is None:
            out.pop(key, None)
        else:
            out[key] = value
    return out


def subnet_from_kea(
    obj: dict[str, Any], family: Family, shared_network: str | None = None, version: str | None = None
) -> Subnet:
    raise NotImplementedError("WP-KEA")


def subnet_to_kea(subnet: Subnet, version: str | None = None) -> dict[str, Any]:
    raise NotImplementedError("WP-KEA")


def shared_network_from_kea(obj: dict[str, Any], family: Family, version: str | None = None) -> SharedNetwork:
    raise NotImplementedError("WP-KEA")


def reservation_from_kea(obj: dict[str, Any], subnet_id: int | None) -> Reservation:
    raise NotImplementedError("WP-KEA")


def reservation_to_kea(res: Reservation) -> dict[str, Any]:
    raise NotImplementedError("WP-KEA")


def client_class_from_kea(obj: dict[str, Any], version: str | None = None) -> ClientClass:
    raise NotImplementedError("WP-KEA")


def pelagos_context(user_context: dict[str, Any]) -> dict[str, Any]:
    """Pelagos metadata lives under user-context.pelagos; other keys are untouched."""
    return dict(user_context.get(PELAGOS_CONTEXT_KEY) or {})


def with_pelagos_context(user_context: dict[str, Any], **meta: Any) -> dict[str, Any]:
    out = dict(user_context)
    current = dict(out.get(PELAGOS_CONTEXT_KEY) or {})
    current.update({k: v for k, v in meta.items() if v is not None})
    out[PELAGOS_CONTEXT_KEY] = current
    return out


def is_v3(version: str | None) -> bool:
    try:
        return int((version or "3").split(".")[0]) >= 3
    except ValueError:
        return True
