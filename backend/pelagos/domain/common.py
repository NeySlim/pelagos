# SPDX-License-Identifier: Apache-2.0
"""Shared domain primitives: engines, ids, time and the Model base class.

Every domain dataclass derives from Model, which gives it to_dict/from_dict with
the JSON conventions of docs/architecture.md section 4. No I/O lives here.
"""

from __future__ import annotations

import dataclasses
import enum
import os
import secrets
import threading
import time
import types
import typing
from datetime import UTC, datetime
from typing import Any, TypeVar, get_args, get_origin, get_type_hints

T = TypeVar("T", bound="Model")

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


class Engine(enum.StrEnum):
    BIND = "bind"
    KEA4 = "kea4"
    KEA6 = "kea6"
    D2 = "d2"


class Family(enum.StrEnum):
    V4 = "v4"
    V6 = "v6"

    @property
    def kea_engine(self) -> Engine:
        return Engine.KEA4 if self is Family.V4 else Engine.KEA6


def utcnow() -> datetime:
    """Timezone-aware UTC now at millisecond precision, so JSON round trips are exact."""
    now = datetime.now(UTC)
    return now.replace(microsecond=(now.microsecond // 1000) * 1000)


_ulid_lock = threading.Lock()
_ulid_last: tuple[int, int] = (0, 0)


def new_id() -> str:
    """ULID: 48 bits of milliseconds then 80 random bits, Crockford base32, monotonic within a process."""
    global _ulid_last
    ms = int(time.time() * 1000)
    with _ulid_lock:
        last_ms, last_rand = _ulid_last
        if ms <= last_ms:
            # Same millisecond (or clock went back): increment so ids stay sortable in creation order.
            ms, rand = last_ms, last_rand + 1
        else:
            rand = int.from_bytes(secrets.token_bytes(10), "big")
        _ulid_last = (ms, rand)
    value = (ms << 80) | rand
    out = []
    for _ in range(26):
        out.append(_CROCKFORD[value & 31])
        value >>= 5
    return "".join(reversed(out))


def ulid_time(ulid: str) -> datetime:
    """Decode the timestamp part of a ULID."""
    value = 0
    for ch in ulid[:10]:
        value = value * 32 + _CROCKFORD.index(ch.upper())
    return datetime.fromtimestamp(value / 1000, tz=UTC)


def to_rfc3339(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    dt = dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def from_rfc3339(value: str | int | float | datetime) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, int | float):
        return datetime.fromtimestamp(value, tz=UTC)
    text = value.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _encode(value: Any) -> Any:
    if isinstance(value, Model):
        return value.to_dict()
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, datetime):
        return to_rfc3339(value)
    if isinstance(value, list | tuple | set | frozenset):
        return [_encode(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _encode(v) for k, v in value.items()}
    return value


def _strip_optional(hint: Any) -> tuple[Any, bool]:
    origin = get_origin(hint)
    if origin is typing.Union or origin is types.UnionType:
        args = [a for a in get_args(hint) if a is not type(None)]
        if len(args) == 1:
            return args[0], True
        return hint, True
    return hint, False


def _decode(value: Any, hint: Any) -> Any:
    if value is None:
        return None
    hint, _ = _strip_optional(hint)
    if hint is Any or hint is object:
        return value
    origin = get_origin(hint)
    if origin in (list, set, tuple):
        (item_hint,) = get_args(hint) or (Any,)
        return [_decode(v, item_hint) for v in value]
    if origin is dict:
        args = get_args(hint)
        value_hint = args[1] if len(args) == 2 else Any
        return {k: _decode(v, value_hint) for k, v in value.items()}
    if origin is typing.Union or origin is types.UnionType:
        return value
    if isinstance(hint, type):
        if issubclass(hint, Model):
            return hint.from_dict(value) if isinstance(value, dict) else value
        if issubclass(hint, enum.Enum):
            return hint(value)
        if hint is datetime:
            return from_rfc3339(value)
        if hint is int and isinstance(value, str) and value.isdigit():
            return int(value)
    return value


class Model:
    """Base for domain dataclasses: JSON conversion driven by type hints."""

    __slots__ = ()
    _hints_cache: typing.ClassVar[dict[type, dict[str, Any]]] = {}

    @classmethod
    def _hints(cls) -> dict[str, Any]:
        hints = Model._hints_cache.get(cls)
        if hints is None:
            hints = get_type_hints(cls)
            Model._hints_cache[cls] = hints
        return hints

    def to_dict(self) -> dict[str, Any]:
        return {f.name: _encode(getattr(self, f.name)) for f in dataclasses.fields(self)}  # type: ignore[arg-type]

    @classmethod
    def from_dict(cls: type[T], data: dict[str, Any]) -> T:
        hints = cls._hints()
        kwargs: dict[str, Any] = {}
        for f in dataclasses.fields(cls):  # type: ignore[arg-type]
            if f.name in data:
                kwargs[f.name] = _decode(data[f.name], hints.get(f.name, Any))
        return cls(**kwargs)

    def replace(self: T, **changes: Any) -> T:
        return dataclasses.replace(self, **changes)  # type: ignore[type-var]


def env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")
