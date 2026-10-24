# SPDX-License-Identifier: Apache-2.0
"""rndc operations carried by a plan: zone operations run on a peer through /repl/v1/plans/apply,
and the DNSSEC key operations (rollover, checkds) previewed and confirmed like any plan.

Target `op:<name>/<view>/<zone>`; `after` holds the few typed arguments. The rndc arguments are
always built here from an allowlist, never taken from the plan.
"""

from __future__ import annotations

import re
from typing import Any

from pelagos.connectors.bind.rndc import zone_args
from pelagos.domain.dns import normalize_name
from pelagos.domain.plan import Change

PREFIX = "op:"
ZONE_OPS = ("retransfer", "notify", "reload", "freeze", "thaw", "sync")
DNSSEC_OPS = ("dnssec-rollover", "dnssec-checkds")
CHECKDS_STATES = ("published", "withdrawn")
_WHEN = re.compile(r"^(now|\d{14})$")
DEFAULT_VIEW = "_default"


class OpError(ValueError):
    """An operation or argument outside the allowlist."""


def is_op(change: Change) -> bool:
    return change.target.startswith(PREFIX)


def target(name: str, zone: str, view: str | None) -> str:
    return f"{PREFIX}{name}/{view or DEFAULT_VIEW}/{normalize_name(zone)}"


def parse_target(text: str) -> tuple[str, str | None, str]:
    """(op, view or None for the default view, zone)."""
    if not text.startswith(PREFIX):
        raise OpError(f"{text!r} is not an operation target")
    parts = text[len(PREFIX) :].split("/")
    if len(parts) != 3 or not all(parts):
        raise OpError(f"{text!r} is not op:<name>/<view>/<zone>")
    name, view, zone = parts
    if name not in ZONE_OPS + DNSSEC_OPS:
        raise OpError(f"unknown operation {name}")
    return name, None if view == DEFAULT_VIEW else view, normalize_name(zone)


def check_args(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Typed and bounded arguments; anything else is refused."""
    out: dict[str, Any] = {}
    allowed = {
        "sync": {"clean"},
        "dnssec-rollover": {"key_id", "when"},
        "dnssec-checkds": {"key_id", "when", "state"},
    }
    extra = set(args) - allowed.get(name, set())
    if extra:
        raise OpError(f"{name} takes no {', '.join(sorted(extra))}")
    if "clean" in args:
        out["clean"] = bool(args["clean"])
    if args.get("key_id") is not None:
        try:
            key_id = int(args["key_id"])
        except (TypeError, ValueError) as exc:
            raise OpError("key_id must be an integer key tag") from exc
        if not 0 <= key_id <= 65535:
            raise OpError("key_id must be a key tag (0 to 65535)")
        out["key_id"] = key_id
    if args.get("when"):
        when = str(args["when"])
        if not _WHEN.match(when):
            raise OpError("when must be `now` or YYYYMMDDHHMMSS")
        out["when"] = when
    if name == "dnssec-rollover" and "key_id" not in out:
        raise OpError("dnssec-rollover needs key_id")
    if name == "dnssec-checkds":
        state = args.get("state")
        if state not in CHECKDS_STATES:
            raise OpError("state must be published or withdrawn")
        out["state"] = state
    return out


def rndc_args(name: str, zone: str, view: str | None, args: dict[str, Any]) -> list[str]:
    args = check_args(name, args)
    where = zone_args(zone, view)
    if name == "sync":
        return ["sync", *(["-clean"] if args.get("clean") else []), *where]
    if name == "dnssec-rollover":
        when = ["-when", args["when"]] if args.get("when") else []
        return ["dnssec", "-rollover", "-key", str(args["key_id"]), *when, *where]
    if name == "dnssec-checkds":
        key = ["-key", str(args["key_id"])] if "key_id" in args else []
        when = ["-when", args["when"]] if args.get("when") else []
        return ["dnssec", "-checkds", *key, *when, args["state"], *where]
    return [name, *where]


def command_text(name: str, zone: str, view: str | None, args: dict[str, Any]) -> str:
    return "rndc " + " ".join(rndc_args(name, zone, view, args))
