# SPDX-License-Identifier: Apache-2.0
"""Shape checks of plan change targets and bodies: a malformed request is a 400, never a 409 or 500."""

from __future__ import annotations

import re
from typing import Any

import dns.exception
import dns.name
import dns.rdatatype

from pelagos.connectors.base import ConnectorError
from pelagos.connectors.kea import config as kcfg
from pelagos.domain import Family, ReservationIdType
from pelagos.services.errors import ValidationError, field_error

MAX_TTL = 2**31 - 1
# Same label rule as the record editor (frontend pages/dns/records.js): LDH plus underscore.
_LABEL = re.compile(r"^(?:\*|[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)$", re.IGNORECASE)
# RFC 952/1123 host names: BIND check-names (default fail on primary zones) applies them to the owners
# of A, AAAA and MX (BIND 9.20 ARM, check-names, read 2026-10-30).
_HOST_LABEL = re.compile(r"^(?:\*|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$", re.IGNORECASE)
HOSTNAME_OWNER_TYPES = frozenset({"A", "AAAA", "MX"})

# Documented forms, also the OpenAPI examples (api.models).
DHCP_TARGETS: dict[str, str] = {
    "subnet": "subnet4/<id> or subnet4/new (subnet6 on /dhcp/v6)",
    "reservation": "subnet4/<id>/reservations/<id-type>=<identifier> or global/reservations/hw-address=<mac>",
    "shared_network": "shared-networks/<name>",
    "class": "client-classes/<name>",
    "options": "option-data/dhcp4/<name or code>, or a global key such as valid-lifetime",
}
_KIND_OF_TARGET = {
    "subnet": "subnet",
    "reservation": "reservation",
    "shared_network": "shared_network",
    "class": "client_class",
}


def _invalid(field: str, detail: str, message: str) -> ValidationError:
    return ValidationError(detail, [field_error(field, message)])


def check_dhcp_target(kind: str, target: str, family: Family, field: str) -> None:
    """The target parses as the endpoint's object, in the endpoint's family."""
    try:
        t = kcfg.parse_target(target)
    except ConnectorError:
        raise _invalid(
            field, f"{field} {target!r} is not a valid target: {DHCP_TARGETS.get(kind, '')}", "bad format"
        ) from None
    want = _KIND_OF_TARGET.get(kind)
    if kind == "options":
        if t.kind not in ("option", "key"):
            raise _invalid(field, f"{field} {target!r}: expected {DHCP_TARGETS['options']}", "bad format")
        return
    if want is None:
        return
    n = "4" if family is Family.V4 else "6"
    wrong_family = target.startswith("subnet") and not target.startswith(f"subnet{n}/")
    if t.kind != want or wrong_family:
        raise _invalid(field, f"{field} {target!r}: expected {DHCP_TARGETS[kind]}", "bad format")
    id_type = (t.reservation_key or "").partition("=")[0]
    if want == "reservation" and id_type not in {v.value for v in ReservationIdType}:
        known = ", ".join(v.value for v in ReservationIdType)
        detail = f"{field} {target!r}: identifier type {id_type} is not one of {known}"
        raise _invalid(field, detail, "bad type")


def model_error(exc: Exception, field: str) -> ValidationError:
    """A domain object that cannot be built from the request: the fields at fault, as a 400."""
    text = str(exc)
    missing = re.findall(r"'(\w+)'", text) if "required" in text else []
    if missing:
        errors = [field_error(f"{field}.{name}", "required") for name in missing]
        return ValidationError(f"{field} is missing {', '.join(missing)}", errors)
    return ValidationError(f"{field} is invalid: {text}", [field_error(field, text)])


def _absolute(owner: str, zone: str) -> str:
    if owner in ("", "@"):
        return zone
    if owner.endswith("."):
        return owner
    return f"{owner}.{zone}" if zone != "." else f"{owner}."


def check_record_owner(owner: str, zone: str, rtype: str, op: str, field: str) -> None:
    """Owner and type of a record target, with the editor's rules. A delete only needs a name
    in the zone, so a badly named record already there can still be removed."""
    try:
        dns.rdatatype.from_text(rtype)
    except dns.exception.DNSException:
        raise _invalid(field, f"{field}: unknown record type {rtype}", "unknown type") from None
    o = owner.strip()
    if not o.isascii():
        try:
            hint = f": use its IDNA form {o.encode('idna').decode()}"
        except UnicodeError:
            hint = ""
        raise _invalid(field, f"{field}: owner {o!r} is not ASCII{hint}", "not ASCII")
    try:
        name = dns.name.from_text(_absolute(o.lower(), zone))
        origin = dns.name.from_text(zone)
    except dns.exception.DNSException as exc:
        raise _invalid(field, f"{field}: invalid owner {o!r}: {exc}", "invalid name") from None
    if not name.is_subdomain(origin):
        raise _invalid(field, f"{field}: {name} is outside zone {zone}", "outside zone")
    if op == "delete":
        return
    rule = _HOST_LABEL if rtype in HOSTNAME_OWNER_TYPES else _LABEL
    labels = name.relativize(origin).labels if name != origin else ()
    for i, raw in enumerate(labels):
        label = raw.decode("ascii", "replace")
        if not rule.match(label) or (label == "*" and i != 0):
            what = "host name (letters, digits, hyphens)" if rule is _HOST_LABEL else "name"
            raise _invalid(field, f"{field}: owner {o!r} is not a valid {rtype} {what}", "invalid name")


def check_ttl(after: Any, field: str) -> None:
    if not isinstance(after, dict) or after.get("ttl") is None:
        return
    ttl = after["ttl"]
    if isinstance(ttl, str) and ttl.strip().isdigit():
        ttl = int(ttl)
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 0 <= ttl <= MAX_TTL:
        raise _invalid(f"{field}.ttl", f"{field}.ttl must be an integer from 0 to {MAX_TTL}", "out of range")
