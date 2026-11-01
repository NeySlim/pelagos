# SPDX-License-Identifier: Apache-2.0
"""Desired state verbs (section 17): compare what an engine holds with what a PUT or DELETE asks for,
and turn the difference into the changes of an existing plan builder. Nothing here writes to an
engine: the caller applies the plan through PlanService.apply."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pelagos.connectors.bind.rrset import RRsetError, normalize_rdata
from pelagos.connectors.kea import config as kcfg
from pelagos.domain import ClientClass, Family, OptionData, Plan, Reservation, RRset, Subnet, Zone
from pelagos.domain.dns import normalize_name, slash_in_zone_name
from pelagos.services.errors import NotFound, ValidationError, field_error
from pelagos.services.plan_targets import check_dhcp_target, check_record_owner, check_ttl, model_error

# Fields a body never sets: the path names the object, the engine computes the rest.
_ZONE_FIXED = frozenset({"name", "view", "role", "source", "config_path", "extra"})
_RESERVATION_FIXED = frozenset({"id_type", "identifier", "raw"})
_RRSET_KEYS = frozenset({"ttl", "records", "ptr", "view", "confirm"})
# Octets separated by ":", "-" or spaces, or plain hex (optionally 0x): what Kea reads for these types.
_HEX_ID = re.compile(r"^(?:0x)?(?:[0-9a-f]{1,2}(?:[:\- ][0-9a-f]{1,2})+|[0-9a-f]{2,})$", re.IGNORECASE)
_WHOLE_OBJECT: dict[str, type] = {"class": ClientClass, "options": OptionData}


@dataclass(slots=True)
class Convergence:
    """What a desired state verb found: the object now (None when absent), its ETag, and the plan
    builder to call when it differs (None: already converged)."""

    current: dict[str, Any] | None
    etag: str | None
    build: Callable[[], Plan] | None = None


def etag_of(value: Any) -> str:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode()).hexdigest()[:20]


def without_raw(value: Any) -> Any:
    """Engine passthrough (`raw`) is never compared: the body speaks domain fields only."""
    if isinstance(value, dict):
        return {k: without_raw(v) for k, v in value.items() if k != "raw"}
    if isinstance(value, list):
        return [without_raw(v) for v in value]
    return value


def covers(current: Any, desired: Any) -> bool:
    """True when `current` already holds `desired`: every key the body gives has the same value;
    a list is compared item by item (same length, same order); keys the body omits are left as is."""
    if isinstance(desired, dict):
        if not isinstance(current, dict):
            return False
        return all(covers(current.get(k), v) for k, v in desired.items())
    if isinstance(desired, list):
        if not isinstance(current, list) or len(current) != len(desired):
            return False
        return all(covers(c, d) for c, d in zip(current, desired, strict=True))
    if desired is None:
        return current in (None, [], {}, "")
    return bool(current == desired)


def check_fields(body: dict[str, Any], model: type, fixed: frozenset[str], where: str = "body") -> None:
    """Unknown keys are refused: a key the domain does not model would never converge."""
    known = {f.name for f in dataclasses.fields(model)} - fixed
    unknown = sorted(k for k in body if k not in known)
    if unknown:
        raise ValidationError(
            f"{where} has fields the object does not take: {', '.join(unknown)}",
            [field_error(f"{where}.{k}", "unknown field") for k in unknown],
        )


def _invalid(field: str, detail: str, message: str) -> ValidationError:
    return ValidationError(detail, [field_error(field, message)])


def check_zone_path(name: str) -> None:
    """`/dns/zones/<path:zone>` also matches the sub-routes (`.../records`, `.../dnssec`): a "/" in a
    zone name other than the RFC 2317 form is a path to another endpoint, never a zone."""
    if slash_in_zone_name(name):
        raise _invalid("zone", f"{name!r} is not a zone name", "not a zone name")


def _absolute(owner: str, zone: str) -> str:
    owner = owner.strip().lower()
    if owner in ("", "@"):
        return zone
    if owner.endswith("."):
        return owner
    return f"{owner}.{zone}" if zone != "." else f"{owner}."


def _soa_serial(rrsets: list[RRset], zone: str) -> str | None:
    soa = next((r for r in rrsets if r.rtype == "SOA" and normalize_name(r.name) == zone), None)
    if soa is None or not soa.rdata:
        return None
    parts = soa.rdata[0].split()
    return parts[2] if len(parts) > 2 else None


def _same_rdata(rtype: str, current: list[str], desired: list[str], zone: str) -> bool:
    try:
        return normalize_rdata(rtype, current, zone) == normalize_rdata(rtype, desired, zone)
    except RRsetError:
        return False  # records/plan refuses the bad rdata (400 validation_error)


class DesiredStateService:
    """`dns` is the DnsService, `dhcp` maps a Family to its DhcpService."""

    def __init__(self, dns: Any, dhcp: Callable[[Family], Any]) -> None:
        self.dns = dns
        self.dhcp = dhcp

    # DNS RRsets ---------------------------------------------------------

    def rrset(self, zone: str, owner: str, rtype: str, view: str | None) -> Convergence:
        """The RRset now and the zone's SOA serial as its ETag."""
        check_zone_path(zone)
        zone = normalize_name(zone)
        rtype = rtype.strip().upper()
        check_record_owner(owner, zone, rtype, "delete", "owner")
        name = normalize_name(_absolute(owner, zone))
        rrsets, _node = self.dns.records(zone, view)
        found = next((r for r in rrsets if normalize_name(r.name) == name and r.rtype.upper() == rtype), None)
        return Convergence(found.to_dict() if found else None, _soa_serial(rrsets, zone))

    def converge_rrset(
        self,
        zone: str,
        owner: str,
        rtype: str,
        body: dict[str, Any] | None,
        view: str | None,
        user: str,
    ) -> Convergence:
        """`body` None deletes; otherwise {"ttl"?, "records": [rdata...], "ptr"?}."""
        zone = normalize_name(zone)
        rtype = rtype.strip().upper()
        op = "delete" if body is None else "replace"
        check_record_owner(owner, zone, rtype, op, "owner")
        ptr = None
        if body is not None:
            unknown = sorted(k for k in body if k not in _RRSET_KEYS)
            if unknown:
                raise ValidationError(
                    f"body has fields an RRset does not take: {', '.join(unknown)}",
                    [field_error(f"body.{k}", "unknown field") for k in unknown],
                )
            records = body.get("records")
            if not isinstance(records, list) or not records or not all(isinstance(r, str) for r in records):
                raise ValidationError(
                    "records must be a non-empty list of rdata strings (DELETE removes the RRset)",
                    [field_error("records", "non-empty list of strings")],
                )
            check_ttl(body, "body")
            ptr = body.get("ptr")
            if ptr is not None and not isinstance(ptr, dict):
                raise ValidationError("ptr must be an object", [field_error("ptr", "object")])
        conv = self.rrset(zone, owner, rtype, view)
        current = conv.current
        target = f"{owner.strip() or '@'}/{rtype}"
        if body is None:
            if current is None:
                return conv
            change: dict[str, Any] = {"op": "delete", "target": target, "before": current}
        else:
            ttl = body.get("ttl")
            ttl = int(ttl) if ttl is not None else None
            if current is not None:
                same_ttl = ttl is None or ttl == int(current["ttl"])
                if same_ttl and _same_rdata(rtype, current["rdata"], body["records"], zone):
                    return conv
            after: dict[str, Any] = {"rdata": list(body["records"])}
            if ttl is not None:
                after["ttl"] = ttl
            elif current is not None:
                after["ttl"] = current["ttl"]
            change = {"op": "add" if current is None else "replace", "target": target, "after": after}
            if current is not None:
                change["before"] = current
        conv.build = lambda: self.dns.plan_records(zone, [change], view, user, ptr)
        return conv

    # DNS zones ----------------------------------------------------------

    def zone(self, name: str, view: str | None) -> Convergence:
        try:
            zone, _statuses = self.dns.zone(name, view)
        except NotFound:
            return Convergence(None, None)
        current = zone.to_dict()
        return Convergence(current, etag_of(current))

    def converge_zone(
        self, name: str, body: dict[str, Any] | None, view: str | None, user: str
    ) -> Convergence:
        """`body` None deletes the zone declaration; otherwise the Zone fields wanted."""
        check_zone_path(name)
        name = normalize_name(name)
        if body is not None:
            check_fields(body, Zone, _ZONE_FIXED)
        conv = self.zone(name, view)
        current = conv.current
        where = (current or {}).get("view") or view or "_default"
        target = f"{where}/{name}"
        if body is None:
            if current is None:
                return conv
            change: dict[str, Any] = {"op": "delete", "target": target, "before": current}
        elif current is None:
            if not body.get("kind"):
                raise _invalid("body.kind", "kind is required to declare a zone", "required")
            change = {"op": "add", "target": target, "after": {**body, "name": name, "view": where}}
        else:
            if covers(without_raw(current), body):
                return conv
            change = {"op": "replace", "target": target, "before": current, "after": {**current, **body}}
        conv.build = lambda: self.dns.plan_zone(change, user)
        return conv

    # DHCP -----------------------------------------------------------------

    def _kea_etag(self, family: Family) -> str | None:
        try:
            return self.dhcp(family).config(None).get("hash")
        except Exception:
            return None

    def _converge_kea(
        self,
        family: Family,
        kind: str,
        target: str,
        current: dict[str, Any] | None,
        body: dict[str, Any] | None,
        add_after: Callable[[], dict[str, Any]],
        user: str,
    ) -> Convergence:
        conv = Convergence(current, self._kea_etag(family))
        if body is None:
            if current is None:
                return conv
            change: dict[str, Any] = {"op": "delete", "target": target, "before": current}
        elif current is None:
            change = {"op": "add", "target": target, "after": add_after()}
        else:
            if covers(without_raw(current), body):
                return conv
            # Subnet and reservation builders complete a partial object over the current one themselves.
            base = (
                {} if kind in ("subnet", "reservation") else {k: v for k, v in current.items() if k != "raw"}
            )
            change = {"op": "replace", "target": target, "before": current, "after": {**base, **body}}
        model = _WHOLE_OBJECT.get(kind)
        if model is not None and isinstance(change.get("after"), dict):
            # These builders take a whole domain object: snake_case keys tell it from a Kea one.
            try:
                change["after"] = model.from_dict(change["after"]).to_dict()
            except (TypeError, ValueError, KeyError) as exc:
                raise model_error(exc, "body") from None
        svc = self.dhcp(family)
        plan_body = {"changes": [change]} if kind == "options" else {"change": change}
        conv.build = lambda: svc.plan(kind, plan_body, user)
        return conv

    def reservation(
        self, family: Family, key: str, subnet_id: int | None, node_id: str | None = None
    ) -> Convergence:
        id_type, identifier = self._reservation_key(family, key, subnet_id)
        found = None
        for r in self.dhcp(family).reservations(subnet_id, None, node_id):
            if r.id_type.value != id_type:
                continue
            if kcfg.normalize_identifier(r.identifier) != kcfg.normalize_identifier(identifier):
                continue
            if subnet_id is None and r.subnet_id not in (None, 0):
                continue
            if subnet_id is not None and r.subnet_id != subnet_id:
                continue
            found = r
            break
        return Convergence(found.to_dict() if found else None, self._kea_etag(family))

    def _reservation_key(self, family: Family, key: str, subnet_id: int | None) -> tuple[str, str]:
        id_type, sep, identifier = key.partition("=")
        if not sep or not identifier:
            raise ValidationError(
                f"reservation key {key!r} is not <id_type>=<identifier>", [field_error("key", "bad format")]
            )
        check_dhcp_target("reservation", self._reservation_target(family, key, subnet_id), family, "key")
        if id_type in ("hw-address", "duid") and not _HEX_ID.match(identifier.strip()):
            raise _invalid("key", f"{id_type} {identifier!r} is not hexadecimal octets", "bad identifier")
        return id_type, identifier

    @staticmethod
    def _reservation_target(family: Family, key: str, subnet_id: int | None) -> str:
        scope = "global" if subnet_id is None else f"subnet{'4' if family is Family.V4 else '6'}/{subnet_id}"
        return f"{scope}/reservations/{key}"

    def converge_reservation(
        self, family: Family, key: str, body: dict[str, Any] | None, subnet_id: int | None, user: str
    ) -> Convergence:
        """`subnet_id` comes from the body on PUT (absent: a global reservation), the query on DELETE."""
        if body is not None:
            check_fields(body, Reservation, _RESERVATION_FIXED)
            raw_sid = body.get("subnet_id")
            if raw_sid is not None and (isinstance(raw_sid, bool) or not isinstance(raw_sid, int)):
                raise _invalid("body.subnet_id", "subnet_id must be an integer", "integer")
            subnet_id = raw_sid
        id_type, identifier = self._reservation_key(family, key, subnet_id)
        found = self.reservation(family, key, subnet_id).current
        identifier = found["identifier"] if found else _canonical_identifier(id_type, identifier)
        target = self._reservation_target(family, f"{id_type}={identifier}", subnet_id)
        if body is not None:
            body = {**body, "subnet_id": subnet_id}

        def add_after() -> dict[str, Any]:
            return {**(body or {}), "id_type": id_type, "identifier": identifier}

        return self._converge_kea(family, "reservation", target, found, body, add_after, user)

    def converge_subnet(
        self, family: Family, subnet_id: int, body: dict[str, Any] | None, user: str
    ) -> Convergence:
        if body is not None:
            check_fields(body, Subnet, frozenset({"family", "raw"}))
            if body.get("id") not in (None, subnet_id):
                raise _invalid("body.id", "id must match the path", "must match the path")
            body = {**body, "id": subnet_id}
        try:
            current: dict[str, Any] | None = self.dhcp(family).subnet(subnet_id).to_dict()
        except NotFound:
            current = None
        target = f"subnet{'4' if family is Family.V4 else '6'}/{subnet_id}"
        return self._converge_kea(family, "subnet", target, current, body, lambda: dict(body or {}), user)

    def subnet(self, family: Family, subnet_id: int) -> Convergence:
        try:
            current: dict[str, Any] | None = self.dhcp(family).subnet(subnet_id).to_dict()
        except NotFound:
            current = None
        return Convergence(current, self._kea_etag(family))

    def client_class(self, family: Family, name: str, node_id: str | None = None) -> Convergence:
        found = next((c for c in self.dhcp(family).client_classes(node_id) if c.name == name), None)
        return Convergence(found.to_dict() if found else None, self._kea_etag(family))

    def converge_client_class(
        self, family: Family, name: str, body: dict[str, Any] | None, user: str
    ) -> Convergence:
        if body is not None:
            check_fields(body, ClientClass, frozenset({"name", "raw"}))
        current = self.client_class(family, name).current
        return self._converge_kea(
            family,
            "class",
            f"client-classes/{name}",
            current,
            body,
            lambda: {**(body or {}), "name": name},
            user,
        )

    def option(self, family: Family, space: str, code: str, node_id: str | None = None) -> Convergence:
        check_dhcp_target("options", f"option-data/{space}/{code}", family, "code")
        options, _defs = self.dhcp(family).options(node_id)
        found = next((o for o in options if _option_matches(o, space, code)), None)
        return Convergence(found.to_dict() if found else None, self._kea_etag(family))

    def converge_option(
        self, family: Family, space: str, code: str, body: dict[str, Any] | None, user: str
    ) -> Convergence:
        if body is not None:
            check_fields(body, OptionData, frozenset({"space", "raw"}))
            given = body.get("code") if code.isdigit() else body.get("name")
            if given is not None and str(given) != code:
                field = "code" if code.isdigit() else "name"
                raise ValidationError(
                    f"{field} must match the path", [field_error(f"body.{field}", "must match the path")]
                )
        current = self.option(family, space, code).current

        def add_after() -> dict[str, Any]:
            named = {"code": int(code)} if code.isdigit() else {"name": code}
            return {**(body or {}), **named, "space": space}

        return self._converge_kea(
            family, "options", f"option-data/{space}/{code}", current, body, add_after, user
        )


def _canonical_identifier(id_type: str, identifier: str) -> str:
    """hw-address and duid as Kea prints them (`aa:bb:..`); other types as given."""
    if id_type not in ("hw-address", "duid"):
        return identifier.strip()
    raw = kcfg.normalize_identifier(identifier)
    if any(c not in "0123456789abcdef" for c in raw):
        return identifier.strip()
    return ":".join(raw[i : i + 2] for i in range(0, len(raw), 2))


def _option_matches(option: OptionData, space: str, code: str) -> bool:
    if option.space != space:
        return False
    return str(option.code) == code if code.isdigit() else option.name == code
