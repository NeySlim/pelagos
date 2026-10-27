# SPDX-License-Identifier: Apache-2.0
"""In-memory DnsBackend, DhcpBackend and DdnsBackend implementing the section 5 contracts.

They behave like the real connectors as seen from the services: plans carry
before/after, diff, preconditions and validations; apply re-checks the
preconditions and mutates the in-memory state; rollback applies the inverse.
Failure injection: set `backend.failure = ConnectorUnavailable("down")` and
every call raises it. WP-COLLECTOR may reuse them (contracts-changes.md).
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import secrets
import tempfile
from pathlib import Path
from typing import Any

from pelagos.connectors.base import (
    ConnectorContext,
    ConnectorError,
    DdnsBackend,
    DhcpBackend,
    DnsBackend,
    PreconditionFailed,
    ValidationFailed,
)
from pelagos.domain import (
    BindConfigTree,
    BindInstanceStats,
    Change,
    ChangeOp,
    ClientClass,
    ConfigEntry,
    D2Stats,
    DhcpCapabilities,
    DnsCapabilities,
    Engine,
    Family,
    HAMode,
    HAPartner,
    HAState,
    Lease,
    LeaseState,
    NodeApplyResult,
    OptionData,
    PdPool,
    Plan,
    PlanScope,
    PlanState,
    Pool,
    Precondition,
    PreconditionKind,
    Reservation,
    ReservationIdType,
    RRset,
    SharedNetwork,
    Subnet,
    ValidationResult,
    Zone,
    ZoneKind,
    ZoneSource,
    ZoneStatus,
    normalize_name,
    to_rfc3339,
    utcnow,
)

NODE_A = "01JB0ZK4Q9X3M5N7P8R2T4V6W8"


def fake_context(
    node_id: str = NODE_A, engine: str = "bind", backup_root: Path | None = None
) -> ConnectorContext:
    root = backup_root or Path(tempfile.mkdtemp(prefix="plg-fake-")) / engine
    return ConnectorContext(
        node_id=node_id,
        engine_config={},
        backup_root=root,
        get_secret=lambda name: None,
        settings={"dns": {"read_key": "ddi-read", "admin_key": "ddi-admin"}},
    )


def _validated(plan: Plan, tool: str, ok: bool = True, output: str = "") -> Plan:
    plan.validations.append(ValidationResult(ok=ok, tool=tool, output=output, node_id=plan.node_id))
    plan.state = PlanState.VALIDATED if ok else PlanState.FAILED
    if not ok:
        plan.error = output
    return plan


def _diff(before: Any, after: Any, label: str) -> str:
    lines = [f"--- {label}", f"+++ {label}"]
    for line in _lines(before):
        lines.append("-" + line)
    for line in _lines(after):
        lines.append("+" + line)
    return "\n".join(lines) + "\n"


def _lines(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return value.splitlines()
    return json.dumps(value, indent=1, sort_keys=True).splitlines()


# DNS -------------------------------------------------------------------------


class FakeDnsBackend(DnsBackend):
    def __init__(self, ctx: ConnectorContext | None = None, node_id: str = NODE_A, seed: bool = True) -> None:
        super().__init__(ctx or fake_context(node_id, "bind"))
        self.node_id = self.ctx.node_id
        self.failure: ConnectorError | None = None
        self.running = True
        self.version = "9.20.30"
        self.zones: dict[str, Zone] = {}
        self.rrsets: dict[str, dict[tuple[str, str], RRset]] = {}
        self.serials: dict[str, int] = {}
        self.keys: dict[str, tuple[str, str]] = {}
        self.acls: dict[str, list[str]] = {}
        self.options: dict[str, str] = {}
        self.ops: list[tuple[str, ...]] = []
        self.applied: list[str] = []
        self.rolled_back: list[str] = []
        self.details: dict[str, dict[str, Any]] = {}
        self.catalog: list[str] = ["member1.example.lan."]
        self.policies: dict[str, list[dict[str, str]]] = {}
        self.rpz_state: dict[str, Any] = {}
        self.rpz_ram: int | None = 8192
        self.dns: Any = None
        if seed:
            self.seed()

    def seed(self) -> None:
        self.add_zone(
            Zone(
                name="example.lan.",
                kind=ZoneKind.PRIMARY,
                file="pelagos/example.lan.db",
                dynamic=True,
                update_policy=["grant ddi-admin zonesub ANY", "grant kea-ddns zonesub A AAAA PTR DHCID"],
                allow_transfer=["key ddi-read"],
                source=ZoneSource.PELAGOS,
                config_path="/etc/bind/pelagos/zones.conf",
            ),
            [
                RRset(
                    "example.lan.",
                    "SOA",
                    3600,
                    ["ns1.example.lan. hostmaster.example.lan. 2026102401 3600 900 1209600 300"],
                ),
                RRset("example.lan.", "NS", 3600, ["ns1.example.lan.", "ns2.example.lan."]),
                RRset("ns1.example.lan.", "A", 3600, ["192.0.2.1"]),
                RRset("ns2.example.lan.", "A", 3600, ["192.0.2.2"]),
                RRset("www.example.lan.", "A", 300, ["192.0.2.10"]),
                RRset("pc1.example.lan.", "A", 300, ["192.0.2.100"]),
                RRset("pc1.example.lan.", "DHCID", 300, ["AAEBOSD+XR3Os/0LozeXVqcNc7FwCfQdWL3b/NaiUDlW2No="]),
                RRset("www.example.lan.", "AAAA", 300, ["2001:db8::10"]),
            ],
            serial=2026102401,
        )
        self.add_zone(
            Zone(
                name="2.0.192.in-addr.arpa.",
                kind=ZoneKind.PRIMARY,
                file="pelagos/2.0.192.in-addr.arpa.db",
                dynamic=True,
                update_policy=["grant ddi-admin zonesub ANY"],
                source=ZoneSource.PELAGOS,
                config_path="/etc/bind/pelagos/zones.conf",
            ),
            [
                RRset(
                    "2.0.192.in-addr.arpa.",
                    "SOA",
                    3600,
                    ["ns1.example.lan. hostmaster.example.lan. 2026102401 3600 900 1209600 300"],
                ),
                RRset("2.0.192.in-addr.arpa.", "NS", 3600, ["ns1.example.lan."]),
                RRset("10.2.0.192.in-addr.arpa.", "PTR", 300, ["www.example.lan."]),
                RRset("100.2.0.192.in-addr.arpa.", "PTR", 300, ["pc1.example.lan."]),
            ],
            serial=2026102401,
        )
        self.add_zone(
            Zone(
                name="corp.example.",
                kind=ZoneKind.SECONDARY,
                primaries=["192.0.2.50"],
                config_path="/etc/bind/named.conf.local",
            ),
            [
                RRset(
                    "corp.example.",
                    "SOA",
                    3600,
                    ["ns.corp.example. root.corp.example. 7 3600 900 1209600 300"],
                )
            ],
            serial=7,
        )
        self.add_zone(
            Zone(
                name="rpz.example.lan.",
                kind=ZoneKind.PRIMARY,
                file="rpz.db",
                config_path="/etc/bind/named.conf.local",
            ),
            [
                RRset(
                    "rpz.example.lan.",
                    "SOA",
                    3600,
                    ["ns1.example.lan. hostmaster.example.lan. 1 3600 900 1209600 300"],
                )
            ],
            serial=1,
        )
        self.keys = {
            "ddi-read": ("hmac-sha256", "cmVhZC1zZWNyZXQ="),
            "ddi-admin": ("hmac-sha256", "YWRtaW4tc2VjcmV0"),
            "kea-ddns": ("hmac-sha256", "a2VhLXNlY3JldA=="),
            "legacy": ("hmac-md5", "bGVnYWN5"),
        }
        self.acls = {"trusted": ["192.0.2.0/24", "2001:db8::/64"], "secondaries": ["192.0.2.2"]}
        self.options = {
            "recursion": "no",
            "allow-recursion": "{ trusted; }",
            "forwarders": "{ 192.0.2.53; }",
            "forward": "only",
            "dnssec-validation": "auto",
            "response-policy": '{ zone "rpz.example.lan"; }',
            "catalog-zones": '{ zone "catalog.example.lan" default-primaries { 192.0.2.1; }; }',
        }

    # Helpers ------------------------------------------------------------

    def add_zone(self, zone: Zone, rrsets: list[RRset], serial: int = 1) -> None:
        self.zones[zone.name] = zone
        self.rrsets[zone.name] = {(normalize_name(r.name), r.rtype.upper()): r for r in rrsets}
        self.serials[zone.name] = serial

    def _check(self) -> None:
        if self.failure is not None:
            raise self.failure

    def _zone(self, zone: str) -> Zone:
        name = normalize_name(zone)
        if name not in self.zones:
            raise ConnectorError(f"zone {name} is not configured")
        return self.zones[name]

    def _owner(self, zone: str, owner: str) -> str:
        zone = normalize_name(zone)
        if owner in ("@", ""):
            return zone
        if owner.endswith("."):
            return normalize_name(owner)
        return normalize_name(f"{owner}.{zone}")

    # Observation --------------------------------------------------------

    def capabilities(self) -> DnsCapabilities:
        self._check()
        return DnsCapabilities(
            version=self.version,
            running=self.running,
            rndc=self.running,
            statistics_channel=self.running,
            views=["_default"],
            tsig_read_key="ddi-read",
            tsig_admin_key="ddi-admin",
            dnssec=True,
            catalog_zones=True,
        )

    def server_status(self) -> dict[str, str]:
        self._check()
        return {
            "version": f"BIND {self.version}",
            "running on": "ns1",
            "number of zones": str(len(self.zones)),
            "server is up and running": "",
        }

    def config_files_tree(self) -> dict[str, Any]:
        """The shape of namedconf.files_tree(): statements with args, line, value or statements."""
        self._check()

        def st(name: str, args: list[str], line: int, children: list | None = None) -> dict[str, Any]:
            out: dict[str, Any] = {"name": name, "args": args, "line": line, "include": name == "include"}
            if children is None:
                out["value"] = " ".join(args)
            else:
                out["statements"] = children
            return out

        options = [st(k, [v], i + 2) for i, (k, v) in enumerate(self.options.items())]
        keys = [
            st("key", [f'"{name}"'], 2 + i, [st("algorithm", [algo], 3 + i), st("secret", ["****"], 4 + i)])
            for i, (name, (algo, _secret)) in enumerate(self.keys.items())
        ]
        return {
            "files": [
                {
                    "path": "/etc/bind/named.conf",
                    "managed": False,
                    "statements": [
                        st("options", [], 1, options),
                        st("include", ['"/etc/bind/pelagos/pelagos.conf"'], 20),
                    ],
                },
                {"path": "/etc/bind/pelagos/keys.conf", "managed": True, "statements": keys},
            ],
            "missing": [],
            "errors": [],
        }

    def read_config(self) -> BindConfigTree:
        self._check()
        user = "/etc/bind/named.conf"
        managed = "/etc/bind/pelagos/"
        return BindConfigTree(
            node_id=self.node_id,
            user_conf=user,
            includes=[
                user,
                "/etc/bind/named.conf.options",
                "/etc/bind/named.conf.local",
                managed + "pelagos.conf",
            ],
            options=[
                ConfigEntry(k, v, path="/etc/bind/named.conf.options", line=i + 1)
                for i, (k, v) in enumerate(self.options.items())
            ],
            keys=[
                ConfigEntry(
                    name,
                    algo,
                    path=(managed + "keys.conf" if name.startswith("ddi-") else user),
                    line=1,
                    managed=name.startswith("ddi-"),
                )
                for name, (algo, _secret) in self.keys.items()
            ],
            acls=[
                ConfigEntry(
                    name, "{ " + "; ".join(elems) + "; }", path=managed + "acls.conf", line=1, managed=True
                )
                for name, elems in self.acls.items()
            ],
            controls=[
                ConfigEntry(
                    "controls",
                    'inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { "rndc-key"; }',
                    path=user,
                    line=5,
                )
            ],
            statistics_channels=[
                ConfigEntry(
                    "statistics-channels", "inet 127.0.0.1 port 8053 allow { 127.0.0.1; }", path=user, line=9
                )
            ],
            logging=None,
            views={"_default": list(self.zones.values())},
            zones=list(self.zones.values()),
            pelagos={
                "include_dir": managed,
                "top_include": True,
                "options_include": True,
                "files": ["pelagos.conf", "keys.conf", "acls.conf", "zones.conf", "options.conf"],
            },
        )

    def read_key_secret(self, name: str) -> str | None:
        """Optional extension used by GET /dns/keys/{name}/secret when the secret is not in cluster.toml."""
        self._check()
        entry = self.keys.get(name)
        return entry[1] if entry else None

    def list_zones(self, view: str | None = None) -> list[Zone]:
        self._check()
        return [z for z in self.zones.values() if view is None or z.view == view]

    def zone_status(self, zone: str, view: str | None = None) -> ZoneStatus:
        self._check()
        z = self._zone(zone)
        return ZoneStatus(
            zone=z.name,
            view=z.view,
            node_id=self.node_id,
            kind=z.kind,
            serial=self.serials[z.name],
            config_serial=self.serials[z.name],
            dynamic=z.dynamic,
            signed=False,
            files=[z.file] if z.file else [],
            raw={"name": z.name, "type": z.kind.value, "serial": str(self.serials[z.name])},
        )

    def soa_serial(self, zone: str, view: str | None = None) -> int | None:
        self._check()
        return self.serials.get(normalize_name(zone))

    def read_zone(self, zone: str, view: str | None = None) -> list[RRset]:
        self._check()
        z = self._zone(zone)
        return [copy.deepcopy(r) for r in self.rrsets[z.name].values()]

    def instance_stats(self) -> BindInstanceStats:
        self._check()
        return BindInstanceStats(
            node_id=self.node_id,
            version=self.version,
            opcodes={"QUERY": 1200},
            rcodes={"NOERROR": 1100, "NXDOMAIN": 100},
            qtypes={"A": 900, "AAAA": 200, "PTR": 100},
            nsstats={"Requestv4": 1200, "Response": 1200},
            zones={f"_default/{name}": {"serial": serial} for name, serial in self.serials.items()},
        )

    def dnssec_status(self, zone: str, view: str | None = None) -> dict[str, Any]:
        self._check()
        z = self._zone(zone)
        return {"zone": z.name, "policy": z.dnssec_policy, "signed": False, "keys": []}

    # Plans --------------------------------------------------------------

    def plan_rrset_changes(
        self, zone: str, changes: list[Change], view: str | None = None, created_by: str = ""
    ) -> Plan:
        self._check()
        z = self._zone(zone)
        plan = Plan(
            scope=PlanScope.DNS_RRSET,
            node_id=self.node_id,
            summary="",
            created_by=created_by,
            engine=Engine.BIND,
            target_node_ids=[self.node_id],
        )
        table = self.rrsets[z.name]
        diff = ""
        for change in changes:
            parts = change.target.split("/")
            if len(parts) != 3:
                return _validated(
                    plan, "dnspython", False, f"bad target {change.target}: expected <zone>/<owner>/<type>"
                )
            owner = self._owner(z.name, parts[1])
            rtype = parts[2].upper()
            current = table.get((owner, rtype))
            after = change.after
            if change.op in (ChangeOp.ADD, ChangeOp.REPLACE):
                if not isinstance(after, dict) or not after.get("rdata"):
                    return _validated(
                        plan, "dnspython", False, f"{change.target}: after.rdata must be a non-empty list"
                    )
                if int(after.get("ttl", 0)) < 0:
                    return _validated(plan, "dnspython", False, f"{change.target}: ttl must be >= 0")
                after = RRset(owner, rtype, int(after.get("ttl", 300)), list(after["rdata"])).to_dict()
            else:
                after = None
            if change.op is ChangeOp.ADD and current is not None:
                plan.preconditions.append(
                    Precondition(PreconditionKind.RRSET_ABSENT, f"{owner}/{rtype}", "absent", self.node_id)
                )
                return _validated(plan, "dnspython", False, f"{owner} {rtype} already exists")
            if change.op in (ChangeOp.REPLACE, ChangeOp.DELETE) and current is None:
                return _validated(plan, "dnspython", False, f"{owner} {rtype} does not exist")
            kind = (
                PreconditionKind.RRSET_ABSENT if change.op is ChangeOp.ADD else PreconditionKind.RRSET_EXISTS
            )
            plan.preconditions.append(
                Precondition(
                    kind, f"{owner}/{rtype}", "absent" if current is None else "exists", self.node_id
                )
            )
            before = current.to_dict() if current else None
            plan.changes.append(Change(change.op, f"{z.name}/{owner}/{rtype}", before=before, after=after))
            diff += _diff(before and _rr_text(before), after and _rr_text(after), f"{owner} {rtype}")
        plan.preconditions.append(
            Precondition(PreconditionKind.SOA_SERIAL, z.name, str(self.serials[z.name]), self.node_id)
        )
        plan.diff = diff
        plan.summary = f"{len(plan.changes)} record change(s) in {z.name}"
        return _validated(plan, "dnspython")

    def plan_zone_change(self, change: Change, created_by: str = "") -> Plan:
        self._check()
        plan = Plan(
            scope=PlanScope.DNS_ZONE,
            node_id=self.node_id,
            summary="",
            created_by=created_by,
            engine=Engine.BIND,
            target_node_ids=[self.node_id],
        )
        view, _, name = change.target.partition("/")
        if not name:
            return _validated(plan, "named-checkconf", False, "target must be <view>/<zone>")
        name = normalize_name(name)
        current = self.zones.get(name)
        if change.op is ChangeOp.ADD and current is not None:
            return _validated(plan, "named-checkconf", False, f"zone {name} already exists")
        if change.op is not ChangeOp.ADD and current is None:
            return _validated(plan, "named-checkconf", False, f"zone {name} does not exist")
        after = None
        if change.op is not ChangeOp.DELETE:
            try:
                after = Zone.from_dict(
                    {**(change.after or {}), "name": name, "view": view or "_default"}
                ).to_dict()
            except (TypeError, ValueError) as exc:
                return _validated(plan, "named-checkconf", False, f"invalid zone: {exc}")
        before = current.to_dict() if current else None
        plan.changes.append(Change(change.op, f"{view or '_default'}/{name}", before=before, after=after))
        plan.preconditions.append(
            Precondition(
                PreconditionKind.FILE_SHA256, "/etc/bind/pelagos/zones.conf", self._zones_hash(), self.node_id
            )
        )
        plan.diff = _diff(before, after, "zones.conf")
        plan.requires_confirmation = change.op is ChangeOp.DELETE
        plan.summary = f"{change.op.value} zone {name}"
        return _validated(plan, "named-checkconf")

    def plan_config_change(self, changes: list[Change], created_by: str = "") -> Plan:
        self._check()
        plan = Plan(
            scope=PlanScope.DNS_CONFIG,
            node_id=self.node_id,
            summary="",
            created_by=created_by,
            engine=Engine.BIND,
            target_node_ids=[self.node_id],
        )
        for change in changes:
            kind, _, name = change.target.partition("/")
            if kind == "keys":
                before = {"name": name, "algorithm": self.keys[name][0]} if name in self.keys else None
                after = None
                if change.op is not ChangeOp.DELETE:
                    after = dict(change.after or {})
                    after.setdefault("name", name)
                    after.setdefault("algorithm", "hmac-sha256")
                    if not after.get("secret"):
                        after["secret"] = secrets.token_urlsafe(32)
                shown = {k: v for k, v in (after or {}).items() if k != "secret"} if after else None
                plan.diff += _diff(before, shown, "keys.conf")
                plan.preconditions.append(
                    Precondition(
                        PreconditionKind.FILE_SHA256,
                        "/etc/bind/pelagos/keys.conf",
                        self._hash(self.keys),
                        self.node_id,
                    )
                )
            elif kind == "acls":
                before = {"name": name, "elements": self.acls[name]} if name in self.acls else None
                after = (
                    None
                    if change.op is ChangeOp.DELETE
                    else {"name": name, "elements": list((change.after or {}).get("elements", []))}
                )
                plan.diff += _diff(before, after, "acls.conf")
                plan.preconditions.append(
                    Precondition(
                        PreconditionKind.FILE_SHA256,
                        "/etc/bind/pelagos/acls.conf",
                        self._hash(self.acls),
                        self.node_id,
                    )
                )
            elif kind == "options":
                before = self.options.get(name)
                after = None if change.op is ChangeOp.DELETE else str(change.after)
                plan.diff += _diff(before, after, f"options.conf {name}")
                plan.preconditions.append(
                    Precondition(
                        PreconditionKind.FILE_SHA256,
                        "/etc/bind/pelagos/options.conf",
                        self._hash(self.options),
                        self.node_id,
                    )
                )
            elif change.target.startswith("raw:"):
                before, after = None, str(change.after)
                plan.diff += _diff(before, after, change.target[4:])
            elif kind == "rpz":
                from pelagos.rpz import model as rpz_model

                subs = [
                    rpz_model.Sub(**{k: v for k, v in r.items() if k in rpz_model.Sub.__dataclass_fields__})
                    for r in (change.after or {}).get("subs", [])
                ]
                mine = rpz_model.for_node(subs, self.node_id)
                before = self.options.get("response-policy")
                after = rpz_model.response_policy_value(mine) if mine else None
                if before == after:
                    return _validated(plan, "parser", False, "no change")
                plan.diff += _diff(before, after, "options.conf response-policy")
                before, after = None, dict(change.after or {})
            elif kind == "dnssec-policy":
                before = self.policies.get(name)
                after = None if change.op is ChangeOp.DELETE else dict(change.after or {})
                plan.diff += _diff(before, after, "policies.conf")
            else:
                return _validated(plan, "named-checkconf", False, f"unknown config target {change.target}")
            plan.changes.append(Change(change.op, change.target, before=before, after=after))
        plan.summary = f"{len(plan.changes)} configuration change(s)"
        if any(c.target.startswith("keys/") and c.op is not ChangeOp.ADD for c in plan.changes):
            plan.requires_confirmation = True
        return _validated(plan, "named-checkconf")

    def apply(self, plan: Plan) -> NodeApplyResult:
        self._check()
        if plan.changes and plan.changes[0].target.startswith("op:"):
            from pelagos.connectors.bind import ops

            name, view, zone = ops.parse_target(plan.changes[0].target)
            self.applied.append(plan.id)
            return NodeApplyResult(
                node_id=self.node_id, ok=True, message=self._op(name, zone, *([view] if view else []))
            )
        self._recheck(plan)
        self._mutate(plan.changes)
        self.applied.append(plan.id)
        self._record_details(plan, "apply")
        return NodeApplyResult(node_id=self.node_id, ok=True, message="applied")

    # BindExtras shapes ----------------------------------------------------

    def catalog_zones(self) -> list[dict[str, Any]]:
        self._check()
        members = [
            {"zone": z, "label": f"m{i}", "group": None, "coo": None} for i, z in enumerate(self.catalog)
        ]
        return [
            {
                "zone": "catalog.example.lan.",
                "view": "_default",
                "role": "producer",
                "members": members,
                "member_count": len(members),
                "version": "2",
                "error": None,
            }
        ]

    def dnssec_policies(self) -> list[dict[str, Any]]:
        self._check()
        return [
            {
                "name": n,
                "statements": s,
                "source": "pelagos",
                "config_path": "/etc/bind/pelagos/policies.conf",
                "used_by": [],
            }
            for n, s in self.policies.items()
        ]

    def plan_operation(
        self, name: str, zone: str, view: str | None, args: dict[str, Any] | None = None, created_by: str = ""
    ) -> Plan:
        from pelagos.connectors.bind import ops

        command = ops.command_text(name, zone, view, dict(args or {}))
        plan = Plan(
            scope=PlanScope.DNS_ZONE,
            node_id=self.node_id,
            summary=command,
            created_by=created_by,
            engine=Engine.BIND,
            target_node_ids=[self.node_id],
            changes=[
                Change(
                    ChangeOp.REPLACE,
                    ops.target(name, zone, view),
                    after=ops.check_args(name, dict(args or {})),
                )
            ],
            diff=f"+{command}",
            requires_confirmation=name in ops.DNSSEC_OPS,
        )
        return _validated(plan, "rndc")

    def rollback(self, plan: Plan) -> NodeApplyResult:
        self._check()
        self._mutate([c.inverse() for c in reversed(plan.changes)])
        self.rolled_back.append(plan.id)
        self._record_details(plan, "rollback")
        return NodeApplyResult(node_id=self.node_id, ok=True, message="rolled back", rolled_back=True)

    def _record_details(self, plan: Plan, verb: str) -> None:
        """Audit material in BindBackend.details' shapes (record plans by verb, file plans flat)."""
        if plan.scope is PlanScope.DNS_RRSET:
            update = "\n".join(f"update {c.op.value} {c.target}" for c in plan.changes)
            entry = {"request": {"update": update, "key": "ddi-admin"}, "response": {"rcode": "NOERROR"}}
            self.details.setdefault(plan.id, {})[verb] = entry
        elif verb == "apply":
            files = sorted({f"/etc/bind/pelagos/{c.target.split('/')[0]}.conf" for c in plan.changes})
            secrets_ = [
                c.after["secret"] for c in plan.changes if isinstance(c.after, dict) and c.after.get("secret")
            ]
            self.details[plan.id] = {
                "request": {"files": files, "text": "".join(f'secret "{s}";' for s in secrets_)},
                "response": {"steps": [{"name": "write", "ok": True}], "backup_dir": "/tmp/backup"},
            }
        else:
            self.details.setdefault(plan.id, {})["rollback"] = {"steps": [], "backup_dir": "/tmp/backup"}

    def pop_details(self, plan_id: str) -> dict[str, Any]:
        return self.details.pop(plan_id, {})

    def _recheck(self, plan: Plan) -> None:
        for pre in plan.preconditions:
            if pre.kind in (PreconditionKind.RRSET_EXISTS, PreconditionKind.RRSET_ABSENT):
                owner, _, rtype = pre.subject.partition("/")
                zone = next((z for z in self.zones if owner.endswith(z)), None)
                exists = zone is not None and (owner, rtype) in self.rrsets[zone]
                observed = "exists" if exists else "absent"
                # The real connector puts "" (absent) or the rdata (exists) in `value`.
                want = "absent" if pre.kind is PreconditionKind.RRSET_ABSENT else "exists"
                if observed != want:
                    raise PreconditionFailed(pre, observed)
            elif pre.kind is PreconditionKind.SOA_SERIAL:
                observed = str(self.serials.get(pre.subject))
                if observed != pre.value:
                    raise PreconditionFailed(pre, observed)
            elif pre.kind is PreconditionKind.FILE_SHA256:
                observed = {
                    "zones.conf": self._zones_hash,
                    "keys.conf": lambda: self._hash(self.keys),
                    "acls.conf": lambda: self._hash(self.acls),
                    "options.conf": lambda: self._hash(self.options),
                }[Path(pre.subject).name]()
                if observed != pre.value:
                    raise PreconditionFailed(pre, observed)

    def _mutate(self, changes: list[Change]) -> None:
        for change in changes:
            if change.target.startswith("raw:"):
                self.ops.append(("raw", change.target, change.after))
                continue
            head, _, rest = change.target.partition("/")
            if head == "dnssec-policy":
                if change.op is ChangeOp.DELETE:
                    self.policies.pop(rest, None)
                else:
                    self.policies[rest] = list(change.after.get("statements") or [])
                continue
            if head == "rpz":
                self._mutate_rpz(change)
            elif head in ("keys", "acls", "options"):
                self._mutate_config(head, rest, change)
            elif normalize_name(head) in self.zones and "/" in rest:
                zone = normalize_name(head)
                owner, _, rtype = rest.rpartition("/")
                table = self.rrsets[zone]
                if change.op is ChangeOp.DELETE:
                    table.pop((owner, rtype), None)
                else:
                    table[(owner, rtype)] = RRset.from_dict(change.after)
                self.serials[zone] += 1
            else:
                name = normalize_name(rest)
                if change.op is ChangeOp.DELETE:
                    self.zones.pop(name, None)
                    self.rrsets.pop(name, None)
                    self.serials.pop(name, None)
                else:
                    zone = Zone.from_dict(change.after)
                    if name not in self.zones:
                        self.add_zone(zone, [], serial=1)
                    self.zones[name] = zone

    def _mutate_rpz(self, change: Change) -> None:
        from pelagos.rpz import model as rpz_model

        subs = [
            rpz_model.Sub(**{k: v for k, v in r.items() if k in rpz_model.Sub.__dataclass_fields__})
            for r in (change.after or {}).get("subs", [])
        ]
        mine = rpz_model.for_node(subs, self.node_id)
        if mine:
            self.options["response-policy"] = rpz_model.response_policy_value(mine)
        else:
            self.options.pop("response-policy", None)

    def rpz_node_state(self) -> dict[str, Any]:
        return {"state": self.rpz_state, "ram_mb": self.rpz_ram}

    def rpz_env(self, log_path: str = "") -> Any:
        raise NotImplementedError

    def _mutate_config(self, kind: str, name: str, change: Change) -> None:
        if kind == "keys":
            if change.op is ChangeOp.DELETE:
                self.keys.pop(name, None)
            else:
                self.keys[name] = (
                    change.after["algorithm"],
                    change.after.get("secret") or self.keys.get(name, ("", ""))[1],
                )
        elif kind == "acls":
            if change.op is ChangeOp.DELETE:
                self.acls.pop(name, None)
            else:
                self.acls[name] = list(change.after["elements"])
        else:
            if change.op is ChangeOp.DELETE:
                self.options.pop(name, None)
            else:
                self.options[name] = str(change.after)

    def _zones_hash(self) -> str:
        return self._hash({n: z.to_dict() for n, z in self.zones.items()})

    @staticmethod
    def _hash(obj: Any) -> str:
        return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()

    # Operations ---------------------------------------------------------

    def _op(self, *args: str) -> str:
        self._check()
        self.ops.append(args)
        return f"{' '.join(args)}: ok"

    def reconfig(self) -> str:
        return self._op("reconfig")

    def reload(self, zone: str | None = None, view: str | None = None) -> str:
        return self._op("reload", *([zone] if zone else []))

    def notify(self, zone: str, view: str | None = None) -> str:
        return self._op("notify", zone)

    def retransfer(self, zone: str, view: str | None = None) -> str:
        return self._op("retransfer", zone)

    def freeze(self, zone: str, view: str | None = None) -> str:
        return self._op("freeze", zone)

    def thaw(self, zone: str, view: str | None = None) -> str:
        return self._op("thaw", zone)

    def sync(self, zone: str | None = None, clean: bool = False) -> str:
        return self._op("sync", *([zone] if zone else []))


def _rr_text(rr: dict[str, Any]) -> str:
    return "\n".join(f"{rr['name']} {rr['ttl']} IN {rr['rtype']} {r}" for r in rr["rdata"])


# DHCP ------------------------------------------------------------------------


def default_dhcp4_config() -> dict[str, Any]:
    return {
        "valid-lifetime": 3600,
        "interfaces-config": {"interfaces": ["eth0"]},
        "control-socket": {"socket-type": "unix", "socket-name": "/run/kea/kea4-ctrl-socket"},
        "hooks-libraries": [
            {"library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so"},
            {"library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_host_cmds.so"},
            {"library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_subnet_cmds.so"},
            {"library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_stat_cmds.so"},
            {
                "library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_ha.so",
                "parameters": {"high-availability": [{"mode": "hot-standby"}]},
            },
        ],
        "option-data": [
            {"name": "domain-name-servers", "code": 6, "space": "dhcp4", "data": "192.0.2.1, 192.0.2.2"},
            {"name": "domain-name", "code": 15, "space": "dhcp4", "data": "example.lan"},
        ],
        "option-def": [{"name": "custom-url", "code": 224, "type": "string", "space": "dhcp4"}],
        "client-classes": [
            {
                "name": "voip",
                "test": "option[60].hex == 'phone'",
                "option-data": [{"name": "tftp-server-name", "data": "192.0.2.9"}],
            },
        ],
        "dhcp-ddns": {"enable-updates": True, "server-ip": "127.0.0.1", "server-port": 53001},
        "ddns-send-updates": True,
        "ddns-qualifying-suffix": "example.lan.",
        "shared-networks": [
            {
                "name": "office",
                "subnet4": [
                    {
                        "id": 3,
                        "subnet": "192.0.3.0/24",
                        "pools": [{"pool": "192.0.3.10 - 192.0.3.20"}],
                        "user-context": {"pelagos": {"notes": "office floor 2"}},
                    },
                ],
            }
        ],
        "subnet4": [
            {
                "id": 1,
                "subnet": "192.0.2.0/24",
                "pools": [{"pool": "192.0.2.100 - 192.0.2.199", "client-classes": ["voip"]}],
                "option-data": [{"name": "routers", "code": 3, "space": "dhcp4", "data": "192.0.2.254"}],
                "reservations": [
                    {"hw-address": "aa:bb:cc:dd:ee:01", "ip-address": "192.0.2.100", "hostname": "pc1"},
                    {"hw-address": "aa:bb:cc:dd:ee:02", "ip-address": "192.0.2.101", "hostname": "pc2"},
                ],
                "user-context": {"pelagos": {"notes": "main LAN", "tags": ["lan"]}},
            },
            {"id": 2, "subnet": "192.0.4.0/24", "pools": [{"pool": "192.0.4.0/25"}]},
        ],
    }


def default_dhcp6_config() -> dict[str, Any]:
    return {
        "valid-lifetime": 7200,
        "preferred-lifetime": 3600,
        "hooks-libraries": [{"library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so"}],
        "option-data": [{"name": "dns-servers", "code": 23, "space": "dhcp6", "data": "2001:db8::1"}],
        "subnet6": [
            {
                "id": 1,
                "subnet": "2001:db8::/64",
                "pools": [{"pool": "2001:db8::100 - 2001:db8::1ff"}],
                "pd-pools": [{"prefix": "2001:db8:1::", "prefix-len": 48, "delegated-len": 64}],
                "reservations": [
                    {"duid": "01:02:03:04:05", "ip-addresses": ["2001:db8::100"], "hostname": "pc6"}
                ],
            }
        ],
    }


def default_leases4(node_id: str) -> list[Lease]:
    return [
        Lease(
            "192.0.2.100",
            1,
            Family.V4,
            hw_address="aa:bb:cc:dd:ee:01",
            hostname="pc1.example.lan.",
            valid_lft=3600,
            fqdn_fwd=True,
            fqdn_rev=True,
            node_id=node_id,
        ),
        Lease(
            "192.0.2.150",
            1,
            Family.V4,
            hw_address="aa:bb:cc:dd:ee:50",
            client_id="01:aa:bb:cc:dd:ee:50",
            hostname="laptop",
            valid_lft=3600,
            node_id=node_id,
        ),
        Lease(
            "192.0.2.151",
            1,
            Family.V4,
            hw_address="aa:bb:cc:dd:ee:51",
            state=LeaseState.EXPIRED_RECLAIMED,
            valid_lft=0,
            node_id=node_id,
        ),
        Lease(
            "192.0.3.10",
            3,
            Family.V4,
            hw_address="aa:bb:cc:dd:ee:03",
            hostname="printer",
            valid_lft=3600,
            node_id=node_id,
        ),
    ]


class FakeDhcpBackend(DhcpBackend):
    def __init__(
        self,
        ctx: ConnectorContext | None = None,
        family: Family = Family.V4,
        node_id: str = NODE_A,
        config: dict[str, Any] | None = None,
        leases: list[Lease] | None = None,
    ) -> None:
        super().__init__(ctx or fake_context(node_id, family.kea_engine.value), family)
        self.node_id = self.ctx.node_id
        self.failure: ConnectorError | None = None
        self.running = True
        self.enabled = True
        self.version = "3.2.1"
        self.config: dict[str, Any] = (
            config
            if config is not None
            else (default_dhcp4_config() if family is Family.V4 else default_dhcp6_config())
        )
        self.lease_table: list[Lease] = (
            leases if leases is not None else (default_leases4(self.node_id) if family is Family.V4 else [])
        )
        self.ha: HAState = HAState(
            node_id=self.node_id,
            family=family,
            collected_at=utcnow(),
            server_name="ns1",
            mode=HAMode.HOT_STANDBY,
            role="primary",
            state="hot-standby",
            scopes=["ns1"],
            partner=HAPartner(
                role="standby", server_name="ns2", state="hot-standby", scopes=[], in_touch=True
            ),
        )
        self.commands: list[tuple[str, dict[str, Any] | None]] = []
        self.applied: list[str] = []
        self.rolled_back: list[str] = []

    @property
    def subnet_key(self) -> str:
        return "subnet4" if self.family is Family.V4 else "subnet6"

    def _check(self) -> None:
        if self.failure is not None:
            raise self.failure

    # Observation --------------------------------------------------------

    def config_schema(self) -> dict[str, Any]:
        from pelagos.connectors.kea.schema import config_schema

        self._check()
        return config_schema(self.family.value, self.version)

    def capabilities(self) -> DhcpCapabilities:
        self._check()
        hooks = [
            Path(h["library"]).name.removeprefix("libdhcp_").removesuffix(".so")
            for h in self.config.get("hooks-libraries", [])
        ]
        has = {h: h in hooks for h in ("lease_cmds", "host_cmds", "subnet_cmds", "stat_cmds", "ha")}
        return DhcpCapabilities(
            engine=self.family.kea_engine,
            version=self.version,
            running=self.running,
            control_socket=f"/run/kea/kea{4 if self.family is Family.V4 else 6}-ctrl-socket",
            hooks=hooks,
            lease_cmds=has["lease_cmds"],
            host_cmds=has["host_cmds"],
            subnet_cmds=has["subnet_cmds"],
            stat_cmds=has["stat_cmds"],
            ha=has["ha"],
            degraded=not (has["host_cmds"] and has["subnet_cmds"]),
            config_write=True,
            lease_backend="memfile",
            multi_threading=False,
        )

    def status(self) -> dict[str, Any]:
        self._check()
        return {
            "pid": 4242,
            "uptime": 12345,
            "reload": 12345,
            "multi-threading-enabled": False,
            "dhcp-state": "enabled" if self.enabled else "disabled",
        }

    def command(self, command: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        self._check()
        if command in ("config-set", "config-write", "config-reload", "shutdown"):
            raise PermissionError(f"{command} must go through a plan")
        self.commands.append((command, arguments))
        return {"result": 0, "text": f"{command} ok"}

    def config_get(self) -> dict[str, Any]:
        self._check()
        return copy.deepcopy(self.config)

    def config_hash(self) -> str:
        self._check()
        return hashlib.sha256(json.dumps(self.config, sort_keys=True).encode()).hexdigest()

    def _all_subnet_raws(self) -> list[tuple[dict[str, Any], str | None]]:
        out = [(s, None) for s in self.config.get(self.subnet_key, [])]
        for net in self.config.get("shared-networks", []):
            out.extend((s, net["name"]) for s in net.get(self.subnet_key, []))
        return out

    def _subnet(self, raw: dict[str, Any], network: str | None) -> Subnet:
        return Subnet(
            id=int(raw["id"]),
            subnet=raw["subnet"],
            family=self.family,
            shared_network=network,
            pools=[
                Pool(
                    pool=p["pool"],
                    client_classes=list(p.get("client-classes", [])),
                    user_context=dict(p.get("user-context", {})),
                    raw=p,
                )
                for p in raw.get("pools", [])
            ],
            pd_pools=[
                PdPool(
                    prefix=p["prefix"],
                    prefix_len=int(p["prefix-len"]),
                    delegated_len=int(p["delegated-len"]),
                    raw=copy.deepcopy(p),
                )
                for p in raw.get("pd-pools", [])
            ],
            options=[_option(o, self.family) for o in raw.get("option-data", [])],
            reservations=[self._reservation(r, int(raw["id"])) for r in raw.get("reservations", [])],
            client_classes=list(raw.get("client-classes", [])),
            valid_lifetime=raw.get("valid-lifetime"),
            user_context=dict(raw.get("user-context", {})),
            raw=copy.deepcopy(raw),
        )

    def _reservation(self, raw: dict[str, Any], subnet_id: int | None) -> Reservation:
        id_type = next(t for t in ReservationIdType if t.value in raw)
        return Reservation(
            subnet_id=subnet_id,
            id_type=id_type,
            identifier=str(raw[id_type.value]).lower(),
            ip_address=raw.get("ip-address"),
            ip_addresses=list(raw.get("ip-addresses", [])),
            prefixes=list(raw.get("prefixes", [])),
            hostname=raw.get("hostname"),
            client_classes=list(raw.get("client-classes", [])),
            options=[_option(o, self.family) for o in raw.get("option-data", [])],
            user_context=dict(raw.get("user-context", {})),
            raw=copy.deepcopy(raw),
        )

    def list_subnets(self) -> list[Subnet]:
        self._check()
        return [self._subnet(raw, net) for raw, net in self._all_subnet_raws()]

    def get_subnet(self, subnet_id: int) -> Subnet:
        self._check()
        for raw, net in self._all_subnet_raws():
            if int(raw["id"]) == subnet_id:
                return self._subnet(raw, net)
        raise ConnectorError(f"subnet {subnet_id} not found")

    def list_shared_networks(self) -> list[SharedNetwork]:
        self._check()
        return [
            SharedNetwork(
                name=n["name"],
                family=self.family,
                subnets=[self._subnet(s, n["name"]) for s in n.get(self.subnet_key, [])],
                raw=copy.deepcopy(n),
            )
            for n in self.config.get("shared-networks", [])
        ]

    def list_client_classes(self) -> list[ClientClass]:
        self._check()
        return [
            ClientClass(
                name=c["name"],
                test=c.get("test"),
                options=[_option(o, self.family) for o in c.get("option-data", [])],
                raw=copy.deepcopy(c),
            )
            for c in self.config.get("client-classes", [])
        ]

    def global_options(self) -> list[OptionData]:
        self._check()
        return [_option(o, self.family) for o in self.config.get("option-data", [])]

    def option_defs(self) -> list[dict[str, Any]]:
        self._check()
        return copy.deepcopy(self.config.get("option-def", []))

    def list_reservations(self, subnet_id: int | None = None) -> list[Reservation]:
        self._check()
        out = [self._reservation(r, None) for r in self.config.get("reservations", [])]
        for raw, _net in self._all_subnet_raws():
            out.extend(self._reservation(r, int(raw["id"])) for r in raw.get("reservations", []))
        return [r for r in out if subnet_id is None or r.subnet_id == subnet_id]

    def leases(
        self, subnet_id: int | None = None, limit: int = 500, from_address: str | None = None
    ) -> list[Lease]:
        self._check()
        rows = [
            copy.deepcopy(lease)
            for lease in self.lease_table
            if subnet_id is None or lease.subnet_id == subnet_id
        ]
        if from_address:
            rows = [r for r in rows if r.ip_address > from_address]
        return rows[:limit]

    def lease(self, ip_address: str) -> Lease | None:
        self._check()
        return next(
            (copy.deepcopy(lease) for lease in self.lease_table if lease.ip_address == ip_address), None
        )

    def leases_by_hw(self, hw_address: str) -> list[Lease]:
        self._check()
        return [
            copy.deepcopy(lease)
            for lease in self.lease_table
            if (lease.hw_address or "").lower() == hw_address.lower()
        ]

    def leases_by_hostname(self, hostname: str) -> list[Lease]:
        self._check()
        want = hostname.lower().rstrip(".")
        return [
            copy.deepcopy(lease)
            for lease in self.lease_table
            if (lease.hostname or "").lower().rstrip(".") == want
        ]

    def statistics(self) -> dict[str, Any]:
        self._check()
        now = utcnow().isoformat()
        return {
            "pkt4-received": [[1500, now]],
            "pkt4-ack-sent": [[1400, now]],
            "subnet[1].assigned-addresses": [[2, now]],
            "subnet[1].total-addresses": [[100, now]],
        }

    def pool_utilization(self) -> list[dict[str, Any]]:
        self._check()
        out = []
        for raw, _net in self._all_subnet_raws():
            sid = int(raw["id"])
            active = [
                lease
                for lease in self.lease_table
                if lease.subnet_id == sid and lease.state is LeaseState.DEFAULT
            ]
            for pool in raw.get("pools", []):
                total = _pool_size(pool["pool"])
                out.append(
                    {
                        "subnet_id": sid,
                        "subnet": raw["subnet"],
                        "pool": pool["pool"],
                        "total": total,
                        "assigned": len(active),
                        "declined": 0,
                    }
                )
        return out

    def ha_state(self) -> HAState:
        self._check()
        self.ha.collected_at = utcnow()
        return copy.deepcopy(self.ha)

    # Plans --------------------------------------------------------------

    def _plan(self, scope: PlanScope, created_by: str, summary: str) -> Plan:
        plan = Plan(
            scope=scope,
            node_id=self.node_id,
            summary=summary,
            created_by=created_by,
            engine=self.family.kea_engine,
            target_node_ids=[self.node_id],
        )
        plan.preconditions.append(
            Precondition(
                PreconditionKind.CONFIG_HASH, self.family.kea_engine.value, self.config_hash(), self.node_id
            )
        )
        return plan

    def _find_subnet_raw(self, subnet_id: int) -> tuple[list[dict[str, Any]], int] | None:
        for container in [self.config.setdefault(self.subnet_key, [])] + [
            n.setdefault(self.subnet_key, []) for n in self.config.get("shared-networks", [])
        ]:
            for i, raw in enumerate(container):
                if int(raw["id"]) == subnet_id:
                    return container, i
        return None

    def plan_subnet_change(self, change: Change, created_by: str = "") -> Plan:
        self._check()
        plan = self._plan(PlanScope.DHCP_SUBNET, created_by, "")
        prefix, _, sid = change.target.partition("/")
        if prefix != self.subnet_key or not sid.isdigit():
            return _validated(plan, "config-test", False, f"target must be {self.subnet_key}/<id>")
        found = self._find_subnet_raw(int(sid))
        before = copy.deepcopy(found[0][found[1]]) if found else None
        after = None
        if change.op is not ChangeOp.DELETE:
            after = dict(change.after or {})
            after = after.get("raw") or after
            after = {k: v for k, v in after.items() if k not in ("family", "shared_network", "raw")}
            after = _kea_keys(after)
            after["id"] = int(sid)
            if not after.get("subnet"):
                return _validated(plan, "config-test", False, "subnet prefix is required")
        if change.op is ChangeOp.ADD and before is not None:
            return _validated(plan, "config-test", False, f"subnet {sid} already exists")
        if change.op is not ChangeOp.ADD and before is None:
            return _validated(plan, "config-test", False, f"subnet {sid} does not exist")
        plan.changes.append(Change(change.op, change.target, before=before, after=after))
        plan.diff = _diff(before, after, f"{self.subnet_key}[{sid}]")
        plan.summary = f"{change.op.value} subnet {sid}"
        plan.requires_confirmation = change.op is ChangeOp.DELETE
        return _validated(plan, "config-test")

    def plan_shared_network_change(self, change: Change, created_by: str = "") -> Plan:
        self._check()
        plan = self._plan(PlanScope.DHCP_SHARED_NETWORK, created_by, "")
        _, _, name = change.target.partition("/")
        nets = self.config.setdefault("shared-networks", [])
        before = copy.deepcopy(next((n for n in nets if n["name"] == name), None))
        after = (
            None
            if change.op is ChangeOp.DELETE
            else {**_kea_keys(dict((change.after or {}).get("raw") or change.after or {})), "name": name}
        )
        if change.op is ChangeOp.ADD and before is not None:
            return _validated(plan, "config-test", False, f"shared network {name} already exists")
        plan.changes.append(Change(change.op, change.target, before=before, after=after))
        plan.diff = _diff(before, after, f"shared-networks[{name}]")
        plan.summary = f"{change.op.value} shared network {name}"
        return _validated(plan, "config-test")

    def plan_reservation_change(self, change: Change, created_by: str = "") -> Plan:
        self._check()
        plan = self._plan(PlanScope.DHCP_RESERVATION, created_by, "")
        try:
            container, ident = self._reservation_target(change.target)
        except ValueError as exc:
            return _validated(plan, "config-test", False, str(exc))
        before = copy.deepcopy(next((r for r in container if r.get(ident[0]) == ident[1]), None))
        after = None
        if change.op is not ChangeOp.DELETE:
            raw = dict(change.after or {})
            after = _kea_keys(
                raw.get("raw")
                or {
                    k: v
                    for k, v in raw.items()
                    if k not in ("subnet_id", "id_type", "identifier", "raw") and v not in (None, [], {})
                }
            )
            after[ident[0]] = ident[1]
            if not (
                after.get("ip-address")
                or after.get("ip-addresses")
                or after.get("prefixes")
                or after.get("hostname")
            ):
                return _validated(
                    plan, "config-test", False, "a reservation needs an address, a prefix or a hostname"
                )
        if change.op is ChangeOp.ADD and before is not None:
            return _validated(plan, "config-test", False, f"reservation {ident[1]} already exists")
        if change.op is not ChangeOp.ADD and before is None:
            return _validated(plan, "config-test", False, f"reservation {ident[1]} does not exist")
        plan.changes.append(Change(change.op, change.target, before=before, after=after))
        plan.diff = _diff(before, after, change.target)
        plan.summary = f"{change.op.value} reservation {ident[1]}"
        return _validated(plan, "config-test")

    def _reservation_target(self, target: str) -> tuple[list[dict[str, Any]], tuple[str, str]]:
        parts = target.split("/")
        if len(parts) == 3 and parts[0] == "global" and parts[1] == "reservations":
            container = self.config.setdefault("reservations", [])
            ident = parts[2]
        elif len(parts) == 4 and parts[0] == self.subnet_key and parts[2] == "reservations":
            found = self._find_subnet_raw(int(parts[1]))
            if found is None:
                raise ValueError(f"subnet {parts[1]} does not exist")
            container = found[0][found[1]].setdefault("reservations", [])
            ident = parts[3]
        else:
            raise ValueError(f"bad reservation target {target}")
        id_type, _, value = ident.partition("=")
        if id_type not in {t.value for t in ReservationIdType} or not value:
            raise ValueError(f"bad reservation identifier {ident}")
        return container, (id_type, value.lower())

    def plan_class_change(self, change: Change, created_by: str = "") -> Plan:
        self._check()
        plan = self._plan(PlanScope.DHCP_CLASS, created_by, "")
        _, _, name = change.target.partition("/")
        classes = self.config.setdefault("client-classes", [])
        before = copy.deepcopy(next((c for c in classes if c["name"] == name), None))
        after = (
            None
            if change.op is ChangeOp.DELETE
            else {**_kea_keys(dict((change.after or {}).get("raw") or change.after or {})), "name": name}
        )
        if change.op is ChangeOp.ADD and before is not None:
            return _validated(plan, "config-test", False, f"class {name} already exists")
        plan.changes.append(Change(change.op, change.target, before=before, after=after))
        plan.diff = _diff(before, after, f"client-classes[{name}]")
        plan.summary = f"{change.op.value} class {name}"
        return _validated(plan, "config-test")

    def plan_global_change(self, changes: list[Change], created_by: str = "") -> Plan:
        self._check()
        plan = self._plan(PlanScope.DHCP_OPTIONS, created_by, "")
        for change in changes:
            if change.target.startswith("option-data/"):
                _, space, key = change.target.split("/", 2)
                options = self.config.setdefault("option-data", [])
                before = copy.deepcopy(
                    next(
                        (
                            o
                            for o in options
                            if o.get("space", "dhcp4") == space
                            and (str(o.get("code")) == key or o.get("name") == key)
                        ),
                        None,
                    )
                )
                after = (
                    None
                    if change.op is ChangeOp.DELETE
                    else {**_kea_keys(dict(change.after or {})), "space": space}
                )
            elif "/" not in change.target:
                before = copy.deepcopy(self.config.get(change.target))
                after = None if change.op is ChangeOp.DELETE else change.after
            else:
                return _validated(plan, "config-test", False, f"bad global target {change.target}")
            plan.changes.append(Change(change.op, change.target, before=before, after=after))
            plan.diff += _diff(before, after, change.target)
        plan.summary = f"{len(plan.changes)} global change(s)"
        return _validated(plan, "config-test")

    def plan_config_replace(self, config: dict[str, Any], created_by: str = "") -> Plan:
        self._check()
        plan = self._plan(PlanScope.DHCP_CONFIG, created_by, "replace the whole configuration")
        if not isinstance(config, dict) or self.subnet_key not in config:
            return _validated(plan, "config-test", False, f"configuration must contain {self.subnet_key}")
        before = copy.deepcopy(self.config)
        plan.changes.append(Change(ChangeOp.REPLACE, "config", before=before, after=copy.deepcopy(config)))
        plan.diff = _diff(before, config, "config")
        return _validated(plan, "config-test")

    def plan_lease_delete(self, ip_address: str, created_by: str = "") -> Plan:
        self._check()
        plan = self._plan(PlanScope.DHCP_LEASE, created_by, f"delete lease {ip_address}")
        plan.preconditions.clear()
        lease = self.lease(ip_address)
        if lease is None:
            return _validated(
                plan, f"lease{4 if self.family is Family.V4 else 6}-get", False, f"no lease for {ip_address}"
            )
        plan.changes.append(
            Change(
                ChangeOp.DELETE,
                f"lease{4 if self.family is Family.V4 else 6}/{ip_address}",
                before=lease.to_dict(),
            )
        )
        plan.diff = _diff(lease.to_dict(), None, f"lease {ip_address}")
        plan.requires_confirmation = True
        return _validated(plan, "lease-cmds")

    def plan_ha_maintenance(self, action: str, created_by: str = "") -> Plan:
        self._check()
        plan = self._plan(PlanScope.DHCP_HA, created_by, f"HA maintenance {action}")
        plan.preconditions = [
            Precondition(
                PreconditionKind.HA_STATE, self.family.kea_engine.value, self.ha.state or "", self.node_id
            )
        ]
        if action not in ("start", "cancel"):
            return _validated(plan, "ha-maintenance", False, "action must be start or cancel")
        plan.changes.append(Change(ChangeOp.REPLACE, "ha/maintenance", before=self.ha.state, after=action))
        plan.requires_confirmation = True
        return _validated(plan, "ha-maintenance")

    def plan_ha_setup(self, spec: dict | None, this_server: str | None, created_by: str = "") -> Plan:
        from pelagos.connectors.kea.ha import hooks_dir_of, hooks_with_ha, relationship_entry

        self._check()
        plan = self._plan(PlanScope.DHCP_CONFIG, created_by, f"HA setup {this_server or 'removed'}")
        hooks = list(self.config.get("hooks-libraries") or [])
        entry: Any = None
        if spec is not None and spec.get("relationships"):
            if len(spec["relationships"]) > 1 and int(self.version.split(".")[0]) < 3:
                raise ConnectorError(f"Kea {self.version} runs one HA relationship per server")
            entry = [relationship_entry(r, r["this_server"]) for r in spec["relationships"]]
        elif spec is not None:
            entry = relationship_entry(spec, this_server or "")
        after = hooks_with_ha(hooks, entry, hooks_dir_of(hooks) or "/usr/lib/kea/hooks")
        plan.changes.append(Change(ChangeOp.REPLACE, "hooks-libraries", before=hooks, after=after))
        plan.diff = _diff(hooks, after, "hooks-libraries")
        return _validated(plan, "config-test")

    def plan_service_toggle(self, enable: bool, created_by: str = "") -> Plan:
        self._check()
        plan = self._plan(PlanScope.DHCP_HA, created_by, "dhcp-enable" if enable else "dhcp-disable")
        plan.preconditions.clear()
        plan.changes.append(Change(ChangeOp.REPLACE, "service", before=self.enabled, after=bool(enable)))
        plan.requires_confirmation = True
        return _validated(plan, "dhcp-enable" if enable else "dhcp-disable")

    def apply(self, plan: Plan) -> NodeApplyResult:
        self._check()
        for pre in plan.preconditions:
            if pre.kind is PreconditionKind.CONFIG_HASH and pre.value != self.config_hash():
                raise PreconditionFailed(pre, self.config_hash())
            if pre.kind is PreconditionKind.HA_STATE and pre.value != (self.ha.state or ""):
                raise PreconditionFailed(pre, self.ha.state or "")
        self._mutate(plan.changes)
        self.applied.append(plan.id)
        return NodeApplyResult(node_id=self.node_id, ok=True, message="applied, config-write done")

    def rollback(self, plan: Plan) -> NodeApplyResult:
        self._check()
        self._mutate([c.inverse() for c in reversed(plan.changes)])
        self.rolled_back.append(plan.id)
        return NodeApplyResult(node_id=self.node_id, ok=True, message="rolled back", rolled_back=True)

    def _mutate(self, changes: list[Change]) -> None:
        for change in changes:
            target = change.target
            if target == "config":
                self.config = copy.deepcopy(change.after)
            elif target.startswith("lease"):
                ip = target.partition("/")[2]
                if change.op is ChangeOp.DELETE:
                    self.lease_table = [lease for lease in self.lease_table if lease.ip_address != ip]
                else:
                    self.lease_table.append(Lease.from_dict(change.after))
            elif target == "ha/maintenance":
                self.ha.state = (
                    "in-maintenance"
                    if change.after == "start"
                    else (self.ha.mode.value if self.ha.mode else "hot-standby")
                )
            elif target == "ha/restart":
                # A reset server serves again (the real connector waits for the pair).
                if isinstance(change.after, dict) and change.after.get("action") == "restart":
                    self.resets = getattr(self, "resets", 0) + 1
                    if self.ha.state == "terminated":
                        self.ha.state = self.ha.mode.value if self.ha.mode else "hot-standby"
            elif target == "hooks-libraries":
                self.config["hooks-libraries"] = copy.deepcopy(change.after)
            elif target == "service":
                after = change.after
                # The real connector takes {"enable": bool}; older fakes passed a bare bool.
                self.enabled = (
                    bool(after.get("enable", after.get("enabled")))
                    if isinstance(after, dict)
                    else bool(after)
                )
            elif "/reservations/" in target:
                container, ident = self._reservation_target(target)
                container[:] = [r for r in container if r.get(ident[0]) != ident[1]]
                if change.op is not ChangeOp.DELETE:
                    container.append(copy.deepcopy(change.after))
            elif target.startswith(self.subnet_key + "/"):
                sid = int(target.partition("/")[2])
                found = self._find_subnet_raw(sid)
                if change.op is ChangeOp.DELETE:
                    if found:
                        del found[0][found[1]]
                elif found:
                    found[0][found[1]] = copy.deepcopy(change.after)
                else:
                    self.config.setdefault(self.subnet_key, []).append(copy.deepcopy(change.after))
            elif target.startswith("shared-networks/"):
                _replace_named(
                    self.config.setdefault("shared-networks", []), target.partition("/")[2], change
                )
            elif target.startswith("client-classes/"):
                _replace_named(self.config.setdefault("client-classes", []), target.partition("/")[2], change)
            elif target.startswith("option-data/"):
                _, space, key = target.split("/", 2)
                options = self.config.setdefault("option-data", [])
                options[:] = [
                    o
                    for o in options
                    if not (
                        o.get("space", "dhcp4") == space
                        and (str(o.get("code")) == key or o.get("name") == key)
                    )
                ]
                if change.op is not ChangeOp.DELETE:
                    options.append(copy.deepcopy(change.after))
            else:
                if change.op is ChangeOp.DELETE:
                    self.config.pop(target, None)
                else:
                    self.config[target] = copy.deepcopy(change.after)


def _replace_named(container: list[dict[str, Any]], name: str, change: Change) -> None:
    container[:] = [c for c in container if c.get("name") != name]
    if change.op is not ChangeOp.DELETE:
        container.append(copy.deepcopy(change.after))


def _kea_keys(obj: dict[str, Any]) -> dict[str, Any]:
    """Domain dicts use snake_case; Kea wants kebab-case. Values are kept as given."""
    return {k.replace("_", "-"): v for k, v in obj.items()}


def _option(raw: dict[str, Any], family: Family) -> OptionData:
    return OptionData(
        name=raw.get("name"),
        code=raw.get("code"),
        space=raw.get("space", "dhcp4" if family is Family.V4 else "dhcp6"),
        data=str(raw.get("data", "")),
        csv_format=raw.get("csv-format"),
        always_send=raw.get("always-send"),
        never_send=raw.get("never-send"),
        raw=copy.deepcopy(raw),
    )


def _pool_size(pool: str) -> int:
    if "-" in pool:
        lo, hi = (ipaddress.ip_address(p.strip()) for p in pool.split("-", 1))
        return int(hi) - int(lo) + 1
    return ipaddress.ip_network(pool, strict=False).num_addresses


# D2 ----------------------------------------------------------------------------


class FakeDdnsBackend(DdnsBackend):
    def __init__(self, ctx: ConnectorContext | None = None, node_id: str = NODE_A) -> None:
        super().__init__(ctx or fake_context(node_id, "d2"))
        self.node_id = self.ctx.node_id
        self.failure: ConnectorError | None = None
        self.running = True
        self.config: dict[str, Any] = {
            "ip-address": "127.0.0.1",
            "port": 53001,
            "control-socket": {"socket-type": "unix", "socket-name": "/run/kea/kea-ddns-ctrl-socket"},
            "tsig-keys": [
                {"name": "kea-ddns", "algorithm": "HMAC-SHA256", "secret-file": "/etc/kea/kea-ddns.key"}
            ],
            "forward-ddns": {
                "ddns-domains": [
                    {
                        "name": "example.lan.",
                        "key-name": "kea-ddns",
                        "dns-servers": [{"ip-address": "127.0.0.1", "port": 53}],
                    }
                ]
            },
            "reverse-ddns": {
                "ddns-domains": [
                    {
                        "name": "2.0.192.in-addr.arpa.",
                        "key-name": "kea-ddns",
                        "dns-servers": [{"ip-address": "127.0.0.1", "port": 53}],
                    }
                ]
            },
        }
        self.applied: list[str] = []

    def _check(self) -> None:
        if self.failure is not None:
            raise self.failure

    def config_schema(self) -> dict[str, Any]:
        from pelagos.connectors.kea.schema import config_schema

        self._check()
        return config_schema("d2", "3.2.1")

    def capabilities(self) -> dict[str, Any]:
        self._check()
        return {
            "running": self.running,
            "version": "3.2.1",
            "control_socket": "/run/kea/kea-ddns-ctrl-socket",
        }

    def status(self) -> dict[str, Any]:
        self._check()
        return {"pid": 4343, "uptime": 100, "reload": 100}

    def config_get(self) -> dict[str, Any]:
        self._check()
        return copy.deepcopy(self.config)

    def stats(self) -> D2Stats:
        self._check()
        totals = {
            "ncr-received": 100,
            "ncr-invalid": 0,
            "ncr-error": 1,
            "update-sent": 99,
            "update-signed": 99,
            "update-unsigned": 0,
            "update-success": 97,
            "update-timeout": 1,
            "update-error": 1,
        }
        return D2Stats(
            node_id=self.node_id,
            totals=totals,
            per_key={
                "kea-ddns.": {"update-sent": 99, "update-success": 97, "update-timeout": 1, "update-error": 1}
            },
        )

    def plan_config_replace(self, config: dict[str, Any], created_by: str = "") -> Plan:
        self._check()
        plan = Plan(
            scope=PlanScope.D2_CONFIG,
            node_id=self.node_id,
            summary="replace D2 configuration",
            created_by=created_by,
            engine=Engine.D2,
            target_node_ids=[self.node_id],
        )
        if not isinstance(config, dict) or "forward-ddns" not in config:
            raise ValidationFailed(
                ValidationResult(
                    ok=False, tool="config-test", output="DhcpDdns needs forward-ddns", node_id=self.node_id
                )
            )
        before = copy.deepcopy(self.config)
        plan.changes.append(Change(ChangeOp.REPLACE, "config", before=before, after=copy.deepcopy(config)))
        plan.diff = _diff(before, config, "kea-dhcp-ddns.conf")
        return _validated(plan, "config-test")

    def apply(self, plan: Plan) -> NodeApplyResult:
        self._check()
        self.config = copy.deepcopy(plan.changes[0].after)
        self.applied.append(plan.id)
        return NodeApplyResult(node_id=self.node_id, ok=True, message="applied")

    def rollback(self, plan: Plan) -> NodeApplyResult:
        self._check()
        self.config = copy.deepcopy(plan.changes[0].before)
        return NodeApplyResult(node_id=self.node_id, ok=True, message="rolled back", rolled_back=True)


# Peers -------------------------------------------------------------------------


class FakeReplicationClient:
    """Stands for core.replication.ReplicationClient talking to a peer whose engines are `registry`.

    Snapshots are built by services.snapshot on the peer side, as WP-CORE's server will do.
    """

    def __init__(self, node_id: str, registry: Any, reachable: bool = True) -> None:
        self.node_id = node_id
        self.registry = registry
        self.reachable = reachable
        self.calls: list[tuple[str, Any]] = []
        self.config_toml: str | None = None
        self.audit: list[dict[str, Any]] = []
        # The peer's master key: set it to open sealed plan secrets as ReplicationApp does.
        self.secrets: Any = None

    def _check(self) -> None:
        from pelagos.core.replication import ReplicationError

        if not self.reachable:
            raise ReplicationError(f"node {self.node_id} unreachable", code="unreachable")

    @property
    def peer(self) -> Any:
        return type("PeerRef", (), {"id": self.node_id, "name": f"peer-{self.node_id[-4:]}"})()

    def _config_head(self) -> tuple[int, str | None, str | None]:
        import tomllib

        if not self.config_toml:
            return 7, None, None
        data = tomllib.loads(self.config_toml)
        at = data.get("updated_at")
        return (
            int(data.get("version", 0)),
            (to_rfc3339(at) if hasattr(at, "tzinfo") else at),
            data.get("updated_by"),
        )

    def status(self) -> Any:
        from pelagos.core.replication import PeerStatus

        self._check()
        version, updated_at, updated_by = self._config_head()
        return PeerStatus(
            self.node_id,
            True,
            config_version=version,
            audit_count=len(self.audit),
            audit_head=max((e["id"] for e in self.audit), default=None),
            version="0.1.0",
            config_updated_at=updated_at,
            config_updated_by=updated_by,
        )

    def push_config(self, version: int, updated_at: str, updated_by: str, toml_text: str) -> bool:
        self._check()
        if version <= self._config_head()[0] and self.config_toml:
            return False
        self.config_toml = toml_text
        return True

    def push_audit(self, entries: list[dict[str, Any]]) -> int:
        self._check()
        known = {e["id"] for e in self.audit}
        fresh = [e for e in entries if e["id"] not in known]
        self.audit.extend(fresh)
        return len(fresh)

    def audit_ids(self) -> list[str]:
        self._check()
        return sorted(e["id"] for e in self.audit)

    def fetch_audit_ids(self, ids: list[str]) -> list[dict[str, Any]]:
        self._check()
        wanted = set(ids)
        return sorted((e for e in self.audit if e["id"] in wanted), key=lambda e: e["id"])

    def engine_snapshot(
        self, engine: str, kind: str = "summary", params: dict[str, Any] | None = None
    ) -> Any:
        from pelagos.services.snapshot import engine_snapshot

        self._check()
        self.calls.append(("snapshot", (engine, kind, params)))
        return engine_snapshot(self.registry, Engine(engine), kind, params)

    def action(self, name: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST /repl/v1/actions/<name> served by services.peer_actions over the peer's engines."""
        import json

        from pelagos.core.replication import PeerActionError
        from pelagos.services.peer_actions import PeerActions

        self._check()
        self.calls.append(("action", name))
        handler = PeerActions(self.peer_ctx(), self.registry)
        try:
            result = handler(name, json.loads(json.dumps(body)), getattr(self, "caller", "node-a"))
        except PeerActionError as exc:
            return {"ok": False, "code": exc.code, "detail": exc.detail, "errors": exc.errors}
        return {"ok": True, "result": json.loads(json.dumps(result, default=str))}

    def peer_ctx(self) -> Any:
        """The peer's NodeContext (set `ctx`), else a stand-in with an audit list and a locks dir."""
        if getattr(self, "ctx", None) is not None:
            return self.ctx
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace

        if getattr(self, "_stand_in", None) is None:
            root = Path(tempfile.mkdtemp(prefix="pelagos-fake-peer-"))
            audit: list[Any] = []
            self.peer_audit = audit
            self._stand_in = SimpleNamespace(
                node=SimpleNamespace(id=self.node_id, name=f"peer-{self.node_id[-4:]}"),
                paths=SimpleNamespace(locks_dir=root, series_db=root / "series.sqlite"),
                audit_log=SimpleNamespace(append=audit.append),
                secrets=self.secrets,
                settings=lambda: {},
                cluster=lambda: SimpleNamespace(nodes=[], modules={}),
            )
        return self._stand_in

    def apply_plan(self, plan: Plan) -> NodeApplyResult:
        self._check()
        self.calls.append(("apply", plan.id))
        received = Plan.from_dict(plan.to_dict())
        if getattr(self, "answer_lost", False):
            # Applied, but the answer never comes back (read timeout): the caller cannot know.
            from pelagos.core.replication import ReplicationError

            self.registry.backend(plan.engine).apply(received)
            raise ReplicationError("read timed out")
        backend = self.registry.backend(plan.engine)
        try:
            if self.secrets is not None:
                from pelagos.core.plan_secrets import hand_secrets_to_backend

                hand_secrets_to_backend(received, backend, self.secrets)
            result = backend.apply(received)
        except ConnectorError as exc:
            return NodeApplyResult(node_id=self.node_id, ok=False, message=str(exc))
        result.node_id = self.node_id
        return result

    def rollback_plan(self, plan: Plan) -> NodeApplyResult:
        self._check()
        self.calls.append(("rollback", plan.id))
        result = self.registry.backend(plan.engine).rollback(Plan.from_dict(plan.to_dict()))
        result.node_id = self.node_id
        return result

    def fetch_config(self) -> dict[str, Any]:
        self._check()
        return {"version": 0, "updated_at": None, "updated_by": "", "toml": self.config_toml or ""}

    def fetch_audit(self, after_id: str | None, limit: int = 1000) -> tuple[list[dict[str, Any]], str | None]:
        self._check()
        rows = sorted(
            (e for e in self.audit if after_id is None or e["id"] > after_id), key=lambda e: e["id"]
        )
        rows = rows[:limit]
        return rows, (rows[-1]["id"] if len(rows) == limit else None)
