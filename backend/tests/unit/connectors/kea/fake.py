# SPDX-License-Identifier: Apache-2.0
"""In-memory Kea control socket for the unit tier: captured payloads plus the commands Pelagos sends."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pelagos.connectors.base import ConnectorContext
from pelagos.connectors.kea.control_socket import KeaControlSocket

DATA = Path(__file__).resolve().parent / "data"


def load(name: str) -> dict[str, Any]:
    return json.loads((DATA / f"{name}.json").read_text())


def config_of(name: str) -> dict[str, Any]:
    """The daemon object (Dhcp4, Dhcp6 or DhcpDdns) of a captured config-get answer."""
    args = load(name)["arguments"]
    return copy.deepcopy(next(iter(args.values())))


def ok(arguments: Any = None, text: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {"result": 0, "text": text}
    if arguments is not None:
        out["arguments"] = arguments
    return out


def err(text: str, result: int = 1) -> dict[str, Any]:
    return {"result": result, "text": text}


def make_ctx(tmp: Path, **engine: Any) -> ConnectorContext:
    return ConnectorContext(
        node_id="n1",
        engine_config={"socket_dir": str(tmp), "dhcp4_conf": str(tmp / "kea-dhcp4.conf"), **engine},
        backup_root=tmp / "backups",
        get_secret=lambda name: None,
        settings={"plans": {"ttl_seconds": 60}},
    )


class FakeKea(KeaControlSocket):
    """Answers like a kea-dhcp4/6 or kea-dhcp-ddns socket; `sent` records every command."""

    def __init__(self, root: str, cfg: dict[str, Any], version: str = "3.2.1") -> None:
        super().__init__(Path("/run/kea/fake-socket"))
        self.root = root
        self.cfg = cfg
        self.version_text = version
        self.sent: list[tuple[str, Any]] = []
        self.written: list[dict[str, Any]] = []
        self.leases: list[dict[str, Any]] = []
        self.status_args: dict[str, Any] = {"pid": 1, "dhcp-state": {"disabled-by-user": False}}
        self.stats: dict[str, Any] = {}
        self.reject_test: Callable[[dict[str, Any]], str | None] = lambda cfg: None
        self.overrides: dict[str, Any] = {}
        self.disabled = False
        # Hosts written without operation-target "memory" when a hosts database is configured;
        # config-get never lists them, like a real server.
        self.db_hosts: list[dict[str, Any]] = []

    # Transport ---------------------------------------------------------------

    def send(
        self, command: str, arguments: dict[str, Any] | None = None, service: list[str] | None = None
    ) -> dict[str, Any]:
        self.sent.append((command, copy.deepcopy(arguments)))
        if command in self.overrides:
            answer = self.overrides[command]
            return answer(arguments) if callable(answer) else copy.deepcopy(answer)
        handler = getattr(self, "_" + command.replace("-", "_"), None)
        if handler is None:
            n = "4" if self.root == "Dhcp4" else "6"
            generic = (
                command.replace(n, "n", 1) if command.startswith(("subnet", "network", "lease")) else command
            )
            handler = getattr(self, "_" + generic.replace("-", "_"), None)
        if handler is None:
            return err(f"'{command}' command not supported.", 2)
        return handler(copy.deepcopy(arguments) or {})

    def commands(self) -> list[str]:
        return [c for c, _ in self.sent]

    @property
    def n(self) -> str:
        return "4" if self.root == "Dhcp4" else "6"

    # Generic -------------------------------------------------------------------

    def _version_get(self, args):
        return ok({"extended": self.version_text}, self.version_text)

    def _config_get(self, args):
        return ok({self.root: copy.deepcopy(self.cfg)})

    def _config_hash_get(self, args):
        digest = hashlib.sha256(json.dumps(self.cfg, sort_keys=True).encode()).hexdigest().upper()
        return ok({"hash": digest})

    def _config_test(self, args):
        problem = self.reject_test(args[self.root])
        return err(problem) if problem else ok(text="Configuration seems sane.")

    def _config_set(self, args):
        problem = self.reject_test(args[self.root])
        if problem:
            return err(problem)
        self.cfg = copy.deepcopy(args[self.root])
        return ok(text="Configuration successful.")

    def _config_write(self, args):
        self.written.append(copy.deepcopy(self.cfg))
        return ok({"filename": "/etc/kea/kea-dhcp4.conf", "size": 1}, "Configuration written.")

    def _config_reload(self, args):
        return ok(text="Configuration successful.")

    def _status_get(self, args):
        return ok(copy.deepcopy(self.status_args))

    def _statistic_get_all(self, args):
        return ok(copy.deepcopy(self.stats))

    def _dhcp_disable(self, args):
        self.status_args["dhcp-state"]["disabled-by-user"] = True
        return ok(text="DHCPv4 service disabled")

    def _dhcp_enable(self, args):
        self.status_args["dhcp-state"]["disabled-by-user"] = False
        return ok(text="DHCP service successfully enabled")

    def _ha_maintenance_start(self, args):
        self._set_ha_state("partner-in-maintenance")
        return ok(text="Server is now in the partner-in-maintenance state.")

    def _ha_maintenance_cancel(self, args):
        self._set_ha_state("hot-standby")
        return ok(text="Server maintenance successfully canceled.")

    def _set_ha_state(self, state: str) -> None:
        self.status_args["high-availability"][0]["ha-servers"]["local"]["state"] = state

    # Subnets and networks ------------------------------------------------------------

    def _subnets(self) -> list[dict[str, Any]]:
        return self.cfg.setdefault(f"subnet{self.n}", [])

    def _all_subnet_lists(self) -> list[list[dict[str, Any]]]:
        key = f"subnet{self.n}"
        return [self._subnets(), *[net.setdefault(key, []) for net in self.cfg.get("shared-networks", [])]]

    def _find(self, sid: int) -> tuple[list[dict[str, Any]], int] | None:
        for lst in self._all_subnet_lists():
            for i, s in enumerate(lst):
                if s["id"] == sid:
                    return lst, i
        return None

    def _subnetn_add(self, args):
        for s in args[f"subnet{self.n}"]:
            if "reservations" in s:
                return err(f"must not specify host reservations with 'subnet{self.n}-add'.")
            if self._find(s["id"]):
                return err(f"duplicate subnet id {s['id']}")
            self._subnets().append(s)
        return ok(text="added")

    def _subnetn_update(self, args):
        for s in args[f"subnet{self.n}"]:
            if "reservations" in s:
                return err(f"must not specify host reservations with 'subnet{self.n}-update'.")
            found = self._find(s["id"])
            if not found:
                return err("no such subnet")
            lst, i = found
            s["reservations"] = lst[i].get("reservations", [])
            lst[i] = s
        return ok(text="updated")

    def _subnetn_del(self, args):
        found = self._find(args["id"])
        if not found:
            return err("no such subnet", 3)
        del found[0][found[1]]
        return ok(text="deleted")

    def _networkn_add(self, args):
        self.cfg.setdefault("shared-networks", []).extend(args["shared-networks"])
        return ok(text="added")

    def _networkn_del(self, args):
        nets = self.cfg.get("shared-networks", [])
        self.cfg["shared-networks"] = [n for n in nets if n["name"] != args["name"]]
        return ok(text="deleted")

    def _networkn_subnet_add(self, args):
        found = self._find(args["id"])
        sub = found[0].pop(found[1])
        net = next(n for n in self.cfg["shared-networks"] if n["name"] == args["name"])
        net.setdefault(f"subnet{self.n}", []).append(sub)
        return ok(text="added")

    def _networkn_subnet_del(self, args):
        net = next(n for n in self.cfg["shared-networks"] if n["name"] == args["name"])
        lst = net[f"subnet{self.n}"]
        idx = next(i for i, s in enumerate(lst) if s["id"] == args["id"])
        self._subnets().append(lst.pop(idx))
        return ok(text="deleted")

    # Reservations and classes ---------------------------------------------------------

    def _reservation_list(self, sid: int) -> list[dict[str, Any]]:
        if sid == 0:
            return self.cfg.setdefault("reservations", [])
        lst, i = self._find(sid)
        return lst[i].setdefault("reservations", [])

    @property
    def has_hosts_db(self) -> bool:
        return bool(self.cfg.get("hosts-database") or self.cfg.get("hosts-databases"))

    def _in_db(self, args) -> bool:
        return args.get("operation-target") != "memory" and self.has_hosts_db

    @staticmethod
    def _id_of(res: dict[str, Any]) -> tuple[str, str]:
        id_type = next(k for k in ("hw-address", "duid", "client-id", "circuit-id", "flex-id") if k in res)
        return id_type, str(res[id_type]).lower()

    def _db_index(self, sid: int, id_type: str, identifier: str) -> int | None:
        for i, h in enumerate(self.db_hosts):
            if h["subnet-id"] == sid and str(h.get(id_type, "")).lower() == identifier.lower():
                return i
        return None

    def _reservation_add(self, args):
        res = dict(args["reservation"])
        if self._in_db(args):
            if self._db_index(res["subnet-id"], *self._id_of(res)) is not None:
                return err("Host already exists.")
            self.db_hosts.append(res)
            return ok(text="Host added.")
        if args.get("operation-target") != "memory":
            return err("Host database not available, cannot add host.")
        self._reservation_list(res.pop("subnet-id")).append(res)
        return ok(text="Host added.")

    def _reservation_update(self, args):
        res = dict(args["reservation"])
        if self._in_db(args):
            idx = self._db_index(res["subnet-id"], *self._id_of(res))
            if idx is None:
                return err("Host not updated (not found).")
            self.db_hosts[idx] = res
            return ok(text="Host updated.")
        lst = self._reservation_list(res.pop("subnet-id"))
        id_type = self._id_of(res)[0]
        idx = next(i for i, r in enumerate(lst) if r.get(id_type) == res[id_type])
        lst[idx] = res
        return ok(text="Host updated.")

    def _reservation_del(self, args):
        if self._in_db(args):
            idx = self._db_index(args["subnet-id"], args["identifier-type"], args["identifier"])
            if idx is None:
                return err("Host not deleted (not found).", 3)
            del self.db_hosts[idx]
            return ok(text="Host deleted.")
        lst = self._reservation_list(args["subnet-id"])
        before = len(lst)
        lst[:] = [r for r in lst if r.get(args["identifier-type"], "").lower() != args["identifier"]]
        return ok(text="Host deleted.") if len(lst) < before else err("Host not deleted (not found).", 3)

    def _reservation_get(self, args):
        sid, id_type, identifier = args["subnet-id"], args["identifier-type"], args["identifier"].lower()
        try:
            for r in self._reservation_list(sid):
                if str(r.get(id_type, "")).lower() == identifier:
                    return ok({**copy.deepcopy(r), "subnet-id": sid})
        except TypeError:
            pass
        idx = self._db_index(sid, id_type, identifier)
        if idx is not None:
            return ok(copy.deepcopy(self.db_hosts[idx]))
        return err("Host not found.", 3)

    def _reservation_get_page(self, args):
        sid = args["subnet-id"]
        try:
            hosts = [{**r, "subnet-id": sid} for r in self._reservation_list(sid)]
        except TypeError:
            hosts = []
        start = int(args.get("from", 0))
        page = hosts[start : start + args["limit"]]
        if not page:
            return err("0 IPv4 host(s) found.", 3)
        return ok({"count": len(page), "hosts": page, "next": {"from": start + len(page), "source-index": 0}})

    def _class_add(self, args):
        self.cfg.setdefault("client-classes", []).extend(args["client-classes"])
        return ok(text="Class added.")

    def _class_update(self, args):
        new = args["client-classes"][0]
        lst = self.cfg["client-classes"]
        lst[next(i for i, c in enumerate(lst) if c["name"] == new["name"])] = new
        return ok(text="Class updated.")

    def _class_del(self, args):
        self.cfg["client-classes"] = [
            c for c in self.cfg.get("client-classes", []) if c["name"] != args["name"]
        ]
        return ok(text="Class deleted.")

    # Leases -----------------------------------------------------------------------------

    def _sorted_leases(self) -> list[dict[str, Any]]:
        return sorted(self.leases, key=lambda lease: ipaddress.ip_address(lease["ip-address"]))

    def _leasen_get_page(self, args):
        leases = self._sorted_leases()
        if args["from"] != "start":
            cursor = ipaddress.ip_address(args["from"])
            leases = [x for x in leases if ipaddress.ip_address(x["ip-address"]) > cursor]
        page = leases[: args["limit"]]
        if not page:
            return err("0 lease(s) found.", 3)
        return ok({"count": len(page), "leases": copy.deepcopy(page)})

    def _leasen_get(self, args):
        for lease in self.leases:
            same_type = self.n == "4" or lease.get("type", "IA_NA") == args.get("type", "IA_NA")
            if lease["ip-address"] == args["ip-address"] and same_type:
                return ok(copy.deepcopy(lease))
        return err("Lease not found.", 3)

    def _leasen_get_by_hw_address(self, args):
        found = [x for x in self.leases if x.get("hw-address") == args["hw-address"]]
        return ok({"count": len(found), "leases": found}) if found else err("0 lease(s) found.", 3)

    def _leasen_get_by_hostname(self, args):
        found = [x for x in self.leases if x.get("hostname") == args["hostname"]]
        return ok({"count": len(found), "leases": found}) if found else err("0 lease(s) found.", 3)

    def _lease6_get_by_duid(self, args):
        found = [x for x in self.leases if x.get("duid") == args["duid"]]
        return ok({"count": len(found), "leases": found}) if found else err("0 lease(s) found.", 3)

    def _leasen_del(self, args):
        before = len(self.leases)
        self.leases = [x for x in self.leases if x["ip-address"] != args["ip-address"]]
        return ok(text="Lease deleted.") if len(self.leases) < before else err("IPv4 lease not found.", 3)

    def _leasen_add(self, args):
        self.leases.append({**args, "cltt": 1792843949, "valid-lft": args.get("valid-lft", 3600)})
        return ok(text="Lease added.")
