# SPDX-License-Identifier: Apache-2.0
"""In-process imitation of the Hetzner Cloud DNS API, after its OpenAPI description
(https://docs.hetzner.cloud/cloud.spec.json, fetched 2026-10-26): Bearer token, zones looked up by
name, RRSets addressed by relative name and type, records changed only through the add_records and
remove_records actions, which answer 201 with a running action read back on GET /actions/{id}.
Errors carry {"error": {"code", "message", "details"}}. There is no PATCH on an RRSet."""

from __future__ import annotations

import itertools
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from pelagos.core.webcert import http

BASE = "https://api.hetzner.cloud/v1"
RRSET = re.compile(r"^/zones/([^/]+)/rrsets/([^/]+)/([A-Z]+)$")
ACTION = re.compile(r"^/zones/([^/]+)/rrsets/([^/]+)/([A-Z]+)/actions/(add_records|remove_records)$")


@dataclass
class HetznerCloudMock:
    token: str
    zones: list[dict[str, Any]] = field(default_factory=list)
    rrsets: dict[tuple[int, str, str], dict[str, Any]] = field(default_factory=dict)
    actions: dict[int, dict[str, Any]] = field(default_factory=dict)
    calls: list[tuple[str, str, Any]] = field(default_factory=list)
    fail_next_action: str | None = None
    _ids: Any = field(default_factory=lambda: itertools.count(1001))

    def add_zone(self, name: str) -> dict[str, Any]:
        zone = {"id": next(self._ids), "name": name, "mode": "primary", "ttl": 3600, "status": "ok"}
        self.zones.append(zone)
        return zone

    def records(self, zone: str, name: str, rtype: str = "TXT") -> list[str] | None:
        z = next(z for z in self.zones if z["name"] == zone)
        rrset = self.rrsets.get((z["id"], name, rtype))
        return None if rrset is None else [r["value"] for r in rrset["records"]]

    # Transport ---------------------------------------------------------------------------------

    def __call__(
        self, method: str, url: str, *, body: Any = None, headers: dict[str, str] | None = None, **_kw: Any
    ) -> http.Response:
        assert url.startswith(BASE), url
        parts = urlsplit(url[len(BASE) :])
        self.calls.append((method, parts.path + (f"?{parts.query}" if parts.query else ""), body))
        if (headers or {}).get("Authorization") != f"Bearer {self.token}":
            return self._error(401, "unauthorized", "unable to authenticate")
        query = {k: v[-1] for k, v in parse_qs(parts.query).items()}
        path = parts.path
        if method == "GET" and path == "/zones":
            return self._list_zones(query)
        if method == "GET" and path.startswith("/actions/"):
            return self._get_action(int(path.rsplit("/", 1)[1]))
        m = RRSET.match(path)
        if m and method == "GET":
            return self._get_rrset(*m.groups())
        m = ACTION.match(path)
        if m and method == "POST":
            return self._rrset_action(*m.groups(), body or {})
        return self._error(404, "not_found", f"no route {method} {path}")

    def _json(self, status: int, data: Any) -> http.Response:
        return http.Response(status, {"content-type": "application/json"}, json.dumps(data).encode())

    def _error(self, status: int, code: str, message: str) -> http.Response:
        return self._json(status, {"error": {"code": code, "message": message, "details": {}}})

    def _zone(self, id_or_name: str) -> dict[str, Any] | None:
        key = unquote(id_or_name)
        return next((z for z in self.zones if str(z["id"]) == key or z["name"] == key), None)

    def _list_zones(self, query: dict[str, str]) -> http.Response:
        zones = [z for z in self.zones if "name" not in query or z["name"] == query["name"]]
        per_page = int(query.get("per_page", 25))
        if per_page > 100:
            return self._error(400, "invalid_input", "per_page must be at most 100")
        page = int(query.get("page", 1))
        shown = zones[(page - 1) * per_page : page * per_page]
        last = max(1, -(-len(zones) // per_page))
        pagination = {
            "page": page,
            "per_page": per_page,
            "previous_page": page - 1 if page > 1 else None,
            "next_page": page + 1 if page < last else None,
            "last_page": last,
            "total_entries": len(zones),
        }
        return self._json(200, {"zones": shown, "meta": {"pagination": pagination}})

    def _check_name(self, zone: dict[str, Any], rr_name: str) -> str | None:
        name = unquote(rr_name)
        if name != name.lower() or name.endswith(".") or name.endswith(zone["name"]):
            return f"invalid RRSet name {name!r}: lower case, relative to the zone, no final dot"
        return None

    def _get_rrset(self, zid: str, rr_name: str, rtype: str) -> http.Response:
        zone = self._zone(zid)
        if zone is None:
            return self._error(404, "not_found", "zone not found")
        rrset = self.rrsets.get((zone["id"], unquote(rr_name), rtype))
        if rrset is None:
            return self._error(404, "not_found", "rrset not found")
        return self._json(200, {"rrset": rrset})

    def _action(self, command: str, zone: dict[str, Any]) -> http.Response:
        action_id = next(self._ids)
        error = None
        if self.fail_next_action:
            error, self.fail_next_action = {"code": "action_failed", "message": self.fail_next_action}, None
        self.actions[action_id] = {
            "id": action_id,
            "command": command,
            "status": "error" if error else "success",
            "progress": 100,
            "started": "2026-10-26T12:00:00Z",
            "finished": "2026-10-26T12:00:01Z",
            "resources": [{"id": zone["id"], "type": "zone"}],
            "error": error,
        }
        running = {**self.actions[action_id], "status": "running", "progress": 0, "finished": None}
        running["error"] = None
        return self._json(201, {"action": running})

    def _get_action(self, action_id: int) -> http.Response:
        action = self.actions.get(action_id)
        if action is None:
            return self._error(404, "not_found", "action not found")
        return self._json(200, {"action": action})

    def _rrset_action(
        self, zid: str, rr_name: str, rtype: str, verb: str, body: dict[str, Any]
    ) -> http.Response:
        zone = self._zone(zid)
        if zone is None:
            return self._error(404, "not_found", "zone not found")
        bad = self._check_name(zone, rr_name)
        if bad:
            return self._error(400, "invalid_input", bad)
        allowed = {"records", "ttl"} if verb == "add_records" else {"records"}
        records = body.get("records")
        if set(body) - allowed or not isinstance(records, list) or not 1 <= len(records) <= 50:
            return self._error(400, "invalid_input", f"invalid body for {verb}")
        values = [r.get("value") for r in records if isinstance(r, dict) and set(r) <= {"value", "comment"}]
        if len(values) != len(records) or len(set(values)) != len(values):
            return self._error(400, "invalid_input", "records must be distinct {value, comment} objects")
        key = (zone["id"], unquote(rr_name), rtype)
        rrset = self.rrsets.get(key)
        if verb == "add_records":
            ttl = body.get("ttl")
            if rrset is None:
                self.rrsets[key] = rrset = {
                    "id": f"{key[1]}/{rtype}",
                    "name": key[1],
                    "type": rtype,
                    "ttl": ttl,
                    "labels": {},
                    "protection": {"change": False},
                    "records": [],
                    "zone": zone["id"],
                }
            elif ttl is not None and ttl != rrset["ttl"]:
                return self._error(422, "invalid_input", "ttl differs from the RRSet's ttl")
            if any(r["value"] in values for r in rrset["records"]):
                return self._error(422, "invalid_input", "record already in the RRSet")
            rrset["records"].extend({"value": v} for v in values)
            return self._action("add_rrset_records", zone)
        if rrset is None:
            return self._error(404, "not_found", "rrset not found")
        present = {r["value"] for r in rrset["records"]}
        if not set(values) <= present:
            return self._error(422, "invalid_input", "record not in the RRSet")
        rrset["records"] = [r for r in rrset["records"] if r["value"] not in values]
        if not rrset["records"]:
            del self.rrsets[key]
        return self._action("remove_rrset_records", zone)
