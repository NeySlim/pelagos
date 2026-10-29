# SPDX-License-Identifier: Apache-2.0
"""Observed IPv6 addresses over the API (section 27): hosts with their addresses, observation sources.

Observations are merged from this node's cache and every peer's `ipv6.observations`; sources and
watched prefixes are entries of `[settings.ipv6]` written through `update_cluster`, secrets sealed
in `[secrets]` under `ipv6/source/<id>/<name>` and never returned.
"""

from __future__ import annotations

import copy
import ipaddress
import logging
import sqlite3
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

from pelagos.auth.rate_limit import RateLimiter
from pelagos.collector.ipv6 import opnsense
from pelagos.collector.ipv6 import prefixes as prefixes_mod
from pelagos.collector.ipv6 import store as obs_store
from pelagos.collector.ipv6.source import SourceError, normalize_mac
from pelagos.core import settings_registry as reg
from pelagos.domain import AuditEntry, AuditResult, ZoneKind, new_id, normalize_name, to_rfc3339
from pelagos.services import consistency, ipv6_hosts
from pelagos.services.errors import Conflict, NotFound, ServiceError, ValidationError, field_error

log = logging.getLogger(__name__)

DOMAIN = "ipv6"
PEER_ACTION = "ipv6.observations"
PEER_TIMEOUT = 5.0
TESTS_PER_MINUTE = 6
SAMPLE = 5
NAME_MAX = 100
SECRET_MAX = 1024
SOURCE_TYPES = ("opnsense",)
SECRET_NAMES = ("api_key", "api_secret")
SOURCE_FIELDS = ("id", "type", "name", "url", "verify_tls", "ca_pem", "enabled", "allow_http", "exclude_macs")
# Read-only members a client may echo back from a GET: ignored on writes.
ECHOED = ("effective_prefixes", "settings", "status")
FILTERS = ("missing_aaaa", "missing_ptr", "stale", "unknown", "random_mac")
SERVED = (ZoneKind.PRIMARY.value, ZoneKind.SECONDARY.value, ZoneKind.MIRROR.value)


def secret_key(source_id: str, name: str) -> str:
    return f"ipv6/source/{source_id}/{name}"


def _drop_none(value: Any) -> Any:
    """TOML has no null: absent means default."""
    if isinstance(value, dict):
        return {str(k): _drop_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_drop_none(v) for v in value if v is not None]
    return value


def _ts(value: Any) -> str | None:
    if not isinstance(value, int | float) or isinstance(value, bool) or value <= 0:
        return None
    return to_rfc3339(datetime.fromtimestamp(value, tz=UTC))


# Cluster gathering ---------------------------------------------------------------------------


class Gathered:
    """Every node's observations and source statuses; `complete` is false when a node that
    observes did not answer (a node too old to observe counts as answered, with nothing)."""

    def __init__(self) -> None:
        self.observations: list[dict[str, Any]] = []
        self.status: list[dict[str, Any]] = []
        self.unavailable: list[dict[str, Any]] = []
        self.complete = True


def gather(
    node_id: str,
    local: Callable[[], dict[str, Any]],
    peers: Any,
    peer_ids: Iterable[str],
    timeout: float = PEER_TIMEOUT,
) -> Gathered:
    out = Gathered()
    answers: list[tuple[str, dict[str, Any] | ServiceError]] = []
    try:
        answers.append((node_id, local()))
    except ServiceError as exc:
        answers.append((node_id, exc))
    ids = [p for p in dict.fromkeys(peer_ids) if p != node_id]

    def ask(peer_id: str) -> dict[str, Any] | ServiceError:
        peer = peers.peer(peer_id)
        if peer is None:
            return ServiceError("engine_unavailable", f"node {peer_id} is not a known peer")
        try:
            answer = peers.action(peer, PEER_ACTION, {}, timeout=timeout)
        except ServiceError as exc:
            return exc
        if not isinstance(answer, dict):
            return ServiceError("engine_unavailable", f"node {peer_id}: malformed answer")
        return answer

    if ids:
        with ThreadPoolExecutor(max_workers=min(8, len(ids))) as pool:
            answers += list(zip(ids, pool.map(ask, ids), strict=True))
    for nid, answer in answers:
        if isinstance(answer, ServiceError):
            out.unavailable.append({"node_id": nid, "source": "neighbors", "error": answer.detail})
            if answer.code != "not_supported":
                out.complete = False
            continue
        out.observations += [o for o in answer.get("observations") or [] if isinstance(o, dict)]
        out.status += [s for s in answer.get("sources") or [] if isinstance(s, dict)]
    return out


class Ipv6Service:
    def __init__(self, ctx: Any, peers: Any, hosts: Any, cache: Any) -> None:
        self.ctx = ctx
        self.peers = peers
        self.hosts = hosts  # HostsService
        self.cache = cache  # SeriesCache (read-only)
        self.clock: Callable[[], float] = time.time
        self.client: opnsense.Client = opnsense.default_client  # tests replace the HTTP client
        self.test_limiter = RateLimiter(TESTS_PER_MINUTE)

    # Reads ----------------------------------------------------------------------------------

    def _domain(self) -> dict[str, Any]:
        return reg.domain(self.ctx.settings(), DOMAIN)

    def _sources(self) -> list[dict[str, Any]]:
        return [s for s in self._domain().get("sources") or [] if isinstance(s, dict)]

    def _local(self) -> dict[str, Any]:
        conn = self.cache.conn
        try:
            return obs_store.payload(conn, self.ctx.node.id)
        except sqlite3.Error as exc:
            raise ServiceError("engine_unavailable", f"observation cache unreadable: {exc}") from None

    def gathered(self) -> Gathered:
        ids = [n.id for n in self.ctx.cluster().nodes]
        return gather(self.ctx.node.id, self._local, self.peers, ids)

    def _snapshots(self) -> list[dict[str, Any]]:
        conn = self.cache.conn
        if conn is None:
            return []
        try:
            return prefixes_mod.cluster_snapshots(conn)
        except sqlite3.Error:
            return []

    def effective_prefixes(self) -> list[prefixes_mod.Prefix]:
        zones, subnets = prefixes_mod.from_snapshots(self._snapshots())
        listed = self._domain().get("prefixes") or []
        return prefixes_mod.effective(listed if isinstance(listed, list) else [], zones, subnets)

    def _zones(self) -> tuple[list[str], list[str], str | None]:
        """(forward zones, ip6.arpa zones) the cluster serves, or the error that hid them."""
        dns = self.hosts.dns
        if dns is None:
            return [], [], None
        try:
            items = dns.zones()
        except ServiceError as exc:
            return [], [], exc.detail
        names = [i["zone"]["name"] for i in items if i["zone"]["kind"] in SERVED]
        forward = [n for n in names if not n.endswith(("in-addr.arpa.", "ip6.arpa."))]
        return forward, [n for n in names if n.endswith("ip6.arpa.")], None

    def hosts_list(
        self, filter_: str | None, zone: str | None
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        if filter_ is not None and filter_ not in FILTERS:
            raise ValidationError("invalid filter", [field_error("filter", "one of " + ", ".join(FILTERS))])
        settings = self.ctx.settings()
        now = int(self.clock())
        stable = int(reg.get(settings, "ipv6.stable_min_days"))
        g = self.gathered()
        hosts, errors = self.hosts.collect()
        forward, reverse, zones_error = self._zones()
        if zones_error:
            errors["dns"] = zones_error
        excepted = consistency.excepted_for(self.ctx.cluster())
        rows = ipv6_hosts.host_rows(hosts, g.observations, now, stable, forward, reverse, excepted)
        if filter_ == "stale":
            watched = self.effective_prefixes()
            found = ipv6_hosts.stale_records(
                hosts,
                g.observations,
                now,
                stable,
                int(reg.get(settings, "ipv6.stale_days")),
                forward,
                lambda a: prefixes_mod.watched(a, watched),
                excepted,
            )
            keys = {s.host_key for s in found}
            rows = [r for r in rows if r["host_key"] in keys]
        elif filter_ == "missing_aaaa":
            rows = [r for r in rows if ipv6_hosts.missing_aaaa(r)]
        elif filter_ == "missing_ptr":
            rows = [r for r in rows if set(r["aaaa"]) - set(r["ptr"])]
        elif filter_ == "unknown":
            rows = [r for r in rows if not r["name"]]
        elif filter_ == "random_mac":
            rows = [r for r in rows if r["mac_random"]]
        if zone:
            z = normalize_name(zone)
            rows = [
                r
                for r in rows
                if (r["proposal"] or {}).get("zone") == z
                or (r["name"] and (r["name"] == z or r["name"].endswith("." + z)))
            ]
        for row in rows:
            for o in row["observed"]:
                o["first_seen"], o["last_seen"] = _ts(o["first_seen"]), _ts(o["last_seen"])
        meta: dict[str, Any] = {"unavailable": g.unavailable}
        if errors:
            meta["errors"] = errors
        return rows, meta

    def public_source(self, source: dict[str, Any]) -> dict[str, Any]:
        sid = str(source.get("id") or "")
        stored = self.ctx.cluster().secrets
        return {
            "id": sid,
            "type": source.get("type"),
            "name": str(source.get("name") or ""),
            "url": str(source.get("url") or ""),
            "verify_tls": source.get("verify_tls", True) is not False,
            "ca_pem": source.get("ca_pem") or None,
            "enabled": source.get("enabled", True) is not False,
            "allow_http": source.get("allow_http") is True,
            "exclude_macs": list(source.get("exclude_macs") or []),
            "secrets": {n: secret_key(sid, n) in stored for n in SECRET_NAMES},
        }

    def overview(self) -> dict[str, Any]:
        settings = self.ctx.settings()
        g = self.gathered()
        status = [{**s, "last_poll": _ts(s.get("last_poll"))} for s in g.status]
        status += [
            {
                "source": u["source"],
                "source_id": None,
                "node_id": u["node_id"],
                "last_poll": None,
                "error": u["error"],
                "entries": 0,
            }
            for u in g.unavailable
        ]
        listed = self._domain().get("prefixes") or []
        return {
            "sources": [self.public_source(s) for s in self._sources()],
            "prefixes": [str(p) for p in listed] if isinstance(listed, list) else [],
            "effective_prefixes": [p.to_dict() for p in self.effective_prefixes()],
            "settings": {s.path[1]: reg.get(settings, s.key) for s in reg.REGISTRY if s.domain == DOMAIN},
            "status": status,
        }

    # Writes ---------------------------------------------------------------------------------

    @staticmethod
    def _raise(errors: list[dict[str, str]], what: str) -> None:
        if errors:
            fields = ", ".join(dict.fromkeys(e["field"] for e in errors))
            raise ValidationError(f"invalid {what}: {fields}", errors)

    def _check_source(
        self, raw: Any, field: str, known: dict[str, dict[str, Any]], errors: list[dict[str, str]]
    ) -> dict[str, Any]:
        if not isinstance(raw, dict):
            errors.append(field_error(field, "object expected"))
            return {}
        for key in sorted(set(raw) - set(SOURCE_FIELDS) - {"secrets", "scope"}):
            errors.append(field_error(f"{field}.{key}", "unknown field"))
        sid = raw.get("id")
        if sid in (None, ""):
            sid = new_id()
        elif not isinstance(sid, str) or sid not in known:
            errors.append(field_error(f"{field}.id", "unknown source: leave id out for a new one"))
        out: dict[str, Any] = {"id": sid}
        if raw.get("type") not in SOURCE_TYPES:
            errors.append(field_error(f"{field}.type", "one of " + ", ".join(SOURCE_TYPES)))
        out["type"] = raw.get("type")
        name = raw.get("name")
        if not isinstance(name, str) or not name.strip() or len(name) > NAME_MAX:
            errors.append(field_error(f"{field}.name", f"1 to {NAME_MAX} characters"))
        out["name"] = name.strip() if isinstance(name, str) else name
        for flag, default in (("verify_tls", True), ("enabled", True), ("allow_http", False)):
            value = raw.get(flag, default)
            if not isinstance(value, bool):
                errors.append(field_error(f"{field}.{flag}", "boolean expected"))
            out[flag] = value
        url = raw.get("url")
        try:
            opnsense.endpoint(url if isinstance(url, str) else "", out["allow_http"] is True)
        except SourceError as exc:
            errors.append(field_error(f"{field}.url", exc.message))
        out["url"] = url.strip() if isinstance(url, str) else url
        ca = raw.get("ca_pem")
        if ca not in (None, ""):
            try:
                if not isinstance(ca, str):
                    raise SourceError("PEM text expected")
                opnsense.tls_context(True, ca)
            except SourceError as exc:
                errors.append(field_error(f"{field}.ca_pem", exc.message))
        out["ca_pem"] = ca or None
        macs = raw.get("exclude_macs") or []
        clean: list[str] = []
        if not isinstance(macs, list):
            errors.append(field_error(f"{field}.exclude_macs", "list of MAC addresses expected"))
        else:
            for m in macs:
                mac = normalize_mac(m)
                if mac is None:
                    errors.append(field_error(f"{field}.exclude_macs", f"not a MAC address: {m}"))
                elif mac not in clean:
                    clean.append(mac)
        out["exclude_macs"] = clean
        return out

    @staticmethod
    def _check_prefixes(raw: Any, errors: list[dict[str, str]]) -> list[str]:
        if not isinstance(raw, list):
            errors.append(field_error("prefixes", "list of IPv6 prefixes expected"))
            return []
        out: list[str] = []
        for value in raw:
            try:
                net = (
                    ipaddress.IPv6Network(str(value).strip(), strict=False)
                    if isinstance(value, str)
                    else None
                )
            except ValueError:
                net = None
            if net is None or "/" not in str(value):
                errors.append(field_error("prefixes", f"not an IPv6 prefix: {value}"))
            elif net.prefixlen == 0 or net.overlaps(prefixes_mod.LINK_LOCAL) or net.is_multicast:
                errors.append(
                    field_error("prefixes", f"not a watched prefix (link-local, multicast or ::/0): {value}")
                )
            elif str(net) not in out:
                out.append(str(net))
        return out

    @staticmethod
    def _check_secrets(raw: Any, errors: list[dict[str, str]]) -> dict[str, dict[str, str | None]]:
        if raw is None:
            return {}
        if not isinstance(raw, dict):
            errors.append(field_error("secrets", "object of source id to secrets expected"))
            return {}
        out: dict[str, dict[str, str | None]] = {}
        for sid, values in raw.items():
            if not isinstance(values, dict):
                errors.append(field_error(f"secrets.{sid}", "object expected"))
                continue
            for name, value in values.items():
                if name not in SECRET_NAMES:
                    errors.append(field_error(f"secrets.{sid}.{name}", "unknown secret"))
                elif value is not None and (
                    not isinstance(value, str) or not value or len(value) > SECRET_MAX
                ):
                    errors.append(
                        field_error(f"secrets.{sid}.{name}", f"1 to {SECRET_MAX} characters or null")
                    )
                else:
                    out.setdefault(str(sid), {})[name] = value
        return out

    def replace(self, body: dict[str, Any], actor: str, client_ip: str | None) -> dict[str, Any]:
        errors: list[dict[str, str]] = []
        for key in sorted(set(body) - {"sources", "prefixes", "secrets"} - set(ECHOED)):
            errors.append(field_error(key, "unknown field"))
        known = {str(s.get("id")): s for s in self._sources() if s.get("id")}
        sources: list[dict[str, Any]] | None = None
        if "sources" in body:
            if not isinstance(body["sources"], list):
                errors.append(field_error("sources", "list expected"))
            else:
                sources = [
                    self._check_source(s, f"sources[{i}]", known, errors)
                    for i, s in enumerate(body["sources"])
                ]
                ids = [s.get("id") for s in sources]
                if len(set(ids)) != len(ids):
                    errors.append(field_error("sources", "a source id appears twice"))
        prefixes = self._check_prefixes(body["prefixes"], errors) if "prefixes" in body else None
        secrets = self._check_secrets(body.get("secrets"), errors)
        final = sources if sources is not None else [dict(s) for s in known.values()]
        final_ids = {str(s.get("id")) for s in final}
        for sid in secrets:
            if sid not in final_ids:
                errors.append(field_error(f"secrets.{sid}", "unknown source"))
        self._raise(errors, "IPv6 sources")
        # A stored key never follows a source to another URL: it is cleared unless given again.
        moved = {
            str(s["id"])
            for s in final
            if str(s["id"]) in known and str(known[str(s["id"])].get("url") or "") != str(s.get("url") or "")
        }
        box = self.ctx.secrets
        if box is None and any(v is not None for vals in secrets.values() for v in vals.values()):
            raise Conflict("no master key on this node: secrets cannot be stored")

        def apply(cluster: Any) -> None:
            domain = cluster.settings.setdefault(DOMAIN, {})
            if sources is not None:
                domain["sources"] = [_drop_none(copy.deepcopy(s)) for s in sources]
            if prefixes is not None:
                domain["prefixes"] = list(prefixes)
            for name in list(cluster.secrets):
                if not name.startswith("ipv6/source/"):
                    continue
                sid = name.split("/")[2]
                if sid not in final_ids or (sid in moved and name.split("/")[-1] not in secrets.get(sid, {})):
                    cluster.secrets.pop(name, None)
            for sid, values in secrets.items():
                for name, value in values.items():
                    key = secret_key(sid, name)
                    if value is None:
                        cluster.secrets.pop(key, None)
                    else:
                        cluster.secrets[key] = box.encrypt(key, value)

        self.ctx.config_store.update_cluster(apply, updated_by=f"user:{actor}@node:{self.ctx.node.id}")
        listed = self._domain().get("prefixes") or []
        self.ctx.audit_log.append(
            AuditEntry(
                node_id=self.ctx.node.id,
                user=actor,
                action="admin.ipv6.replace",
                target="ipv6",
                request={"sources": sorted(final_ids), "prefixes": list(listed)},
                response={"ok": True},
                result=AuditResult.OK,
                client_ip=client_ip,
            )
        )
        return self.overview()

    def test(self, body: dict[str, Any], actor: str) -> dict[str, Any]:
        """One poll of a source from this node, saved or not; a failed poll is `ok` false."""
        errors: list[dict[str, str]] = []
        known = {str(s.get("id")): s for s in self._sources() if s.get("id")}
        if body.get("source_id"):
            sid = str(body["source_id"])
            if sid not in known:
                raise NotFound(f"source {sid}")
            source = known[sid]
            secrets = {n: self.ctx.get_secret(secret_key(sid, n)) for n in SECRET_NAMES}
        else:
            scope = body.get("scope")
            given = self._check_secrets({"test": body.get("secrets") or {}}, errors).get("test", {})
            raw = {k: v for k, v in body.items() if k not in ("scope", "secrets", "id")}
            source = self._check_source(raw, "source", {}, errors)
            self._raise(errors, "IPv6 source")
            secrets = {}
            if scope:
                saved = known.get(str(scope))
                if saved is None:
                    raise NotFound(f"source {scope}")
                if str(saved.get("url") or "") == str(source.get("url") or ""):
                    secrets = {n: self.ctx.get_secret(secret_key(str(scope), n)) for n in SECRET_NAMES}
            for name, value in given.items():
                secrets[name] = value
        src = opnsense.OpnsenseSource(
            str(source.get("url") or ""),
            secrets.get("api_key"),
            secrets.get("api_secret"),
            verify_tls=source.get("verify_tls", True) is not False,
            ca_pem=source.get("ca_pem") or None,
            client=self.client,
            allow_http=source.get("allow_http") is True,
            exclude_macs=source.get("exclude_macs") or (),
        )
        node_id = self.ctx.node.id
        try:
            found = src.poll()
        except SourceError as exc:
            return {"ok": False, "node_id": node_id, "entries": 0, "error": exc.message, "sample": []}
        now = _ts(self.clock())
        sample = [
            {
                "mac": n.mac,
                "address": n.address,
                "source": src.kind,
                "source_id": str(body.get("source_id") or body.get("scope") or "") or None,
                "node_id": node_id,
                "first_seen": now,
                "last_seen": now,
                "state": n.state,
            }
            for n in found[:SAMPLE]
        ]
        return {"ok": True, "node_id": node_id, "entries": len(found), "sample": sample}
