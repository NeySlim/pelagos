# SPDX-License-Identifier: Apache-2.0
"""RPZ subscriptions across nodes: catalog and categories, subscriptions, allow list, why, activity.

The desired state lives in `settings.rpz` (replicated); the BIND side is one plan (`rpz/state`) that
every node renders for itself; list content is downloaded by each node's collector.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from pelagos.core.signals import signal_collector
from pelagos.domain import AuditEntry, AuditResult, Change, ChangeOp, Engine, Plan, normalize_name
from pelagos.rpz import catalog, estimate, model
from pelagos.rpz.model import RpzInputError
from pelagos.services.errors import EngineUnavailable, NotFound, ValidationError, field_error
from pelagos.services.masking import masked

DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_-]{1,63}\.)*[a-z0-9_-]{1,63}$")


class RpzService:
    def __init__(self, ctx: Any, dns: Any, peers: Any) -> None:
        self.ctx = ctx
        self.dns = dns
        self.peers = peers

    # Settings ------------------------------------------------------------------------

    def _cfg(self) -> dict[str, Any]:
        return model.config(self.ctx.settings())

    def _by(self, user: str) -> str:
        return f"user:{user}@node:{self.ctx.node.id}"

    def _update(self, user: str, mutate: Any) -> None:
        def apply(cluster: Any) -> None:
            rpz = cluster.settings.setdefault("rpz", {})
            mutate(rpz, cluster)

        self.ctx.config_store.update_cluster(apply, updated_by=self._by(user))

    def _audit(
        self, action: str, target: str, user: str, request: dict[str, Any], client_ip: str | None
    ) -> None:
        self.ctx.audit_log.append(
            AuditEntry(
                node_id=self.ctx.node.id,
                user=user,
                action=action,
                target=target,
                request=masked(request),
                response={"ok": True},
                result=AuditResult.OK,
                client_ip=client_ip,
            )
        )

    @staticmethod
    def _input(fn: Any, *args: Any) -> Any:
        try:
            return fn(*args)
        except RpzInputError as exc:
            raise ValidationError(str(exc), [field_error(exc.field or "body", str(exc))]) from exc

    # Nodes ---------------------------------------------------------------------------

    def bind_nodes(self) -> list[Any]:
        return [p for p in self.ctx.cluster().nodes if p.modules.bind]

    def _node_state(self, node_id: str) -> dict[str, Any]:
        """The collector's RPZ state of a node and its memory, from the node itself."""
        if node_id == self.ctx.node.id:
            if self.dns.local is None:
                return {"error": "this node does not run BIND"}
            return self.dns.local.rpz_node_state()
        peer = self.peers.peer(node_id)
        snap = self.peers.snapshot(peer, Engine.BIND, "rpz") if peer else None
        if snap is None or snap.get("error"):
            return {"error": (snap or {}).get("error") or "unreachable"}
        return {"state": snap.get("state") or {}, "ram_mb": snap.get("ram_mb")}

    def _configured_zones(self, node_id: str) -> list[str] | None:
        try:
            return [i["zone"].rstrip(".") for i in self.dns.rpz(node_id)]
        except Exception:
            return None

    # Reads ---------------------------------------------------------------------------

    def catalog(self) -> dict[str, Any]:
        data = catalog.load()
        cats = {}
        for cat_id, cat in data["categories"].items():
            cats[cat_id] = {
                "icon": cat.get("icon"),
                "levels": catalog.category_summary(cat_id),
                "lists": cat["lists"],
                "addons": cat.get("addons", []),
            }
        return {
            "version": data["version"],
            "note": data.get("note", ""),
            "lists": data["lists"],
            "categories": cats,
        }

    def overview(self) -> dict[str, Any]:
        settings = self.ctx.settings()
        cfg = model.config(settings)
        subs = model.resolve(settings)
        nodes = []
        states: dict[str, dict[str, Any]] = {}
        for peer in self.bind_nodes():
            state = self._node_state(peer.id)
            states[peer.id] = state
            mine = model.for_node(subs, peer.id)
            wanted = {model.ALLOW_ZONE, *[s.zone for s in mine]} if mine else set()
            configured = self._configured_zones(peer.id)
            have = set(configured or [])
            # Zones to add, or ours (by name) that should no longer be there.
            pending = configured is not None and bool(
                wanted - have or {z for z in have if z.endswith(model.ZONE_SUFFIX)} - wanted
            )
            nodes.append(
                {
                    "id": peer.id,
                    "name": peer.name,
                    "ram_mb": state.get("ram_mb"),
                    "error": state.get("error"),
                    "pending": pending,
                    "log": (state.get("state") or {}).get("log", {}).get("path"),
                }
            )
        out_subs = []
        for sub in subs:
            row = sub.to_dict()
            row["status"] = {
                n["id"]: (states[n["id"]].get("state") or {}).get("subs", {}).get(sub.id)
                for n in nodes
                if sub.on_node(n["id"]) or sub.nodes is None
            }
            out_subs.append(row)
        return {
            "catalog": self.catalog(),
            "categories": cfg["categories"],
            "subscriptions": out_subs,
            "order": [s.id for s in subs],
            "allow": cfg["allow"],
            "exempt_clients": cfg["exempt_clients"],
            "nodes": nodes,
            "settings": {
                k: cfg[k]
                for k in (
                    "check_seconds",
                    "default_interval_hours",
                    "shrink_percent",
                    "bytes_per_entry",
                    "memory_warn_percent",
                    "small_node_mb",
                    "break_dnssec",
                )
            },
            "allow_zone": model.ALLOW_ZONE,
        }

    def estimate(self, body: dict[str, Any]) -> dict[str, Any]:
        """Memory per node if the given lists were subscribed on top of what is subscribed there."""
        cfg = self._cfg()
        lists = catalog.lists()
        category = body.get("category")
        if category:
            entry = self._input(model.clean_category, category, {**body, "enabled": True})
            added = model.category_lists(entry, category)
        else:
            added = [str(i) for i in body.get("lists") or []]
        unknown = [i for i in added if i not in lists]
        if unknown:
            raise ValidationError(f"unknown lists: {', '.join(unknown)}", [field_error("lists", "unknown")])
        extra = int(body.get("extra_entries") or 0)
        wanted_nodes = body.get("node_ids") or None
        subs = [s for s in model.resolve(self.ctx.settings()) if s.enabled]
        out = []
        for node in self.bind_nodes():
            if wanted_nodes and node.id not in wanted_nodes:
                continue
            state = self._node_state(node.id)
            current = {s.id: self._entries(s, state) for s in model.for_node(subs, node.id)}
            sizes = list(current.values())
            new = [lists[i]["entries"] for i in added if i not in current]
            result = estimate.assess(sizes + new + ([extra] if extra else []), state.get("ram_mb"), cfg)
            current_only = estimate.assess(sizes, state.get("ram_mb"), cfg)
            out.append({"node_id": node.id, "name": node.name, "current": current_only, **result})
        entries = sum(lists[i]["entries"] for i in added)
        return {
            "lists": added,
            "entries": entries,
            "memory_mb": estimate.entries_mb(entries, int(cfg["bytes_per_entry"])),
            "nodes": out,
        }

    @staticmethod
    def _entries(sub: model.Sub, state: dict[str, Any]) -> int:
        seen = ((state.get("state") or {}).get("subs") or {}).get(sub.id) or {}
        return int(seen.get("entries") or sub.entries_hint or 0)

    def activity(self) -> dict[str, Any]:
        """Rewrite counters per list and category, and the latest rewritten answers, per node."""
        subs = {s.id: s for s in model.resolve(self.ctx.settings())}
        nodes = []
        by_list: dict[str, int] = {}
        by_category: dict[str, int] = {}
        recent: list[dict[str, Any]] = []
        for peer in self.bind_nodes():
            state = (self._node_state(peer.id).get("state") or {}).get("log") or {}
            nodes.append(
                {"id": peer.id, "name": peer.name, "log": state.get("path"), "since": state.get("since")}
            )
            for list_id, counter in (state.get("by_list") or {}).items():
                by_list[list_id] = by_list.get(list_id, 0) + int(counter.get("hits", 0))
            for category, hits in (state.get("by_category") or {}).items():
                by_category[category] = by_category.get(category, 0) + int(hits)
            recent.extend({**e, "node_id": peer.id} for e in state.get("recent") or [])
        recent.sort(key=lambda e: e.get("time", ""), reverse=True)
        return {
            "nodes": nodes,
            "by_list": [
                {
                    "list": i,
                    "name": subs[i].name if i in subs else (i if i != model.ALLOW_ID else "allow"),
                    "category": subs[i].category if i in subs else None,
                    "hits": n,
                }
                for i, n in sorted(by_list.items(), key=lambda kv: -kv[1])
            ],
            "by_category": [
                {"category": c, "hits": n} for c, n in sorted(by_category.items(), key=lambda kv: -kv[1])
            ],
            "recent": recent[:200],
        }

    def why(self, domain: str, node_id: str | None = None) -> dict[str, Any]:
        """Which rule of which list answers for a name, in response-policy order, on this node."""
        name = domain.strip().rstrip(".").lower()
        if not DOMAIN.match(name):
            raise ValidationError("domain is not a valid name", [field_error("domain", "invalid")])
        backend = self.dns.local
        if backend is None or node_id not in (None, self.ctx.node.id):
            raise EngineUnavailable("run this lookup on a node that runs BIND (this node)")
        settings = self.ctx.settings()
        subs = model.for_node(model.resolve(settings), self.ctx.node.id)
        by_zone = {s.zone: s for s in subs}
        ordered = [model.ALLOW_ZONE, *[s.zone for s in subs]]
        labels = name.split(".")
        matches = []
        for zone in ordered:
            hit = self._lookup(backend, zone, labels)
            if hit is None:
                continue
            sub = by_zone.get(zone)
            rule, kind, target = hit
            matches.append(
                {
                    "zone": zone,
                    "list": sub.id if sub else model.ALLOW_ID,
                    "name": sub.name if sub else "allow",
                    "category": sub.category if sub else None,
                    "rule": rule,
                    "match": kind,
                    "passthru": target.rstrip(".") == "rpz-passthru"
                    or (sub is not None and sub.action == "passthru"),
                    "action": sub.action if sub else "passthru",
                    "applied": not matches,
                }
            )
        if not matches:
            verdict = "not_listed"
        elif matches[0]["passthru"]:
            verdict = "allowed"
        else:
            verdict = "blocked"
        return {"domain": name, "verdict": verdict, "matches": matches}

    @staticmethod
    def _lookup(backend: Any, zone: str, labels: list[str]) -> tuple[str, str, str] | None:
        """(rule, "exact" | "wildcard", target) of the rule of `zone` that matches the name.

        A rule `P` covers P only and `*.P` its subdomains, so one query for `<name>.<zone>` finds any
        match (the server synthesizes wildcard answers); the literal wildcard names say which rule it was.
        """

        def ask(owner: str) -> list[str] | None:
            return backend.dns.query(normalize_name(f"{owner}.{zone}"), "CNAME")

        try:
            answer = ask(".".join(labels))
            if not answer:
                return None
            for i in range(1, len(labels)):
                parent = ".".join(labels[i:])
                if ask(f"*.{parent}"):
                    return f"*.{parent}", "wildcard", answer[0]
        except Exception:
            return None
        return ".".join(labels), "exact", answer[0]

    # Plan ----------------------------------------------------------------------------

    def _state_change(self) -> Change:
        settings = self.ctx.settings()
        cfg = model.config(settings)
        subs = []
        for sub in model.resolve(settings):
            row = sub.to_dict()
            if sub.kind == "axfr" and sub.tsig_key:
                row["tsig_secret"] = self.ctx.get_secret(f"rpz/tsig/{sub.id}") or ""
            subs.append(row)
        allow = {
            "domains": sorted(a["domain"] for a in cfg["allow"] if a.get("domain")),
            "clients": sorted(c["cidr"] for c in cfg["exempt_clients"] if c.get("cidr")),
        }
        after = {"subs": subs, "allow": allow, "break_dnssec": bool(cfg["break_dnssec"]), "log": True}
        return Change(ChangeOp.REPLACE, "rpz/state", after=after)

    def plan(self, created_by: str) -> Plan | None:
        """The BIND change that brings every node to the subscriptions; None when nothing differs."""
        backend = self.dns._local()
        plan = backend.plan_config_change([self._state_change()], created_by)
        if plan.validations and any(v.output == "no change" for v in plan.validations):
            return None
        plan.target_node_ids = self.dns._target_nodes([p.id for p in self.bind_nodes()])
        return self.dns._store(plan)

    def _result(self, user: str) -> dict[str, Any]:
        plan = self.plan(user)
        return {"plan": plan, "overview": self.overview()}

    # Writes ---------------------------------------------------------------------------

    def set_category(
        self, category: str, body: dict[str, Any], user: str, client_ip: str | None
    ) -> dict[str, Any]:
        entry = self._input(model.clean_category, category, body)
        self._update(user, lambda rpz, _c: rpz.setdefault("categories", {}).__setitem__(category, entry))
        self._audit("rpz.category.set", f"rpz:category:{category}", user, entry, client_ip)
        return self._result(user)

    def clear_category(self, category: str, user: str, client_ip: str | None) -> dict[str, Any]:
        if category not in catalog.categories():
            raise NotFound(f"category {category}")
        self._update(user, lambda rpz, _c: (rpz.get("categories") or {}).pop(category, None))
        self._audit("rpz.category.delete", f"rpz:category:{category}", user, {}, client_ip)
        return self._result(user)

    def put_subscription(
        self, sub_id: str, body: dict[str, Any], user: str, client_ip: str | None
    ) -> dict[str, Any]:
        taken = {s.zone for s in model.resolve(self.ctx.settings()) if s.id != sub_id}
        entry = self._input(model.clean_subscription, sub_id, body, taken)
        secret = body.get("tsig_secret")
        if entry["kind"] == "axfr" and entry["tsig_key"]:
            if not secret and not self.ctx.get_secret(f"rpz/tsig/{sub_id}"):
                raise ValidationError("the TSIG secret is required", [field_error("tsig_secret", "required")])
            if secret and self.ctx.secrets is None:
                raise ValidationError("the master key is not available to seal the secret")

        def mutate(rpz: dict[str, Any], cluster: Any) -> None:
            rpz.setdefault("subscriptions", {})[sub_id] = entry
            if secret:
                cluster.secrets[f"rpz/tsig/{sub_id}"] = self.ctx.secrets.encrypt(
                    f"rpz/tsig/{sub_id}", str(secret)
                )

        self._update(user, mutate)
        self._audit(
            "rpz.subscription.set",
            f"rpz:subscription:{sub_id}",
            user,
            {**entry, "tsig_secret": secret},
            client_ip,
        )
        return self._result(user)

    def delete_subscription(self, sub_id: str, user: str, client_ip: str | None) -> dict[str, Any]:
        if sub_id not in (self._cfg()["subscriptions"] or {}):
            raise NotFound(f"subscription {sub_id}")

        def mutate(rpz: dict[str, Any], cluster: Any) -> None:
            rpz.get("subscriptions", {}).pop(sub_id, None)
            cluster.secrets.pop(f"rpz/tsig/{sub_id}", None)

        self._update(user, mutate)
        self._audit("rpz.subscription.delete", f"rpz:subscription:{sub_id}", user, {}, client_ip)
        return self._result(user)

    def set_order(self, order: Any, user: str, client_ip: str | None) -> dict[str, Any]:
        known = {s.id for s in model.resolve(self.ctx.settings())}
        if not isinstance(order, list) or any(i not in known for i in order):
            raise ValidationError("order must list subscription ids", [field_error("order", "unknown id")])
        self._update(user, lambda rpz, _c: rpz.__setitem__("order", list(dict.fromkeys(order))))
        self._audit("rpz.order.set", "rpz:order", user, {"order": order}, client_ip)
        return self._result(user)

    # Exceptions ---------------------------------------------------------------------------

    def allow(self, domain: str, note: str, user: str, client_ip: str | None) -> dict[str, Any]:
        name = str(domain or "").strip().rstrip(".").lower().removeprefix("*.")
        if not DOMAIN.match(name):
            raise ValidationError("domain is not a valid name", [field_error("domain", "invalid")])
        entry = {
            "domain": name,
            "note": str(note or "")[:200],
            "by": user,
            "at": datetime.now(UTC).isoformat(),
        }

        def mutate(rpz: dict[str, Any], _c: Any) -> None:
            rows = [a for a in rpz.get("allow", []) if a.get("domain") != name]
            rpz["allow"] = [*rows, entry]

        self._update(user, mutate)
        self._audit("rpz.allow.add", f"rpz:allow:{name}", user, entry, client_ip)
        return self._applied()

    def disallow(self, domain: str, user: str, client_ip: str | None) -> dict[str, Any]:
        name = str(domain).strip().rstrip(".").lower()
        if not any(a.get("domain") == name for a in self._cfg()["allow"]):
            raise NotFound(f"allowed domain {name}")
        self._update(
            user,
            lambda rpz, _c: rpz.__setitem__(
                "allow", [a for a in rpz.get("allow", []) if a.get("domain") != name]
            ),
        )
        self._audit("rpz.allow.delete", f"rpz:allow:{name}", user, {}, client_ip)
        return self._applied()

    def exempt(self, cidr: str, note: str, user: str, client_ip: str | None) -> dict[str, Any]:
        import ipaddress

        try:
            net = str(ipaddress.ip_network(str(cidr).strip(), strict=False))
        except ValueError as exc:
            raise ValidationError(
                "cidr is not an address or network", [field_error("cidr", "invalid")]
            ) from exc
        entry = {"cidr": net, "note": str(note or "")[:200], "by": user, "at": datetime.now(UTC).isoformat()}

        def mutate(rpz: dict[str, Any], _c: Any) -> None:
            rows = [c for c in rpz.get("exempt_clients", []) if c.get("cidr") != net]
            rpz["exempt_clients"] = [*rows, entry]

        self._update(user, mutate)
        self._audit("rpz.exempt.add", f"rpz:exempt:{net}", user, entry, client_ip)
        return self._applied()

    def unexempt(self, cidr: str, user: str, client_ip: str | None) -> dict[str, Any]:
        if not any(c.get("cidr") == cidr for c in self._cfg()["exempt_clients"]):
            raise NotFound(f"exempt client {cidr}")
        self._update(
            user,
            lambda rpz, _c: rpz.__setitem__(
                "exempt_clients", [c for c in rpz.get("exempt_clients", []) if c.get("cidr") != cidr]
            ),
        )
        self._audit("rpz.exempt.delete", f"rpz:exempt:{cidr}", user, {}, client_ip)
        return self._applied()

    def _applied(self) -> dict[str, Any]:
        """The allow zone is rewritten on this node now; the other nodes follow on their next pass."""
        applied = False
        backend = self.dns.local
        if backend is not None:
            from pelagos.rpz import sync

            try:
                env = backend.rpz_env()
                state = sync.load_state(env.state_path)
                settings = self.ctx.settings()
                applied = sync.Syncer(env, lambda: settings).sync_allow(settings, state)
                # Only the allow slot is ours: the collector may have written the lists meanwhile.
                fresh = sync.load_state(env.state_path)
                fresh["allow"] = state.get("allow", {})
                sync.save_state(env.state_path, fresh)
            except Exception:
                applied = False
        signal_collector(self.ctx.paths.collector_sock, "rpz")
        cfg = self._cfg()
        return {"applied_here": applied, "allow": cfg["allow"], "exempt_clients": cfg["exempt_clients"]}

    def refresh(self, sub_id: str | None, user: str, client_ip: str | None) -> dict[str, Any]:
        if sub_id and sub_id not in {s.id for s in model.resolve(self.ctx.settings())}:
            raise NotFound(f"subscription {sub_id}")
        reached = signal_collector(self.ctx.paths.collector_sock, "rpz", id=sub_id)
        self._audit("rpz.refresh", f"rpz:subscription:{sub_id or '*'}", user, {"id": sub_id}, client_ip)
        return {"requested": reached}
