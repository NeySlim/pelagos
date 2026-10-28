# SPDX-License-Identifier: Apache-2.0
"""DDNS catch-up (section 24): the outage window seen by each D2, the leases of a window whose DNS
records are missing or differ, and the confirmed plan that resends them (lease4/6-resend-ddns).

Sources (read 2026-10-28): Kea 2.6.3 ARM, Lease Commands, "lease4-resend-ddns, lease6-resend-ddns":
an update request is generated when DDNS is enabled, the lease has a hostname and fqdn_fwd or fqdn_rev;
result 0 only means it was queued for D2, 3 that the lease is gone
(kea.readthedocs.io/en/kea-2.6.3/arm/hooks.html). Kea 2.6.3 ARM, "DHCP-DDNS Server Statistics":
update-success, update-timeout and update-error count completed DNS updates; D2 loses its queue when it
stops (kea.readthedocs.io/en/kea-2.6.3/arm/ddns.html).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from pelagos.connectors.base import ConnectorError
from pelagos.core import settings_registry as reg
from pelagos.domain import (
    Alert,
    AlertKind,
    Change,
    ChangeOp,
    Engine,
    Family,
    Lease,
    LeaseState,
    Plan,
    PlanScope,
    PlanState,
    RRset,
    Severity,
    ValidationResult,
    messages,
    normalize_name,
    to_rfc3339,
)
from pelagos.domain.common import from_rfc3339, utcnow
from pelagos.services import consistency
from pelagos.services.errors import Conflict, ServiceError, ValidationError, field_error

OUTAGE_KIND = "outage"  # d2 engine snapshot written by the D2 poller, copied to every peer
FAILURES = ("update-timeout", "update-error")
# An open window with no new failure for this long is over: the next lost update opens another.
QUIET_CLOSE_SECONDS = 900
REVERSE_SUFFIXES = ("in-addr.arpa.", "ip6.arpa.")
DEFAULT_VIEW = "_default"


# Outage window ------------------------------------------------------------------------------------


def track_outage(
    state: dict[str, Any] | None,
    prev: dict[str, int] | None,
    totals: dict[str, int] | None,
    now: int,
    quiet_seconds: int = QUIET_CLOSE_SECONDS,
    stamps: dict[str, str] | None = None,
) -> dict[str, Any]:
    """The next outage state of one D2 from its counters (None: D2 down or unreadable).

    State `{"open": {"since", "cause", "failed_at"}|None, "last": {"from", "to"}|None, "good_at"}`,
    epoch seconds. A window opens when updates time out or fail, or when D2 is down (its queue is
    lost). Every lost update is counted as a failure, so it closes at the first poll with successes
    and no new failure, or whose last success came after its last failure (`stamps`: the time Kea
    gives each counter's latest sample), after `quiet_seconds` without failure, or when D2 comes
    back with none."""
    out: dict[str, Any] = {"open": None, "last": None, "good_at": None, **(state or {})}
    current = out["open"]
    if totals is None:
        if current is None:
            out["open"] = {"since": out["good_at"] or now, "cause": "d2_down", "failed_at": now}
        else:
            out["open"] = {**current, "failed_at": now}
        return out
    if prev is None:
        if current is None:
            out["good_at"] = now
        return out
    if any(int(totals.get(k, 0)) < int(prev.get(k, 0)) for k in ("update-sent", *FAILURES)):
        prev = {}  # D2 restarted: its counters start again from zero
    delta = {k: max(0, int(totals.get(k, 0)) - int(prev.get(k, 0))) for k in ("update-success", *FAILURES)}
    if sum(delta[k] for k in FAILURES):
        since = out["good_at"] or now if current is None else current["since"]
        if delta["update-success"] and _recovered(stamps):
            out["last"] = {"from": int(since), "to": now}
            out["open"] = None
            out["good_at"] = now
            return out
        out["open"] = {"since": since, "cause": "updates", "failed_at": now}
        return out
    if current is not None:
        quiet = now - int(current.get("failed_at") or current["since"]) >= quiet_seconds
        if delta["update-success"] or quiet or current.get("cause") == "d2_down":
            out["last"] = {"from": int(current["since"]), "to": now}
            out["open"] = None
    if out["open"] is None:
        out["good_at"] = now
    return out


def _recovered(stamps: dict[str, str] | None) -> bool:
    """The latest success is newer than the latest failure (Kea's sample times, one clock)."""
    if not stamps or not stamps.get("update-success"):
        return False
    failed = [str(stamps[k]) for k in FAILURES if stamps.get(k)]
    return bool(failed) and str(stamps["update-success"]) > max(failed)


def sample_stamps(raw: dict[str, Any]) -> dict[str, str]:
    """Time of the latest sample of the success and failure counters in a statistic-get-all answer."""
    out: dict[str, str] = {}
    for name in ("update-success", *FAILURES):
        samples = raw.get(name)
        if isinstance(samples, list) and samples and isinstance(samples[0], list) and len(samples[0]) > 1:
            out[name] = str(samples[0][1])
    return out


@dataclass(slots=True)
class Window:
    start: datetime
    end: datetime
    source: str  # "outage" (closed), "open" (still going on), "default" (no outage known), "request"


def _ts(value: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(value), tz=UTC)
    except (TypeError, ValueError, OverflowError):
        return None


def outage_windows(
    states: Iterable[dict[str, Any]],
) -> tuple[tuple[datetime, datetime] | None, datetime | None]:
    """(last closed window, earliest open since) over the D2 outage states of every node. Closed
    windows of several nodes that overlap the latest one are merged into it."""
    closed: list[tuple[datetime, datetime]] = []
    opens: list[datetime] = []
    for state in states:
        if not isinstance(state, dict):
            continue
        last = state.get("last") if isinstance(state.get("last"), dict) else None
        if last:
            start, end = _ts(last.get("from")), _ts(last.get("to"))
            if start and end and start <= end:
                closed.append((start, end))
        current = state.get("open") if isinstance(state.get("open"), dict) else None
        if current and _ts(current.get("since")):
            opens.append(_ts(current["since"]))  # type: ignore[arg-type]
    window = None
    if closed:
        closed.sort(key=lambda w: w[1], reverse=True)
        start, end = closed[0]
        for s, e in closed[1:]:
            if e >= start:
                start = min(start, s)
        window = (start, end)
    return window, (min(opens) if opens else None)


def outage_states(store: Any) -> list[dict[str, Any]]:
    """Every node's D2 outage state in the local series store (peers' rows are copies)."""
    if store is None:
        return []
    return [
        s["payload"]
        for s in store.snapshots(engine=Engine.D2.value)
        if s.get("kind") == OUTAGE_KIND and isinstance(s.get("payload"), dict)
    ]


# Selection ----------------------------------------------------------------------------------------


@dataclass(slots=True)
class Candidate:
    lease: Lease
    fqdn: str
    problems: list[dict[str, Any]] = field(default_factory=list)  # {"rtype","name","found"}


def eligible(lease: Lease, start: datetime, end: datetime) -> bool:
    """Active, named, with a DNS direction flag and its last client transaction in the window."""
    if lease.state is not LeaseState.DEFAULT or not lease.hostname or not (lease.fqdn_fwd or lease.fqdn_rev):
        return False
    if (lease.lease_type or "").upper() in ("IA_PD", "2"):
        return False  # a delegated prefix has no DNS name
    return lease.cltt is not None and start <= lease.cltt <= end


def _apex_of(name: str, apexes: set[str]) -> str | None:
    """The zone read that holds `name`; None when no zone was read for it."""
    return consistency._in_zone(name, apexes) if apexes else None


def select(
    leases: Iterable[Lease],
    forward: Iterable[RRset],
    reverse: Iterable[RRset],
    start: datetime,
    end: datetime,
) -> list[Candidate]:
    """Leases of the window whose A/AAAA (fqdn_fwd) or PTR (fqdn_rev) is missing or differs, in zones
    the RRsets cover (their SOA marks the zone); a direction whose zone was not read is not judged.
    Oldest client transaction first; one candidate per address."""
    forward, reverse = list(forward), list(reverse)
    fwd_apexes = consistency._apexes(forward)
    rev_apexes = consistency._apexes(reverse)
    addresses = consistency._address_index(forward)
    ptrs = consistency._ptr_index(reverse)
    out: dict[str, Candidate] = {}
    for lease in leases:
        ip = consistency.canonical_ip(lease.ip_address)
        if ip is None or ip in out or not eligible(lease, start, end):
            continue
        fqdn = normalize_name(str(lease.hostname))
        problems: list[dict[str, Any]] = []
        if lease.fqdn_fwd and _apex_of(fqdn, fwd_apexes):
            rtype = "AAAA" if ":" in ip else "A"
            found = addresses.get((fqdn, rtype), set())
            if ip not in found:
                problems.append({"rtype": rtype, "name": fqdn, "found": sorted(found)})
        rname = consistency.reverse_name(ip)
        if lease.fqdn_rev and _apex_of(rname, rev_apexes):
            targets = ptrs.get(rname, set())
            if fqdn not in targets:
                problems.append({"rtype": "PTR", "name": rname, "found": sorted(targets)})
        if problems:
            out[ip] = Candidate(lease, fqdn, problems)
    return sorted(out.values(), key=lambda c: (c.lease.cltt or end, c.lease.ip_address))


def zones_needed(leases: Iterable[Lease], zones: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The served zones holding a name or reverse name of these leases (the longest match per view)."""
    names: set[str] = set()
    for lease in leases:
        ip = consistency.canonical_ip(lease.ip_address)
        if ip is None or not lease.hostname:
            continue
        if lease.fqdn_fwd:
            names.add(normalize_name(lease.hostname))
        if lease.fqdn_rev:
            names.add(consistency.reverse_name(ip))
    picked: dict[tuple[str, str], dict[str, Any]] = {}
    for name in names:
        best: dict[str, dict[str, Any]] = {}
        for zone in zones:
            apex = zone["name"]
            if name == apex or name.endswith("." + apex):
                view = zone.get("view") or DEFAULT_VIEW
                if view not in best or len(apex) > len(best[view]["name"]):
                    best[view] = zone
        for view, zone in best.items():
            picked[(zone["name"], view)] = zone
    return [picked[k] for k in sorted(picked)]


# Plan ---------------------------------------------------------------------------------------------


def _change(c: Candidate) -> Change:
    lease = c.lease
    return Change(
        ChangeOp.REPLACE,
        f"resend/{consistency.canonical_ip(lease.ip_address)}",
        before={"records": c.problems},
        after={
            "hostname": c.fqdn,
            "fqdn_fwd": lease.fqdn_fwd,
            "fqdn_rev": lease.fqdn_rev,
            "cltt": to_rfc3339(lease.cltt) if lease.cltt else None,
            "subnet_id": lease.subnet_id,
        },
    )


def _diff_line(c: Candidate) -> str:
    what = ", ".join(
        f"{p['rtype']} {'differs (' + ' '.join(p['found']) + ')' if p['found'] else 'missing'}"
        for p in c.problems
    )
    return f"~{c.lease.ip_address} {c.fqdn} {what}\n"


class DdnsReplayService:
    def __init__(
        self,
        ctx: Any,
        dns: Any,
        dhcp: Callable[[], Iterable[Any]],
        plans: Any,
        store: Callable[[], Any],
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.ctx = ctx
        self.dns = dns
        self.dhcp = dhcp  # the DhcpService of each family whose module is on
        self.plans = plans
        self.store = store  # the local SeriesStore, or None
        self.clock = clock

    def _settings(self) -> tuple[int, int]:
        settings = self.ctx.settings()
        return int(reg.get(settings, "ddns.replay_max_leases")), int(
            reg.get(settings, "ddns.replay_window_max_hours")
        )

    def window(self, body: dict[str, Any]) -> Window:
        """The requested window, else the open outage, else the last closed one, else the last
        `replay_window_max_hours`; never longer than that."""
        _max_leases, max_hours = self._settings()
        span = timedelta(hours=max_hours)
        now = self.clock()
        start = _when(body.get("from"), "from")
        end = _when(body.get("to"), "to")
        if start is not None or end is not None:
            end = end or now
            start = start or end - span
            source = "request"
        else:
            closed, open_since = outage_windows(outage_states(self.store()))
            if open_since is not None:
                start, end, source = open_since, now, "open"
            elif closed is not None and closed[1] >= now - span:
                start, end, source = closed[0], closed[1], "outage"
            else:
                start, end, source = now - span, now, "default"
            start = max(start, end - span)
        if start >= end:
            raise ValidationError("from must be before to", [field_error("from", "before to")])
        if end - start > span:
            raise ValidationError(
                f"the window is longer than {max_hours} h (ddns.replay_window_max_hours)",
                [field_error("from", f"at most {max_hours} h before to")],
            )
        return Window(start, end, source)

    def _families(self, body: dict[str, Any]) -> list[Any]:
        family = body.get("family")
        if family not in (None, "", "v4", "v6"):
            raise ValidationError("family must be v4 or v6", [field_error("family", "v4 or v6")])
        return [d for d in self.dhcp() if family in (None, "") or d.family.value == family]

    def _leases(self, dhcp: Any, win: Window, notes: list[ValidationResult]) -> list[Lease]:
        """Eligible leases of every node running the engine, this node first; one copy per address
        (HA partners hold the same lease), tagged with the node it was read on."""
        nodes: list[tuple[str, str]] = []
        if dhcp.local is not None:
            nodes.append((self.ctx.node.id, self.ctx.node.name))
        nodes += [(p.id, p.name) for p in dhcp.peers.peers_running(dhcp.engine)]
        seen: dict[str, Lease] = {}
        for node_id, name in nodes:
            try:
                rows, read_on, _partial = dhcp.all_leases(node_id)
            except ServiceError as exc:
                notes.append(
                    _note(False, "ddns.replay.unread", node=name, engine=dhcp.engine.value, error=exc.detail)
                )
                continue
            for lease in rows:
                ip = consistency.canonical_ip(lease.ip_address)
                if ip is None or ip in seen or not eligible(lease, win.start, win.end):
                    continue
                lease.node_id = read_on
                seen[ip] = lease
        return list(seen.values())

    def _records(self, leases: list[Lease]) -> tuple[list[RRset], list[RRset], list[ValidationResult]]:
        zones = [z["zone"] for z in self.dns.zones() if z["zone"]["kind"] in ("primary", "secondary")]
        forward: list[RRset] = []
        reverse: list[RRset] = []
        notes: list[ValidationResult] = []
        for zone in zones_needed(leases, zones):
            view = zone.get("view") or DEFAULT_VIEW
            try:
                rrsets, _node = self.dns.records(zone["name"], None if view == DEFAULT_VIEW else view)
            except (ServiceError, ConnectorError) as exc:
                # A zone that cannot be read (AXFR refused) leaves its direction unjudged, never fails.
                detail = exc.detail if isinstance(exc, ServiceError) else str(exc)
                notes.append(
                    ValidationResult(ok=False, tool="ddns-replay", output=f"{zone['name']}: {detail}")
                )
                continue
            (reverse if zone["name"].endswith(REVERSE_SUFFIXES) else forward).extend(rrsets)
        return forward, reverse, notes

    def candidates(self, body: dict[str, Any]) -> tuple[Window, list[Candidate], list[ValidationResult]]:
        win = self.window(body)
        notes: list[ValidationResult] = []
        leases: list[Lease] = []
        for dhcp in self._families(body):
            leases += self._leases(dhcp, win, notes)
        forward, reverse, zone_notes = self._records(leases)
        return win, select(leases, forward, reverse, win.start, win.end), notes + zone_notes

    def plan(self, body: dict[str, Any], created_by: str) -> Plan:
        max_leases, _hours = self._settings()
        limit = body.get("limit")
        if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or limit < 1):
            raise ValidationError(
                "limit must be a positive integer", [field_error("limit", "positive integer")]
            )
        limit = min(limit or max_leases, max_leases)
        win, found, notes = self.candidates(body)
        if not found:
            span = f"no lease to replay from {to_rfc3339(win.start)} to {to_rfc3339(win.end)}"
            unread = [n.output for n in notes if not n.ok and n.output]
            if unread:
                raise Conflict(f"{span}: records not checked, " + "; ".join(unread))
            raise Conflict(f"{span}: every lease of the window has its records")
        chosen = found[:limit]
        if len(found) > limit:
            notes.append(_note(True, "ddns.replay.more", count=len(found) - limit))
        names = {p.id: p.name for p in self.ctx.cluster().nodes}
        names.setdefault(self.ctx.node.id, self.ctx.node.name)
        groups: dict[tuple[Family, str], list[Candidate]] = {}
        for c in chosen:
            groups.setdefault((c.lease.family, c.lease.node_id or self.ctx.node.id), []).append(c)
        parts = []
        for (family, node_id), items in sorted(groups.items(), key=lambda g: (g[0][0].value, g[0][1])):
            engine = family.kea_engine
            part = Plan(
                scope=PlanScope.DHCP_LEASE,
                node_id=self.ctx.node.id,
                engine=engine,
                **messages.fields(
                    "summary",
                    messages.msg(
                        "plan.ddns.replay_on",
                        count=len(items),
                        engine=engine.value,
                        node=names.get(node_id, node_id),
                    ),
                ),
                created_by=created_by,
                changes=[_change(c) for c in items],
                diff="".join(_diff_line(c) for c in items),
                requires_confirmation=True,
                state=PlanState.VALIDATED,
                target_node_ids=[node_id],
            )
            if not self._lease_cmds(engine, node_id):
                part.validations.append(
                    _note(
                        False,
                        "ddns.replay.no_lease_cmds",
                        engine=engine.value,
                        node=names.get(node_id, node_id),
                    )
                )
                part.state = PlanState.FAILED
                part.error = part.validations[-1].output
            parts.append(part)
        summary = messages.msg(
            "plan.ddns.replay", count=len(chosen), start=to_rfc3339(win.start), end=to_rfc3339(win.end)
        )
        plan = _combine(summary, parts, created_by, self.ctx.node.id)
        plan.validations = notes + plan.validations
        if len(parts) == 1:
            part = parts[0]
            part.summary, part.summary_message = plan.summary, plan.summary_message
            part.validations = plan.validations
            return self.ctx.plan_store.put(part)
        self.plans.register_composite(plan, parts)
        return self.ctx.plan_store.put(plan)

    def _lease_cmds(self, engine: Engine, node_id: str) -> bool:
        """False only when the node's last capabilities say lease_cmds is not loaded."""
        store = self.store()
        found = store.snapshot(node_id, engine.value, "capabilities") if store is not None else None
        caps = found[1] if found else None
        if not isinstance(caps, dict) or not caps.get("running", True) or "lease_cmds" not in caps:
            return True
        return bool(caps["lease_cmds"])


def _when(value: Any, name: str) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        when = from_rfc3339(str(value))
    except (TypeError, ValueError):
        when = None
    if when is None:
        raise ValidationError(f"{name} must be an RFC 3339 time", [field_error(name, "RFC 3339 time")])
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def _note(ok: bool, key: str, **params: Any) -> ValidationResult:
    return ValidationResult(ok=ok, tool="ddns-replay", output=messages.render(messages.msg(key, **params)))


def _combine(summary: dict[str, Any], parts: list[Plan], created_by: str, node_id: str) -> Plan:
    plan = Plan(
        scope=PlanScope.DHCP_LEASE,
        node_id=node_id,
        summary=messages.render(summary),
        summary_message=summary,
        created_by=created_by,
        requires_confirmation=True,
    )
    for part in parts:
        plan.changes.extend(part.changes)
        plan.diff += part.diff
        plan.validations.extend(part.validations)
        for target in part.target_node_ids:
            if target not in plan.target_node_ids:
                plan.target_node_ids.append(target)
    failed = [p for p in parts if p.state is PlanState.FAILED]
    plan.state = PlanState.FAILED if failed else PlanState.VALIDATED
    plan.error = "; ".join(p.error or "validation failed" for p in failed) or None
    return plan


def replay_alert(window: tuple[datetime, datetime] | None, found: list[Candidate]) -> Alert | None:
    """`ddns_replay` (cluster-wide, subject `ddns:replay`) for the last closed outage window."""
    if window is None or not found:
        return None
    start, end = to_rfc3339(window[0]), to_rfc3339(window[1])
    return Alert(
        kind=AlertKind.DDNS_REPLAY,
        severity=Severity.WARNING,
        subject="ddns:replay",
        **messages.fields("title", messages.msg("alert.ddns_replay", count=len(found), start=start, end=end)),
        details={
            "from": start,
            "to": end,
            "count": len(found),
            "leases": [c.lease.ip_address for c in found[:20]],
        },
    )
