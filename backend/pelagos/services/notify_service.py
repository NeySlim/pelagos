# SPDX-License-Identifier: Apache-2.0
"""Administration > Notifications (architecture section 22): channels, test sends, order, mute, history.

Channels, order and mute are entries of `[settings.notifications]` written through `update_cluster`,
so they replicate like every cluster setting; secrets are sealed in `[secrets]` and never returned.
Channel status comes from the dispatcher state of the sending node (`collector.notify.read_state`).
"""

from __future__ import annotations

import copy
import logging
import re
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pelagos.auth.rate_limit import RateLimiter
from pelagos.collector import notify as dispatcher
from pelagos.core import settings_registry as reg
from pelagos.domain import (
    AlertKind,
    AuditEntry,
    AuditResult,
    Engine,
    Severity,
    from_rfc3339,
    new_id,
    to_rfc3339,
    utcnow,
)
from pelagos.notify import transports
from pelagos.notify.model import SECRET_NAMES, Batch, ChannelType, Reason, SendResult, secret_key
from pelagos.services.errors import Conflict, NotFound, ServiceError, ValidationError, field_error

log = logging.getLogger(__name__)

DOMAIN = "notifications"
TARGET = dispatcher.TARGET_PREFIX
# Peer action giving the dispatcher state of a node (services.peer_actions).
PEER_STATE = "notify.state"
STATE_TIMEOUT = 4.0
TESTS_PER_MINUTE = 6
MUTE_MAX = timedelta(hours=24)
# A mute "24 hours ahead" set from a browser lands a little later here.
MUTE_SLACK = timedelta(minutes=5)
NAME_MAX = 100
COMMENT_MAX = 500
REMINDER_MAX_HOURS = 24 * 30
CONFIRM_MAX_SECONDS = 3600
HHMM = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
FIELDS = ("type", "name", "enabled", "language", "params", "filters", "schedule")
# Read-only members a client may echo back from a GET: ignored on writes.
ECHOED = ("id", "status", "secrets", "warnings", "scope")
# The parameter naming where a channel's secrets go: a stored secret follows it, never a new server.
TARGET_PARAM = {
    ChannelType.EMAIL: "host",
    ChannelType.NTFY: "url",
    ChannelType.GOTIFY: "url",
    ChannelType.MATRIX: "homeserver",
    ChannelType.WEBHOOK: "url",
    ChannelType.HOME_ASSISTANT: "url",
}
SendFn = Callable[..., SendResult]


def _drop_none(value: Any) -> Any:
    """TOML has no null: absent means default."""
    if isinstance(value, dict):
        return {str(k): _drop_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_drop_none(v) for v in value if v is not None]
    return value


def _str_list(value: Any, field: str, allowed: set[str] | None, errors: list[dict[str, str]]) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        errors.append(field_error(field, "list of strings expected"))
        return []
    unknown = [v for v in value if allowed is not None and v not in allowed]
    if unknown:
        errors.append(field_error(field, "unknown: " + ", ".join(unknown)))
    return list(dict.fromkeys(value))


def _int(value: Any, field: str, lo: int, hi: int, errors: list[dict[str, str]]) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | float) or int(value) != value:
        errors.append(field_error(field, "integer expected"))
        return None
    if not lo <= int(value) <= hi:
        errors.append(field_error(field, f"between {lo} and {hi}"))
        return None
    return int(value)


def clean_filters(raw: Any, node_ids: set[str], errors: list[dict[str, str]]) -> dict[str, Any]:
    raw = {} if raw is None else raw
    if not isinstance(raw, dict):
        errors.append(field_error("filters", "object expected"))
        return dict(dispatcher.DEFAULT_FILTERS)
    out = {**copy.deepcopy(dispatcher.DEFAULT_FILTERS), **raw}
    unknown = set(out) - set(dispatcher.DEFAULT_FILTERS)
    for key in sorted(unknown):
        errors.append(field_error(f"filters.{key}", "unknown field"))
    if out["severity_min"] not in set(Severity):
        errors.append(field_error("filters.severity_min", "info, warning or critical"))
    kinds = {k.value for k in AlertKind}
    out["kinds_include"] = _str_list(out["kinds_include"], "filters.kinds_include", kinds, errors)
    out["kinds_exclude"] = _str_list(out["kinds_exclude"], "filters.kinds_exclude", kinds, errors)
    out["node_ids"] = _str_list(out["node_ids"], "filters.node_ids", node_ids, errors)
    out["engines"] = _str_list(out["engines"], "filters.engines", {e.value for e in Engine}, errors)
    return {k: out[k] for k in dispatcher.DEFAULT_FILTERS}


def clean_quiet(raw: Any, errors: list[dict[str, str]]) -> dict[str, Any] | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        errors.append(field_error("schedule.quiet", "object or null expected"))
        return None
    out = {"start": raw.get("start"), "end": raw.get("end"), "timezone": raw.get("timezone") or "UTC"}
    for key in sorted(set(raw) - {"start", "end", "timezone", "days", "critical_passes"}):
        errors.append(field_error(f"schedule.quiet.{key}", "unknown field"))
    for key in ("start", "end"):
        if not isinstance(out[key], str) or not HHMM.match(out[key]):
            errors.append(field_error(f"schedule.quiet.{key}", "HH:MM expected"))
    if out["start"] == out["end"]:
        errors.append(field_error("schedule.quiet.end", "must differ from start"))
    try:
        ZoneInfo(str(out["timezone"]))
    except (ZoneInfoNotFoundError, ValueError):
        errors.append(field_error("schedule.quiet.timezone", "IANA time zone expected"))
    days = raw.get("days", [])
    if not isinstance(days, list) or any(
        isinstance(d, bool) or not isinstance(d, int) or not 0 <= d <= 6 for d in days
    ):
        errors.append(field_error("schedule.quiet.days", "list of days 0 (Monday) to 6"))
        days = []
    out["days"] = sorted(set(days))
    passes = raw.get("critical_passes", True)
    if not isinstance(passes, bool):
        errors.append(field_error("schedule.quiet.critical_passes", "boolean expected"))
    out["critical_passes"] = bool(passes)
    return out


def clean_schedule(raw: Any, errors: list[dict[str, str]]) -> dict[str, Any]:
    raw = {} if raw is None else raw
    if not isinstance(raw, dict):
        errors.append(field_error("schedule", "object expected"))
        return dict(dispatcher.DEFAULT_SCHEDULE)
    out = {**copy.deepcopy(dispatcher.DEFAULT_SCHEDULE), **raw}
    for key in sorted(set(out) - set(dispatcher.DEFAULT_SCHEDULE)):
        errors.append(field_error(f"schedule.{key}", "unknown field"))
    out["reminder_hours"] = _int(
        out["reminder_hours"], "schedule.reminder_hours", 0, REMINDER_MAX_HOURS, errors
    )
    if not isinstance(out["send_resolved"], bool):
        errors.append(field_error("schedule.send_resolved", "boolean expected"))
    if out["confirm_seconds"] is not None:
        out["confirm_seconds"] = _int(
            out["confirm_seconds"], "schedule.confirm_seconds", 0, CONFIRM_MAX_SECONDS, errors
        )
    out["quiet"] = clean_quiet(out["quiet"], errors)
    return {k: out[k] for k in dispatcher.DEFAULT_SCHEDULE}


def _target(channel: Mapping[str, Any]) -> str:
    param = TARGET_PARAM.get(str(channel.get("type")), "url")
    value = (channel.get("params") or {}).get(param)
    return str(value or "").strip().rstrip("/").lower()


class NotifyService:
    def __init__(self, ctx: Any, peers: Any) -> None:
        self.ctx = ctx
        self.peers = peers
        # Transport entry point; tests replace it with a fake that records the batch.
        self.send: SendFn = transports.send
        self.test_limiter = RateLimiter(TESTS_PER_MINUTE)
        self.clock: Callable[[], datetime] = utcnow

    # Settings -------------------------------------------------------------------------------

    def _domain(self) -> dict[str, Any]:
        return reg.domain(self.ctx.settings(), DOMAIN)

    def _channels(self) -> list[dict[str, Any]]:
        return [c for c in self._domain().get("channels") or [] if isinstance(c, dict)]

    def _stored(self, channel_id: str) -> dict[str, Any]:
        channel = next((c for c in self._channels() if str(c.get("id")) == channel_id), None)
        if channel is None:
            raise NotFound(f"channel {channel_id}")
        return channel

    def _node_ids(self) -> list[str]:
        ids = [n.id for n in self.ctx.cluster().nodes]
        return ids if self.ctx.node.id in ids else [self.ctx.node.id, *ids]

    def _secret_names(self, channel_id: str) -> set[str]:
        stored = self.ctx.cluster().secrets
        return {
            name
            for names in SECRET_NAMES.values()
            for name in names
            if secret_key(channel_id, name) in stored
        }

    def _update(self, actor: str, mutate: Callable[[dict[str, Any], Any], None]) -> None:
        def apply(cluster: Any) -> None:
            mutate(cluster.settings.setdefault(DOMAIN, {}), cluster)

        self.ctx.config_store.update_cluster(apply, updated_by=f"user:{actor}@node:{self.ctx.node.id}")

    def _audit(
        self,
        action: str,
        target: str,
        actor: str,
        request: dict[str, Any],
        client_ip: str | None,
        *,
        response: dict[str, Any] | None = None,
        ok: bool = True,
        message: str | None = None,
    ) -> None:
        self.ctx.audit_log.append(
            AuditEntry(
                node_id=self.ctx.node.id,
                user=actor,
                action=action,
                target=target,
                request=request,
                response=response if response is not None else {"ok": True},
                result=AuditResult.OK if ok else AuditResult.ERROR,
                message=message,
                client_ip=client_ip,
            )
        )

    # Reads ----------------------------------------------------------------------------------

    def _state(self, local: dict[str, Any]) -> dict[str, Any]:
        """The sender's dispatcher state: this node's file, or the sender's over the peer channel."""
        sender = (local.get("sender") or {}).get("node_id")
        if not sender or sender == self.ctx.node.id:
            return local
        peer = self.peers.peer(sender)
        if peer is None:
            return local
        try:
            remote = self.peers.action(peer, PEER_STATE, {}, timeout=STATE_TIMEOUT)
        except ServiceError as exc:
            log.info("notification state of %s not read: %s", sender, exc.detail)
            return local
        return remote if isinstance(remote, dict) else local

    def _last_sent(self) -> dict[str, str]:
        """Newest `notify.sent` per channel: the replicated record, whichever node sent."""
        out: dict[str, str] = {}
        since = self.clock() - timedelta(days=dispatcher.LEDGER_DAYS)
        entries, _ = self.ctx.audit_log.query(action=dispatcher.ACTION_SENT, since=since, per_page=100000)
        for entry in entries:
            channel_id = dispatcher.channel_of(entry)
            ts = to_rfc3339(entry.ts)
            if channel_id and ts > out.get(channel_id, ""):
                out[channel_id] = ts
        return out

    def public(
        self,
        channel: dict[str, Any],
        state: dict[str, Any] | None = None,
        last_sent: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """A channel as the API returns it: defaults filled, secrets as booleans, status, warnings."""
        channel_id = str(channel.get("id"))
        kind = str(channel.get("type"))
        set_names = self._secret_names(channel_id)
        out = {
            "id": channel_id,
            "type": kind,
            "name": str(channel.get("name") or ""),
            "enabled": bool(channel.get("enabled", True)),
            "language": str(channel.get("language") or "en"),
            "params": copy.deepcopy(dict(channel.get("params") or {})),
            "filters": dispatcher.filters_of(channel),
            "schedule": dispatcher.schedule_of(channel),
            "secrets": {name: name in set_names for name in SECRET_NAMES.get(kind, ())},
        }
        st = ((state or {}).get("channels") or {}).get(channel_id) or {}
        sent = max(str(st.get("last_sent_at") or ""), (last_sent or {}).get(channel_id, "")) or None
        out["status"] = {
            "state": "disabled" if not out["enabled"] else str(st.get("state") or "ok"),
            "since": st.get("since") if out["enabled"] else None,
            "last_sent_at": sent,
            "last_error": st.get("last_error"),
        }
        try:
            issues = transports.validate(out, set_names)
        except Exception:  # an unknown type stored by a newer release: shown, not refused
            issues = []
        out["warnings"] = [{"field": i.field, "message": i.message} for i in issues if i.level == "warning"]
        return out

    def mute(self) -> dict[str, Any] | None:
        mute = self._domain().get("mute")
        if not isinstance(mute, dict):
            return None
        try:
            until = from_rfc3339(str(mute.get("until")))
        except ValueError:
            return None
        return dict(mute) if until > self.clock() else None

    def overview(self) -> dict[str, Any]:
        domain = self._domain()
        local = dispatcher.read_state(self.ctx.paths)
        state = self._state(local)
        last_sent = self._last_sent()
        sender = state.get("sender") or local.get("sender") or {}
        queue = state.get("queue") or {}
        return {
            "channels": [self.public(c, state, last_sent) for c in self._channels()],
            "settings": {k: v for k, v in domain.items() if k not in reg.MANAGED[DOMAIN]},
            "sender": {
                "node_id": sender.get("node_id"),
                "since": sender.get("since"),
                "order": dispatcher.send_order(self._node_ids(), domain.get("order")),
            },
            "mute": self.mute(),
            "queue": {
                "pending": int(queue.get("pending") or 0),
                "failing": int(queue.get("failing") or 0),
                "node_id": state.get("node_id"),
            },
        }

    # Channel input -------------------------------------------------------------------------

    def _check(
        self, channel: dict[str, Any], secret_names: set[str], errors: list[dict[str, str]]
    ) -> dict[str, Any]:
        """The channel table to store; every error found is appended (one 400 lists them all)."""
        if channel.get("type") not in set(ChannelType):
            errors.append(field_error("type", "one of " + ", ".join(ChannelType)))
            return channel
        name = channel.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(field_error("name", "required"))
        elif len(name.strip()) > NAME_MAX:
            errors.append(field_error("name", f"at most {NAME_MAX} characters"))
        else:
            channel["name"] = name.strip()
        if not isinstance(channel.get("enabled"), bool):
            errors.append(field_error("enabled", "boolean expected"))
        if not isinstance(channel.get("params"), dict):
            errors.append(field_error("params", "object expected"))
            channel["params"] = {}
        channel["params"] = _drop_none(channel["params"])
        channel["filters"] = clean_filters(channel.get("filters"), set(self._node_ids()), errors)
        channel["schedule"] = clean_schedule(channel.get("schedule"), errors)
        for issue in transports.validate(channel, secret_names):
            if issue.level == "error":
                errors.append(field_error(issue.field, issue.message))
        return channel

    @staticmethod
    def _secrets_in(body: dict[str, Any], kind: str, errors: list[dict[str, str]]) -> dict[str, str | None]:
        """Secrets of a request: a string sets it, null erases it, absent keeps it."""
        raw = body.get("secrets")
        if raw is None:
            return {}
        if not isinstance(raw, dict):
            errors.append(field_error("secrets", "object expected"))
            return {}
        allowed = SECRET_NAMES.get(kind, ())
        out: dict[str, str | None] = {}
        for name, value in raw.items():
            if name not in allowed:
                errors.append(field_error(f"secrets.{name}", "not a secret of this channel type"))
            elif value is not None and not isinstance(value, str):
                errors.append(field_error(f"secrets.{name}", "string or null expected"))
            else:
                out[name] = value.strip() if isinstance(value, str) and value.strip() else None
        return out

    @staticmethod
    def _unknown(body: dict[str, Any], errors: list[dict[str, str]]) -> None:
        for key in sorted(set(body) - set(FIELDS) - set(ECHOED)):
            errors.append(field_error(key, "unknown field"))

    def _seal(self, channel_id: str, secrets: dict[str, str | None]) -> Callable[[Any], None]:
        box = self.ctx.secrets
        if any(v is not None for v in secrets.values()) and box is None:
            raise Conflict("no master key on this node: secrets cannot be stored")

        def apply(cluster: Any) -> None:
            for name, value in secrets.items():
                key = secret_key(channel_id, name)
                if value is None:
                    cluster.secrets.pop(key, None)
                else:
                    cluster.secrets[key] = box.encrypt(key, value)

        return apply

    @staticmethod
    def _raise(errors: list[dict[str, str]]) -> None:
        if errors:
            fields = ", ".join(dict.fromkeys(e["field"] for e in errors))
            raise ValidationError(f"invalid channel: {fields}", errors)

    # Channel writes ------------------------------------------------------------------------

    def create(self, body: dict[str, Any], actor: str, client_ip: str | None) -> dict[str, Any]:
        errors: list[dict[str, str]] = []
        self._unknown(body, errors)
        channel: dict[str, Any] = {
            "id": new_id(),
            "type": body.get("type"),
            "name": body.get("name"),
            "enabled": body.get("enabled", True),
            "language": body.get("language") or "en",
            "params": body.get("params") or {},
            "filters": body.get("filters") or {},
            "schedule": body.get("schedule") or {},
        }
        secrets = self._secrets_in(body, str(channel["type"]), errors)
        set_names = {k for k, v in secrets.items() if v is not None}
        channel = self._check(channel, set_names, errors)
        self._raise(errors)
        stored = _drop_none(channel)
        seal = self._seal(channel["id"], {k: v for k, v in secrets.items() if v is not None})

        def mutate(domain: dict[str, Any], cluster: Any) -> None:
            domain["channels"] = [*(domain.get("channels") or []), stored]
            seal(cluster)

        self._update(actor, mutate)
        out = self.public(stored)
        self._audit(
            "admin.notify.add", TARGET + stored["id"], actor, _audited(out), client_ip, message=stored["name"]
        )
        return out

    def update(
        self, channel_id: str, body: dict[str, Any], actor: str, client_ip: str | None
    ) -> dict[str, Any]:
        before = self._stored(channel_id)
        errors: list[dict[str, str]] = []
        self._unknown(body, errors)
        if "type" in body and body["type"] != before.get("type"):
            errors.append(field_error("type", "a channel keeps its type: create a new one"))
        channel = copy.deepcopy(before)
        channel.setdefault("enabled", True)
        channel.setdefault("language", "en")
        for key in ("name", "enabled", "language", "params"):
            if key in body:
                channel[key] = body[key]
        for key in ("filters", "schedule"):
            if key in body:
                given = body[key]
                current = channel.get(key) or {}
                channel[key] = {**current, **given} if isinstance(given, dict) else given
        kind = str(before.get("type"))
        secrets = self._secrets_in(body, kind, errors)
        stored_names = self._secret_names(channel_id)
        if _target(channel) != _target(before):
            # A stored secret never follows a channel to another server unless it is entered again.
            for name in sorted(stored_names - set(secrets)):
                errors.append(
                    field_error(f"secrets.{name}", "enter it again or clear it: the server changed")
                )
        set_names = (stored_names | {k for k, v in secrets.items() if v is not None}) - {
            k for k, v in secrets.items() if v is None
        }
        channel = self._check(channel, set_names, errors)
        self._raise(errors)
        stored = _drop_none(channel)
        seal = self._seal(channel_id, secrets)

        def mutate(domain: dict[str, Any], cluster: Any) -> None:
            items = list(domain.get("channels") or [])
            for i, item in enumerate(items):
                if isinstance(item, dict) and str(item.get("id")) == channel_id:
                    items[i] = stored
                    break
            else:
                raise NotFound(f"channel {channel_id}")
            domain["channels"] = items
            seal(cluster)

        old = self.public(before)
        self._update(actor, mutate)
        out = self.public(stored)
        self._audit(
            "admin.notify.replace",
            TARGET + channel_id,
            actor,
            {"before": _audited(old), "after": _audited(out)},
            client_ip,
            message=stored["name"],
        )
        return out

    def delete(self, channel_id: str, actor: str, client_ip: str | None) -> None:
        before = self._stored(channel_id)
        old = self.public(before)

        def mutate(domain: dict[str, Any], cluster: Any) -> None:
            domain["channels"] = [
                c
                for c in domain.get("channels") or []
                if not (isinstance(c, dict) and c.get("id") == channel_id)
            ]
            for name in {n for names in SECRET_NAMES.values() for n in names}:
                cluster.secrets.pop(secret_key(channel_id, name), None)

        self._update(actor, mutate)
        self._audit(
            "admin.notify.delete",
            TARGET + channel_id,
            actor,
            {"before": _audited(old)},
            client_ip,
            message=old["name"],
        )

    # Test send -----------------------------------------------------------------------------

    def _stored_secrets(self, channel_id: str, kind: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for name in SECRET_NAMES.get(kind, ()):
            value = self.ctx.get_secret(secret_key(channel_id, name))
            if value:
                out[name] = value
        return out

    def test(self, body: dict[str, Any], actor: str, client_ip: str | None) -> dict[str, Any]:
        """A real send from this node, saved channel or not; the result is audited, never queued."""
        errors: list[dict[str, str]] = []
        if body.get("channel_id"):
            channel = self._stored(str(body["channel_id"]))
            secrets = self._stored_secrets(str(channel["id"]), str(channel.get("type")))
        else:
            self._unknown({k: v for k, v in body.items() if k != "channel_id"}, errors)
            channel = {k: copy.deepcopy(body[k]) for k in FIELDS if k in body}
            channel.setdefault("name", "test")
            channel.setdefault("enabled", True)
            channel.setdefault("language", "en")
            channel.setdefault("params", {})
            channel["id"] = str(body.get("scope") or "test")
            kind = str(channel.get("type"))
            given = self._secrets_in(body, kind, errors)
            secrets = {}
            scope = body.get("scope")
            if scope:
                saved = self._stored(str(scope))
                if saved.get("type") == kind and _target(saved) == _target(channel):
                    secrets = self._stored_secrets(str(scope), kind)
            for name, value in given.items():
                if value is None:
                    secrets.pop(name, None)
                else:
                    secrets[name] = value
            channel = self._check(channel, set(secrets), errors)
        self._raise(errors)
        settings = self.ctx.settings()
        cluster = self.ctx.cluster()
        node = self.ctx.node
        batch = Batch(
            id=new_id(),
            cluster_id=str(getattr(cluster, "cluster_id", "")),
            sender_node_id=node.id,
            sender_name=node.name,
            reason=Reason.TEST,
            base_url=getattr(node, "web_url", None),
            sent_at=self.clock(),
        )
        timeout = float(reg.get(settings, "notifications.send_timeout_seconds"))
        result = self.send(channel, secrets, batch, transports.SendContext(timeout=timeout))
        answer = {"node_id": node.id, **result.to_dict()}
        request = {
            "op": "test",
            "channel_id": body.get("channel_id") or body.get("scope"),
            "type": channel.get("type"),
            "name": channel.get("name"),
            "batch_id": batch.id,
        }
        self._audit(
            "admin.notify.op",
            TARGET + str(request["channel_id"] or "test"),
            actor,
            request,
            client_ip,
            response=result.to_dict(),
            ok=result.ok,
            message=str(channel.get("name") or ""),
        )
        return answer

    # Order and mute ------------------------------------------------------------------------

    def set_order(self, body: dict[str, Any], actor: str, client_ip: str | None) -> dict[str, Any]:
        ids = body.get("node_ids")
        nodes = self._node_ids()
        if (
            not isinstance(ids, list)
            or not all(isinstance(i, str) for i in ids)
            or len(ids) != len(nodes)
            or set(ids) != set(nodes)
        ):
            raise ValidationError(
                "node_ids must list every node once", [field_error("node_ids", "every node exactly once")]
            )
        self._update(actor, lambda domain, _c: domain.__setitem__("order", list(ids)))
        self._audit("admin.notify.op", TARGET + "order", actor, {"op": "order", "node_ids": ids}, client_ip)
        return {"order": list(ids)}

    def set_mute(self, body: dict[str, Any], actor: str, client_ip: str | None) -> dict[str, Any]:
        errors: list[dict[str, str]] = []
        now = self.clock()
        until: datetime | None = None
        try:
            until = from_rfc3339(str(body.get("until") or ""))
        except (ValueError, OverflowError):
            errors.append(field_error("until", "RFC 3339 time expected"))
        if until is not None and until <= now:
            errors.append(field_error("until", "a time in the future"))
        elif until is not None and until - now > MUTE_MAX + MUTE_SLACK:
            errors.append(field_error("until", "at most 24 hours ahead"))
        comment = body.get("comment")
        if not isinstance(comment, str) or not comment.strip():
            errors.append(field_error("comment", "required"))
        elif len(comment.strip()) > COMMENT_MAX:
            errors.append(field_error("comment", f"at most {COMMENT_MAX} characters"))
        if errors:
            raise ValidationError("invalid mute", errors)
        assert until is not None and isinstance(comment, str)
        mute = {"until": to_rfc3339(until), "comment": comment.strip(), "by": actor, "at": to_rfc3339(now)}
        self._update(actor, lambda domain, _c: domain.__setitem__("mute", mute))
        self._audit(
            "admin.notify.op",
            TARGET + "mute",
            actor,
            {"op": "mute", "until": mute["until"], "comment": mute["comment"]},
            client_ip,
        )
        return {"mute": mute}

    def unmute(self, actor: str, client_ip: str | None) -> None:
        """End the mute now; the entry stays with `until` = now so the dispatcher sends its digest."""
        current = self.mute()
        if current is None:
            return
        ended = {**current, "until": to_rfc3339(self.clock()), "ended_by": actor}
        self._update(actor, lambda domain, _c: domain.__setitem__("mute", ended))
        self._audit(
            "admin.notify.op", TARGET + "mute", actor, {"op": "unmute", "until": current["until"]}, client_ip
        )

    # History -------------------------------------------------------------------------------

    def history(
        self,
        *,
        channel_id: str | None,
        result: str | None,
        alert_id: str | None,
        since: datetime | None,
        until: datetime | None,
        page: int,
        per_page: int,
    ) -> tuple[list[dict[str, Any]], int]:
        if result not in (None, "ok", "failed"):
            raise ValidationError("result is ok or failed", [field_error("result", "ok or failed")])
        action = {"ok": dispatcher.ACTION_SENT, "failed": dispatcher.ACTION_FAILED}.get(
            result or "", "notify."
        )
        target = TARGET + channel_id if channel_id else None
        kwargs: dict[str, Any] = {"action": action, "target": target, "since": since, "until": until}
        if alert_id is None:
            entries, total = self.ctx.audit_log.query(**kwargs, page=page, per_page=per_page)
            rows = [_history_row(e) for e in entries if _is_send(e, channel_id)]
            return rows, total
        entries, _ = self.ctx.audit_log.query(**kwargs, page=1, per_page=1000000)
        rows = [
            _history_row(e)
            for e in entries
            if _is_send(e, channel_id) and alert_id in ((e.request or {}).get("alert_ids") or [])
        ]
        start = (page - 1) * per_page
        return rows[start : start + per_page], len(rows)


def _is_send(entry: AuditEntry, channel_id: str | None) -> bool:
    if entry.action not in (dispatcher.ACTION_SENT, dispatcher.ACTION_FAILED):
        return False
    return channel_id is None or dispatcher.channel_of(entry) == channel_id


def _history_row(entry: AuditEntry) -> dict[str, Any]:
    request = entry.request or {}
    response = entry.response or {}
    return {
        "id": entry.id,
        "ts": to_rfc3339(entry.ts),
        "channel_id": dispatcher.channel_of(entry),
        "channel_name": entry.message,
        "node_id": entry.node_id,
        "batch_id": request.get("batch_id"),
        "reason": request.get("reason"),
        "events": list(request.get("events") or []),
        "result": "ok" if entry.action == dispatcher.ACTION_SENT else "failed",
        "status": response.get("status"),
        "duration_ms": response.get("duration_ms"),
        "error": response.get("error"),
    }


def _audited(channel: dict[str, Any]) -> dict[str, Any]:
    """A channel in an audit entry: its settings and which secrets are set, never their values."""
    return {k: channel[k] for k in (*FIELDS, "secrets") if k in channel}
