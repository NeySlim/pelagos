# SPDX-License-Identifier: Apache-2.0
"""Runtime operations on BIND (rndc) and Kea (control socket commands), from an allow-list.

Each operation names its permission, whether it changes the daemon's state, and whether it needs
an explicit confirmation. The service builds the rndc words or the Kea arguments itself from typed
parameters: nothing a caller sends reaches the daemon unchecked. Writes run under the engine lock
and every call is audited. Reads may target a peer (snapshot kind "op"); writes on a peer go over
/repl/v1/actions/ops.run and are audited on both nodes.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any

from pelagos.core.context import NodeContext
from pelagos.domain import AuditEntry, AuditResult, Engine
from pelagos.services.engine_lock import engine_lock
from pelagos.services.errors import (
    ConnectorError,
    EngineUnavailable,
    ServiceError,
    ValidationError,
    field_error,
)
from pelagos.services.masking import masked
from pelagos.services.peers import PeerGateway
from pelagos.services.registry import ConnectorRegistry

MAX_OUTPUT = 64 * 1024
_NAME_RE = re.compile(r"^(?!-)[A-Za-z0-9_*.-]{1,253}$")
_VIEW_RE = re.compile(r"^(?!-)[A-Za-z0-9_.-]{1,64}$")
_LIFETIME_RE = re.compile(r"^\d{1,7}[smhdw]?$")
_LEVEL_RE = re.compile(r"^\d{1,2}$")
_KEA_NAME_RE = re.compile(r"^(?!-)[A-Za-z0-9_.\[\]/-]{1,128}$")


@dataclass(frozen=True)
class OpSpec:
    name: str
    permission: str
    write: bool
    params: tuple[str, ...] = ()
    required: tuple[str, ...] = ()
    confirm: bool = False
    choices: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "permission": self.permission,
            "write": self.write,
            "params": list(self.params),
            "required": list(self.required),
            "confirm": self.confirm,
            "choices": {k: list(v) for k, v in self.choices.items()},
        }


def _op(name: str, permission: str, write: bool, *params: str, **kw: Any) -> OpSpec:
    return OpSpec(name, permission, write, tuple(params), **kw)


# rndc operations; zone/view/name/lifetime/mode/clean are typed parameters, never free text.
BIND_OPS: dict[str, OpSpec] = {
    s.name: s
    for s in (
        _op("status", "read:dns", False),
        _op("zonestatus", "read:dns", False, "zone", "view", required=("zone",)),
        _op("showzone", "read:dns", False, "zone", "view", required=("zone",)),
        _op("fetchlimit", "read:dns", False, "view"),
        _op("tcp-timeouts", "read:dns", False),
        _op("validation-status", "read:dns", False, "view"),
        _op("signing-list", "read:dns", False, "zone", "view", required=("zone",)),
        _op("dnssec-status", "read:dns", False, "zone", "view", required=("zone",)),
        _op("serve-stale-status", "read:dns", False, "view"),
        _op("managed-keys-status", "read:dns", False, "view"),
        _op("nta-dump", "read:dns", False),
        _op("reload", "ops:dns", True, "zone", "view"),
        _op("reconfig", "ops:dns", True),
        _op("notify", "ops:dns", True, "zone", "view", required=("zone",)),
        _op("retransfer", "ops:dns", True, "zone", "view", required=("zone",)),
        _op("freeze", "ops:dns", True, "zone", "view", required=("zone",)),
        _op("thaw", "ops:dns", True, "zone", "view", required=("zone",)),
        _op("refresh", "ops:dns", True, "zone", "view", required=("zone",)),
        _op("loadkeys", "ops:dns", True, "zone", "view", required=("zone",)),
        _op("sign", "ops:dns", True, "zone", "view", required=("zone",)),
        _op("trace", "ops:dns", True, "level"),
        _op("notrace", "ops:dns", True),
        _op("sync", "ops:dns", True, "zone", "view", "clean"),
        _op("flush", "ops:dns", True, "view"),
        _op("flushname", "ops:dns", True, "name", "view", required=("name",)),
        _op("flushtree", "ops:dns", True, "name", "view", required=("name",)),
        _op("querylog", "ops:dns", True, "mode", required=("mode",), choices={"mode": ("on", "off")}),
        _op("nta-add", "ops:dns", True, "name", "lifetime", "view", required=("name",)),
        _op("nta-remove", "ops:dns", True, "name", "view", required=("name",)),
        _op(
            "serve-stale",
            "ops:dns",
            True,
            "mode",
            "view",
            required=("mode",),
            choices={"mode": ("on", "off", "reset")},
        ),
        _op("managed-keys-refresh", "ops:dns", True, "view"),
        _op("stats", "ops:dns", True),
        _op("dumpdb", "ops:dns", True),
    )
}

# Kea control socket commands. Parameter types: see KEA_PARAM_TYPES.
_LEASE = "ops:dhcp.leases"
_HA = "ops:dhcp.ha"
_CFG = "write:dhcp.config"
_KEA_COMMON: tuple[OpSpec, ...] = (
    _op("status-get", "read:dhcp", False),
    _op("version-get", "read:dhcp", False),
    _op("build-report", "read:dhcp", False),
    _op("list-commands", "read:dhcp", False),
    _op("statistic-get-all", "read:dhcp", False),
    _op("statistic-get", "read:dhcp", False, "name", required=("name",)),
    _op("statistic-reset", _CFG, True, "name", required=("name",)),
    _op("statistic-reset-all", _CFG, True, confirm=True),
    _op("config-reload", _CFG, True, confirm=True),
)
_KEA_DHCP: tuple[OpSpec, ...] = (
    _op("ha-heartbeat", "read:dhcp", False, "server-name"),
    _op("ha-sync", _HA, True, "server-name", "max-period"),
    _op("ha-scopes", _HA, True, "scopes", "server-name", required=("scopes",)),
    _op("ha-continue", _HA, True, "server-name"),
    _op("ha-reset", _HA, True, "server-name", confirm=True),
    _op("dhcp-disable", _CFG, True, "max-period", confirm=True),
    _op("dhcp-enable", _CFG, True),
    _op("leases-reclaim", _LEASE, True, "remove", required=("remove",)),
    _op("config-backend-pull", _CFG, True),
    _op("cache-clear", _CFG, True, confirm=True),
    _op("cache-flush", _CFG, True, "count", confirm=True),
)
KEA_OPS: dict[str, dict[str, OpSpec]] = {
    "v4": {
        s.name: s
        for s in (
            *_KEA_COMMON,
            *_KEA_DHCP,
            _op("lease4-resend-ddns", _LEASE, True, "ip-address", required=("ip-address",)),
            _op("lease4-wipe", _LEASE, True, "subnet-id", confirm=True),
        )
    },
    "v6": {
        s.name: s
        for s in (
            *_KEA_COMMON,
            *_KEA_DHCP,
            _op("lease6-resend-ddns", _LEASE, True, "ip-address", required=("ip-address",)),
            _op("lease6-wipe", _LEASE, True, "subnet-id", confirm=True),
        )
    },
    "d2": {s.name: s for s in _KEA_COMMON},
}
KEA_PARAM_TYPES = {
    "name": "kea_name",
    "server-name": "kea_name",
    "max-period": "int",
    "scopes": "names",
    "remove": "bool",
    "ip-address": "ip",
    "subnet-id": "int",
    "count": "int",
}
ENGINE_OF_FAMILY = {"v4": Engine.KEA4, "v6": Engine.KEA6, "d2": Engine.D2}


def _field(name: str, message: str) -> ValidationError:
    return ValidationError(f"{name}: {message}", [field_error(name, message)])


def _check_params(spec: OpSpec, params: dict[str, Any]) -> dict[str, Any]:
    unknown = sorted(set(params) - set(spec.params))
    if unknown:
        raise _field(unknown[0], f"not a parameter of {spec.name}")
    for name in spec.required:
        if params.get(name) in (None, "", []):
            raise _field(name, "required")
    for name, allowed in spec.choices.items():
        if name in params and params[name] not in allowed:
            raise _field(name, f"one of {', '.join(allowed)}")
    return {k: v for k, v in params.items() if v not in (None, "")}


def _text(params: dict[str, Any], name: str, pattern: re.Pattern[str]) -> str | None:
    value = params.get(name)
    if value is None:
        return None
    if not isinstance(value, str) or not pattern.match(value):
        raise _field(name, "invalid value")
    return value


def rndc_words(op: str, params: dict[str, Any]) -> list[str]:
    """The rndc argument vector for an allow-listed operation (rndc 9.18 to 9.20 syntax)."""
    spec = BIND_OPS.get(op)
    if spec is None:
        raise _field("op", f"unknown operation {op}")
    p = _check_params(spec, params)
    zone = _text(p, "zone", _NAME_RE)
    view = _text(p, "view", _VIEW_RE)
    name = _text(p, "name", _NAME_RE)
    view_tail = ["IN", view] if view and view != "_default" else []
    zone_words = [zone.rstrip(".") or ".", *view_tail] if zone else []
    if view and not zone and "zone" in spec.params:
        # rndc scopes these by zone; a view alone would silently act on every view.
        raise _field("view", "needs zone")
    if op in {
        "zonestatus",
        "showzone",
        "notify",
        "retransfer",
        "freeze",
        "thaw",
        "refresh",
        "loadkeys",
        "sign",
    }:
        return [op, *zone_words]
    if op == "reload":
        return ["reload", *zone_words]
    if op == "sync":
        clean = p.get("clean")
        if clean not in (None, True, False):
            raise _field("clean", "true or false")
        return ["sync", *(["-clean"] if clean else []), *zone_words]
    if op == "signing-list":
        return ["signing", "-list", *zone_words]
    if op == "dnssec-status":
        return ["dnssec", "-status", *zone_words]
    if op in {"serve-stale-status", "serve-stale"}:
        return ["serve-stale", p.get("mode", "status"), *view_tail]
    if op in {"managed-keys-status", "managed-keys-refresh"}:
        return ["managed-keys", op.rsplit("-", 1)[1], *view_tail]
    if op == "nta-dump":
        return ["nta", "-dump"]  # rndc lists every view and ignores a view argument
    if op == "nta-add":
        lifetime = _text(p, "lifetime", _LIFETIME_RE)
        # rndc syntax: nta [-lifetime d] domain [view]; there is no -view option.
        life = ["-lifetime", lifetime] if lifetime else []
        return ["nta", *life, name, *([view] if view else [])]  # type: ignore[list-item]
    if op == "nta-remove":
        return ["nta", "-remove", name, *([view] if view else [])]  # type: ignore[list-item]
    if op == "fetchlimit":
        return ["fetchlimit", *([view] if view else [])]
    if op == "validation-status":
        return ["validation", "status", *([view] if view else [])]
    if op == "trace":
        level = _text(p, "level", _LEVEL_RE)
        return ["trace", *([level] if level else [])]
    if op == "flush":
        return ["flush", *([view] if view else [])]
    if op in {"flushname", "flushtree"}:
        return [op, name, *([view] if view else [])]  # type: ignore[list-item]
    if op == "querylog":
        return ["querylog", p["mode"]]
    if op == "dumpdb":
        return ["dumpdb", "-all"]
    return [op]  # status, tcp-timeouts, reconfig, stats, notrace


def kea_arguments(family: str, command: str, params: dict[str, Any]) -> Any:
    """Typed arguments of an allow-listed Kea command (usually an object); None when it takes none."""
    spec = KEA_OPS.get(family, {}).get(command)
    if spec is None:
        raise _field("command", f"{command} is not an allowed operation for {family}")
    p = _check_params(spec, params)
    out: dict[str, Any] = {}
    for name, value in p.items():
        kind = KEA_PARAM_TYPES[name]
        if kind == "int":
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise _field(name, "a non-negative integer")
        elif kind == "bool":
            if not isinstance(value, bool):
                raise _field(name, "true or false")
        elif kind == "ip":
            try:
                ipaddress.ip_address(str(value))
            except ValueError:
                raise _field(name, "an IP address") from None
            value = str(value)
        elif kind == "names":
            if not isinstance(value, list) or not all(
                isinstance(v, str) and _KEA_NAME_RE.match(v) for v in value
            ):
                raise _field(name, "a list of names")
        elif not isinstance(value, str) or not _KEA_NAME_RE.match(value):
            raise _field(name, "invalid value")
        out[name] = value
    if command == "cache-flush" and out:
        return out["count"]  # host_cache takes a bare integer, not an object
    return out or None


def _truncate(text: str) -> str:
    return text if len(text) <= MAX_OUTPUT else text[:MAX_OUTPUT] + "\n[truncated]"


def run_bind_read(backend: Any, op: str, params: dict[str, Any]) -> str:
    """Runs a read operation on a local backend; peers call this through the "op" snapshot kind."""
    spec = BIND_OPS.get(op)
    if spec is None or spec.write:
        raise _field("op", f"{op} is not a read operation")
    return _truncate(_rndc(backend).run(*rndc_words(op, params)))


def run_kea_read(backend: Any, family: str, command: str, params: dict[str, Any]) -> Any:
    spec = KEA_OPS.get(family, {}).get(command)
    if spec is None or spec.write:
        raise _field("command", f"{command} is not a read operation")
    return _socket(backend).call(command, kea_arguments(family, command, params), allow_empty=True)


def _rndc(backend: Any) -> Any:
    rndc = getattr(backend, "rndc", None)
    if rndc is None:
        raise ServiceError("not_supported", "this BIND connector has no rndc channel")
    return rndc


def _socket(backend: Any) -> Any:
    sock = getattr(backend, "socket", None)
    if sock is None:
        raise ServiceError("not_supported", "this Kea connector has no control socket")
    return sock


class OpsService:
    def __init__(self, ctx: NodeContext, registry: ConnectorRegistry, peers: PeerGateway) -> None:
        self.ctx = ctx
        self.registry = registry
        self.peers = peers

    # Catalogs ---------------------------------------------------------------------------

    def bind_catalog(self) -> dict[str, Any]:
        return {
            "node_id": self.ctx.node.id,
            "operations": [s.describe() for s in BIND_OPS.values()],
        }

    def kea_catalog(self, family: str, node_id: str | None = None) -> dict[str, Any]:
        """The allow-list intersected with the daemon's list-commands (hooks decide what exists)."""
        specs = self._kea_specs(family)
        available: list[str] | None = None
        error = None
        try:
            available = list(self._kea_read(family, "list-commands", {}, node_id) or [])
        except (ServiceError, ConnectorError) as exc:
            error = str(exc)
        ops = [
            {**s.describe(), "available": available is None or s.name in available} for s in specs.values()
        ]
        return {"node_id": node_id or self.ctx.node.id, "family": family, "operations": ops, "error": error}

    def spec(self, engine: str, name: str) -> OpSpec:
        """`engine` is "bind" or a Kea family; unknown names are a validation error."""
        table = BIND_OPS if engine == "bind" else self._kea_specs(engine)
        spec = table.get(name)
        if spec is None:
            raise _field("op" if engine == "bind" else "command", f"unknown operation {name}")
        return spec

    def _kea_specs(self, family: str) -> dict[str, OpSpec]:
        if family not in KEA_OPS:
            raise _field("family", "v4, v6 or d2")
        return KEA_OPS[family]

    # Execution ----------------------------------------------------------------------------

    def run_bind(
        self,
        op: str,
        params: dict[str, Any],
        node_id: str | None,
        confirm: bool,
        user: str,
        client_ip: str | None,
    ) -> dict[str, Any]:
        spec = self.spec("bind", op)
        words = rndc_words(op, params)
        self._check_confirm(spec, confirm)
        target = node_id or self.ctx.node.id
        if target != self.ctx.node.id and spec.write:
            output = self._run_remote(Engine.BIND, "bind", spec, params, confirm, target, user, client_ip)
        elif target != self.ctx.node.id:
            output = self._peer_read(target, Engine.BIND, spec, {"op": op, "params": params})
        else:
            backend = self.registry.dns
            if backend is None:
                raise EngineUnavailable("this node does not run BIND")
            output = self._run_local(
                Engine.BIND, spec, lambda: _truncate(_rndc(backend).run(*words)), user, client_ip, params
            )
        return {"op": op, "node_id": target, "output": output}

    def run_kea(
        self,
        family: str,
        command: str,
        params: dict[str, Any],
        node_id: str | None,
        confirm: bool,
        user: str,
        client_ip: str | None,
    ) -> dict[str, Any]:
        spec = self.spec(family, command)
        arguments = kea_arguments(family, command, params)
        self._check_confirm(spec, confirm)
        target = node_id or self.ctx.node.id
        engine = ENGINE_OF_FAMILY[family]
        if target != self.ctx.node.id and spec.write:
            result = self._run_remote(engine, family, spec, params, confirm, target, user, client_ip)
        elif target != self.ctx.node.id:
            result = self._peer_read(target, engine, spec, {"command": command, "params": params})
        else:
            backend = self.registry.backend(engine)
            if backend is None:
                raise EngineUnavailable(f"this node does not run {engine.value}")
            result = self._run_local(
                engine,
                spec,
                lambda: _socket(backend).call(command, arguments, allow_empty=True),
                user,
                client_ip,
                params,
            )
        return {"command": command, "family": family, "node_id": target, "result": result}

    def run_received(
        self,
        kind: str,
        name: str,
        params: dict[str, Any],
        confirm: bool,
        user: str,
        caller: str,
        client_ip: str | None,
    ) -> Any:
        """A write operation a peer forwards (`kind` "bind" or a Kea family), run and audited here as
        `node:<caller>` on behalf of `user`; the caller checked the user's permission."""
        spec = self.spec(kind, name)
        if not spec.write:
            raise _field("op", f"{name} is a read: peers read it through the op snapshot")
        self._check_confirm(spec, confirm)
        audit_params = {**params, "requested_by": user}
        if kind == "bind":
            words = rndc_words(name, params)
            dns = self.registry.dns
            if dns is None:
                raise EngineUnavailable("this node does not run BIND")
            call = lambda: _truncate(_rndc(dns).run(*words))  # noqa: E731
            return self._run_local(Engine.BIND, spec, call, f"node:{caller}", client_ip, audit_params)
        arguments = kea_arguments(kind, name, params)
        engine = ENGINE_OF_FAMILY[kind]
        backend = self.registry.backend(engine)
        if backend is None:
            raise EngineUnavailable(f"this node does not run {engine.value}")
        return self._run_local(
            engine,
            spec,
            lambda: _socket(backend).call(name, arguments, allow_empty=True),
            f"node:{caller}",
            client_ip,
            audit_params,
        )

    def _run_remote(
        self,
        engine: Engine,
        kind: str,
        spec: OpSpec,
        params: dict[str, Any],
        confirm: bool,
        node_id: str,
        user: str,
        client_ip: str | None,
    ) -> Any:
        """A write operation on a peer: the peer runs it and audits it, this node audits the request."""
        peer = self.peers.peer(node_id)
        if peer is None:
            raise ValidationError(f"unknown node {node_id}", [field_error("node_id", "unknown")])
        if not getattr(peer.modules, engine.value, False):
            raise EngineUnavailable(f"node {peer.name} does not run {engine.value}")
        body = {
            "engine": kind,
            "name": spec.name,
            "params": params,
            "confirm": confirm,
            "user": user,
            "client_ip": client_ip,
        }
        audit_params = {**params, "node_id": peer.id}
        try:
            output = (self.peers.action(peer, "ops.run", body) or {}).get("output")
        except ServiceError as exc:
            unknown = bool(exc.extra.get("outcome_unknown"))
            if unknown:
                # The peer may still run it (no cancellation): its own audit tells the outcome.
                exc.detail = f"{exc.detail}; outcome unknown, check the audit on {peer.name}"
                exc.args = (exc.detail,)
            error = AuditResult.ERROR
            self._audit(engine, spec, audit_params, None, error, exc.detail, user, client_ip, True, unknown)
            raise
        self._audit(engine, spec, audit_params, output, AuditResult.OK, None, user, client_ip, True)
        return output

    def _kea_read(self, family: str, command: str, params: dict[str, Any], node_id: str | None) -> Any:
        engine = ENGINE_OF_FAMILY[family]
        if node_id not in (None, self.ctx.node.id):
            return self._peer_read(
                node_id, engine, self.spec(family, command), {"command": command, "params": params}
            )
        backend = self.registry.backend(engine)
        if backend is None:
            raise EngineUnavailable(f"this node does not run {engine.value}")
        return run_kea_read(backend, family, command, params)

    @staticmethod
    def _check_confirm(spec: OpSpec, confirm: bool) -> None:
        if spec.confirm and not confirm:
            raise ServiceError("confirmation_required", f"{spec.name} needs confirm=true")

    def _peer_read(self, node_id: str, engine: Engine, spec: OpSpec, params: dict[str, Any]) -> Any:
        if spec.write:
            raise ServiceError("not_supported", f"{spec.name} changes the daemon: it is not a read")
        peer = self.peers.peer(node_id)
        if peer is None:
            raise ValidationError(f"unknown node {node_id}", [field_error("node_id", "unknown")])
        # Snapshot parameters travel as query strings: the typed parameters go as one JSON text.
        flat = {k: v for k, v in params.items() if k != "params"}
        flat["params"] = json.dumps(params.get("params") or {})
        snap = self.peers.snapshot(peer, engine, "op", flat)
        if snap is None:
            raise EngineUnavailable(f"node {peer.name} is not reachable")
        if snap.get("error"):
            raise EngineUnavailable(f"node {peer.name}: {snap['error']}")
        return snap.get("output")

    def _run_local(
        self,
        engine: Engine,
        spec: OpSpec,
        call: Any,
        user: str,
        client_ip: str | None,
        params: dict[str, Any],
    ) -> Any:
        if not spec.write:
            return call()
        try:
            with engine_lock(self.ctx.paths.locks_dir, engine.value):
                output = call()
            result, message = AuditResult.OK, None
        except Exception as exc:
            output, result, message = None, AuditResult.ERROR, str(exc)
            self._audit(engine, spec, params, output, result, message, user, client_ip)
            if isinstance(exc, ServiceError | ConnectorError):
                raise
            raise EngineUnavailable(f"{spec.name} failed: {exc}") from exc
        self._audit(engine, spec, params, output, result, message, user, client_ip)
        return output

    def _audit(
        self,
        engine: Engine,
        spec: OpSpec,
        params: dict[str, Any],
        output: Any,
        result: AuditResult,
        message: str | None,
        user: str,
        client_ip: str | None,
        remote: bool = False,
        outcome_unknown: bool = False,
    ) -> None:
        action = "dns.ops" if engine is Engine.BIND else "dhcp.ops"
        response = {"output": output, **({"remote": True} if remote else {})}
        if outcome_unknown:
            response["outcome_unknown"] = True
        self.ctx.audit_log.append(
            AuditEntry(
                node_id=self.ctx.node.id,
                user=user,
                action=action,
                target=f"{engine.value}:{spec.name}",
                engine=engine,
                request=masked({"op": spec.name, **params}),
                response=masked(response) if output is not None or remote else None,
                result=result,
                message=message,
                client_ip=client_ip,
            )
        )


def snapshot_op(registry: ConnectorRegistry, engine: Engine, params: dict[str, Any]) -> dict[str, Any]:
    """The "op" snapshot kind served to peers: read operations only."""
    backend = registry.backend(engine)
    raw = params.get("params") or "{}"
    typed = json.loads(raw) if isinstance(raw, str) else dict(raw)
    if not isinstance(typed, dict):
        raise _field("params", "an object")
    if engine is Engine.BIND:
        return {"output": run_bind_read(backend, str(params.get("op", "")), typed)}
    family = next(f for f, e in ENGINE_OF_FAMILY.items() if e is engine)
    return {"output": run_kea_read(backend, family, str(params.get("command", "")), typed)}
