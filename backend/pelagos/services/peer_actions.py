# SPDX-License-Identifier: Apache-2.0
"""Writes another node asks this one to build or run: POST /repl/v1/actions/<name> (collector side).

The caller is a peer authenticated by its node certificate (section 13) that has already checked the
user's permissions the way a local request does. Plan builds run here because the plan reads this
node's engine and files; the plan goes back to the caller, which stores it and applies it here over
/plans/apply (audited on both nodes). Runtime operations run here and are audited here and there.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Any

from pelagos.connectors.base import (
    ConnectorDenied,
    ConnectorError,
    ConnectorTimeout,
    ConnectorUnavailable,
    NotSupported,
    PreconditionFailed,
    ValidationFailed,
)
from pelagos.connectors.kea.configfile import FileDiverged
from pelagos.core.context import NodeContext
from pelagos.core.plan_secrets import seal_backend_secrets
from pelagos.core.replication import PeerActionError
from pelagos.core.secrets import SecretError
from pelagos.domain import Engine, Family, Plan
from pelagos.services import d2_secrets, kea_files
from pelagos.services.errors import EngineUnavailable, ServiceError, ValidationError, field_error

log = logging.getLogger(__name__)

# The collector polls the same backend objects under this lock; a peer waits well below its timeout.
LOCK_TIMEOUT = 60.0
DHCP_ENGINES = {"kea4": Engine.KEA4, "kea6": Engine.KEA6, "d2": Engine.D2}
OPS_ENGINES = ("bind", "v4", "v6", "d2")

ZONE_PLAN = "dns.zone.plan"
DNS_CONFIG_PLAN = "dns.config.plan"
ADOPT_PLAN = "dhcp.adopt.plan"
CONFIG_PLAN = "dhcp.config.plan"
HA_PLAN = "dhcp.ha.plan"
# One part of a restore from an archive, built on this node's engine (services.archive_restore).
RESTORE_PART = "archive.restore.part"
OPS_RUN = "ops.run"
# Web UI certificate of this node (services.cert_service, core.webcert).
CERTS_STATUS = "certs.status"
CERTS_RUN = "certs.run"
CERTS_REQUEST = "certs.request"
CERTS_CHECK = "certs.check"
CERTS_UPLOAD = "certs.upload"
CERTS_SELF_SIGNED = "certs.self_signed"
# Security audit of this node (services.install_service): findings, and a plan for some of them.
SECURITY_AUDIT = "security.audit"
SECURITY_PLAN = "security.plan"
# The firewall guard of this node's Kea HA listeners (installer.ha_guard).
SECURITY_HA_GUARD = "security.ha_guard"
# This node's alerts, for a peer's cluster view (services.alerts_service).
ALERTS_LIST = "alerts.list"
# This node's resolver series (services.alerts_service.SeriesService.resolver).
RESOLVER_SERIES = "resolver.series"
# This node's entry of GET /dns/resolver/health (services.resolver_fallback, collector.resolver).
RESOLVER_HEALTH = "resolver.health"
# The notification dispatcher state of this node (collector.notify.read_state).
NOTIFY_STATE = "notify.state"
# Archives of this node (services.archive_service): run state, a run now, a probe file.
ARCHIVE_STATE = "archive.state"
ARCHIVE_RUN = "archive.run"
ARCHIVE_PROBE = "archive.probe"
# IPv6 addresses this node observed and the status of its sources (collector.ipv6.store).
IPV6_OBSERVATIONS = "ipv6.observations"
CERTS_ACTIONS = frozenset(
    {CERTS_STATUS, CERTS_RUN, CERTS_REQUEST, CERTS_CHECK, CERTS_UPLOAD, CERTS_SELF_SIGNED}
)
# Actions that never use the engine connectors: they run without the engine lock.
LOCKLESS = frozenset(
    {
        SECURITY_AUDIT,
        SECURITY_PLAN,
        SECURITY_HA_GUARD,
        ALERTS_LIST,
        RESOLVER_SERIES,
        RESOLVER_HEALTH,
        NOTIFY_STATE,
        ARCHIVE_STATE,
        ARCHIVE_RUN,
        ARCHIVE_PROBE,
        IPV6_OBSERVATIONS,
    }
)


class PeerActions:
    """The ActionHandler given to ReplicationApp; `registry` is the services ConnectorRegistry."""

    def __init__(self, ctx: NodeContext, registry: Any, lock: threading.RLock | None = None) -> None:
        self.ctx = ctx
        self.registry = registry
        self.lock = lock if lock is not None else threading.RLock()
        self.handlers: dict[str, Callable[[dict[str, Any], str], Any]] = {
            ZONE_PLAN: self.zone_plan,
            DNS_CONFIG_PLAN: self.dns_config_plan,
            ADOPT_PLAN: self.adopt_plan,
            CONFIG_PLAN: self.config_plan,
            HA_PLAN: self.ha_plan,
            RESTORE_PART: self.restore_part,
            OPS_RUN: self.ops_run,
            CERTS_STATUS: self.certs_status,
            CERTS_RUN: self.certs_run,
            CERTS_REQUEST: self.certs_request,
            CERTS_CHECK: self.certs_check,
            CERTS_UPLOAD: self.certs_upload,
            CERTS_SELF_SIGNED: self.certs_self_signed,
            SECURITY_AUDIT: self.security_audit,
            SECURITY_PLAN: self.security_plan,
            SECURITY_HA_GUARD: self.security_ha_guard,
            ALERTS_LIST: self.alerts_list,
            RESOLVER_SERIES: self.resolver_series,
            RESOLVER_HEALTH: self.resolver_health,
            NOTIFY_STATE: self.notify_state,
            ARCHIVE_STATE: self.archive_state,
            ARCHIVE_RUN: self.archive_run,
            ARCHIVE_PROBE: self.archive_probe,
            IPV6_OBSERVATIONS: self.ipv6_observations,
        }

    def __call__(self, name: str, body: dict[str, Any], caller: str) -> Any:
        handler = self.handlers.get(name)
        if handler is None:
            raise PeerActionError("not_supported", f"this node does not serve action {name}")
        if name in CERTS_ACTIONS or name in LOCKLESS:
            # Certificates and the security audit never use the engine connectors: no engine lock,
            # so a long poll never waits on it.
            try:
                return handler(body, caller)
            except PeerActionError:
                raise
            except Exception as exc:
                refusal = refusal_of(exc)
                if refusal is None:
                    raise
                raise refusal from None
        if not self.lock.acquire(timeout=LOCK_TIMEOUT):
            raise PeerActionError("engine_unavailable", "busy: the collector is reading the engines")
        try:
            return handler(body, caller)
        except PeerActionError:
            raise
        except Exception as exc:
            refusal = refusal_of(exc)
            if refusal is None:
                raise
            raise refusal from None
        finally:
            self.lock.release()

    # Reads ---------------------------------------------------------------------------------

    def alerts_list(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        """Alerts this node's collector holds; filters as AlertsService.cluster takes them."""
        import sqlite3

        from pelagos.collector import series as series_mod
        from pelagos.core.cluster_alerts import node_alerts

        def text(name: str) -> str | None:
            value = body.get(name)
            return str(value) if value not in (None, "") else None

        path = self.ctx.paths.series_db
        if not path.exists():
            return {"node_id": self.ctx.node.id, "alerts": [], "resolved_total": 0}
        try:
            conn = series_mod.connect(path, readonly=True)
        except sqlite3.Error as exc:
            raise PeerActionError("engine_unavailable", f"alert cache unreadable: {exc}") from None
        try:
            rows, resolved_total = node_alerts(
                conn,
                include_resolved=bool(body.get("include_resolved")),
                resolved_limit=int(body.get("resolved_limit") or 0),
                kind=text("kind"),
                severity=text("severity"),
                engine=text("engine"),
            )
        finally:
            conn.close()
        return {
            "node_id": self.ctx.node.id,
            "alerts": [a.to_dict() for a in rows],
            "resolved_total": resolved_total,
        }

    def resolver_series(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        """This node's series of one resolver metric, read from its own cache."""
        import sqlite3

        from pelagos.collector import series as series_mod
        from pelagos.collector.resolver import METRICS

        metric = body.get("metric")
        if metric not in METRICS:
            raise ValidationError("unknown resolver metric", [field_error("metric", "unknown")])
        path = self.ctx.paths.series_db
        if not path.exists():
            return {"node_id": self.ctx.node.id, "series": []}
        try:
            conn = series_mod.connect(path, readonly=True)
        except sqlite3.Error as exc:
            raise PeerActionError("engine_unavailable", f"series cache unreadable: {exc}") from None
        try:
            series = series_mod.SeriesStore(conn).resolver(
                metric=metric,
                node_id=self.ctx.node.id,
                since=int(body.get("since") or 0),
                until=int(body.get("until") or 0),
                step=int(body.get("step") or 300),
            )
        finally:
            conn.close()
        return {"node_id": self.ctx.node.id, "series": series}

    def ipv6_observations(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        """What this node observed (section 27), read from its series cache; `since` bounds last_seen."""
        import sqlite3

        from pelagos.collector import series as series_mod
        from pelagos.collector.ipv6 import store as obs_store

        since = body.get("since")
        try:
            since = int(since) if since not in (None, "") else None
        except (TypeError, ValueError):
            raise PeerActionError("invalid_request", "since must be a Unix time") from None
        path = self.ctx.paths.series_db
        if not path.exists():
            return obs_store.payload(None, self.ctx.node.id)
        try:
            conn = series_mod.connect(path, readonly=True)
        except sqlite3.Error as exc:
            raise PeerActionError("engine_unavailable", f"observation cache unreadable: {exc}") from None
        try:
            return obs_store.payload(conn, self.ctx.node.id, since)
        finally:
            conn.close()

    def resolver_health(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        """This node's NodeHealth, read from its own series cache and probe table."""
        import sqlite3
        import time

        from pelagos.collector import series as series_mod
        from pelagos.collector.resolver import node_health, served_tlds
        from pelagos.services.resolver_fallback import stale_after

        settings = self.ctx.settings()
        tlds = served_tlds(getattr(self.registry, "dns", None))
        now, stale = int(time.time()), stale_after(settings)
        path = self.ctx.paths.series_db
        if not path.exists():
            return node_health(None, self.ctx.node.id, now, stale, tlds)
        try:
            conn = series_mod.connect(path, readonly=True)
        except sqlite3.Error as exc:
            raise PeerActionError("engine_unavailable", f"series cache unreadable: {exc}") from None
        try:
            return node_health(series_mod.SeriesStore(conn), self.ctx.node.id, now, stale, tlds)
        finally:
            conn.close()

    def notify_state(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        """This node's dispatcher state, for the overview of a node that is not the sender."""
        from pelagos.collector.notify import read_state

        return read_state(self.ctx.paths)

    def archive_state(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        """This node's archive run state and newest archive (Administration > Backups)."""
        from pelagos.services.archive_service import node_state

        return node_state(self.ctx)

    def archive_run(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        """Asks this node's archive runner for a run now (the `archive` event of collector.sock)."""
        from pelagos.core.signals import signal_collector
        from pelagos.services.archive_service import EVENT_ARCHIVE

        if not signal_collector(self.ctx.paths.collector_sock, EVENT_ARCHIVE):
            raise PeerActionError("engine_unavailable", "the archive runner of this node is not listening")
        return {"requested": True}

    def archive_probe(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        """Writes, reads back and deletes a probe file where this node keeps its peers' archives."""
        from pelagos.services.archive_service import probe_local

        try:
            return probe_local(self.ctx)
        except OSError as exc:
            raise PeerActionError("engine_unavailable", f"archive folder not writable: {exc}") from None

    # Plan builds ----------------------------------------------------------------------------

    def zone_plan(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        from pelagos.services.dns_service import parse_change

        backend = self.registry.dns
        if backend is None:
            raise EngineUnavailable("this node does not run BIND")
        many = body.get("changes")
        if isinstance(many, list) and many:
            changes = [parse_change(c, f"changes[{i}]") for i, c in enumerate(many)]
            return self._plan(backend.plan_zone_changes(changes, _created_by(body)))
        change = parse_change(body.get("change"), "change")
        return self._plan(backend.plan_zone_change(change, _created_by(body)))

    def dns_config_plan(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        """Key, ACL and option changes rendered into this node's managed files (never raw files)."""
        from pelagos.services.dns_service import parse_change

        backend = self.registry.dns
        if backend is None:
            raise EngineUnavailable("this node does not run BIND")
        raw = body.get("changes")
        if not isinstance(raw, list) or not raw:
            raise ValidationError("changes must be a non-empty list", [field_error("changes", "required")])
        changes = [parse_change(c, f"changes[{i}]") for i, c in enumerate(raw)]
        for i, change in enumerate(changes):
            if change.target.split("/", 1)[0] not in ("keys", "acls", "options", "tls"):
                raise ValidationError(
                    "only keys/, acls/, options/ and tls/ changes are built for a peer",
                    [field_error(f"changes[{i}].target", "not allowed")],
                )
        return self._plan(backend.plan_config_change(changes, _created_by(body)))

    def adopt_plan(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        _engine, backend = self._dhcp_backend(body)
        source = body.get("source")
        if source not in ("file", "running"):
            raise ValidationError(
                "source must be file or running", [field_error("source", "file or running")]
            )
        return self._plan(backend.plan_adopt(source, _created_by(body)))

    def config_plan(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        """A whole-configuration replace of this node, built from the configuration it served."""
        from pelagos.services.dhcp_service import DhcpService
        from pelagos.services.peers import PeerGateway

        engine, backend = self._dhcp_backend(body)
        config = body.get("config")
        if not isinstance(config, dict):
            raise ValidationError("config must be an object", [field_error("config", "object expected")])
        created_by = _created_by(body)
        try:
            if engine is Engine.D2:
                plan = backend.plan_config_replace(config, created_by)
                if d2_secrets.needs_sealing(plan):
                    # The caller stores the plan and sends it back here: the secrets travel sealed.
                    seal_backend_secrets(plan, backend, self.ctx.secrets)
            else:
                family = Family.V4 if engine is Engine.KEA4 else Family.V6
                service = DhcpService(self.ctx, family, backend, PeerGateway(self.ctx))
                plan = service._build_config_plan("config", {"config": config}, backend, created_by)
        except FileDiverged as exc:
            raise kea_files.from_connector(engine, exc, self.ctx.node.id) from None
        return self._plan(plan)

    def ha_plan(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        """This node's part of an HA setup: its ha hook under `this_server` (`spec` null removes it),
        or under each relationship's `this_server` when `spec` holds `relationships` (hub and spoke)."""
        from pelagos.connectors.kea.ha import validate_relationships

        engine, backend = self._dhcp_backend(body)
        if engine is Engine.D2:
            raise ValidationError("engine must be kea4 or kea6", [field_error("engine", "invalid")])
        spec = body.get("spec")
        if spec is not None:
            if not isinstance(spec, dict):
                raise ValidationError("spec must be an object", [field_error("spec", "object expected")])
            problems = validate_relationships(spec)
            if problems:
                raise ValidationError(
                    f"invalid HA setup: {problems[0][0]}: {problems[0][1]}",
                    [field_error(f, m) for f, m in problems],
                )
        server = body.get("this_server")
        try:
            plan = backend.plan_ha_setup(spec, str(server) if server else None, _created_by(body))
        except FileDiverged as exc:
            raise kea_files.from_connector(engine, exc, self.ctx.node.id) from None
        return self._plan(plan)

    def _dhcp_backend(self, body: dict[str, Any]) -> tuple[Engine, Any]:
        engine = DHCP_ENGINES.get(str(body.get("engine")))
        if engine is None:
            raise ValidationError("engine must be kea4, kea6 or d2", [field_error("engine", "invalid")])
        backend = self.registry.backend(engine)
        if backend is None:
            raise EngineUnavailable(f"this node does not run {engine.value}")
        return engine, backend

    def restore_part(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        """The engine plans of one restore part on this node; D2 secrets travel sealed."""
        from pelagos.services.archive_restore import build_part

        part = body.get("part")
        payload = body.get("payload")
        if not isinstance(part, str) or not isinstance(payload, dict):
            raise ValidationError("part and payload are required", [field_error("part", "required")])
        plans, summary = build_part(self.registry, part, payload, _created_by(body))
        for plan in plans:
            if d2_secrets.needs_sealing(plan) and self.registry.d2 is not None:
                seal_backend_secrets(plan, self.registry.d2, self.ctx.secrets)
            plan.target_node_ids = [self.ctx.node.id]
        return {"plans": [p.to_dict() for p in plans], "summary": summary}

    def _plan(self, plan: Plan) -> dict[str, Any]:
        plan.target_node_ids = [self.ctx.node.id]
        return {"plan": plan.to_dict()}

    # Security audit -------------------------------------------------------------------------

    def security_audit(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        from pelagos.services.install_service import InstallService

        return {"findings": InstallService(self.ctx).security()}

    def security_plan(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        """This node's part of a security plan; the shared key switch stays on this node."""
        from pelagos.services.install_service import InstallService

        service = InstallService(self.ctx)
        if body.get("ha_guard") is not None:
            guard = body["ha_guard"] if isinstance(body["ha_guard"], dict) else {}
            return self._plan(service.build_ha_guard_part(guard.get("peers"), _created_by(body)))
        return self._plan(service.build_security_part(body.get("finding_ids"), _created_by(body), False))

    def security_ha_guard(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        from pelagos.services.install_service import InstallService

        return {"guard": InstallService(self.ctx).local_ha_guard()}

    # Runtime operations ---------------------------------------------------------------------

    def ops_run(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        from pelagos.services.ops_service import OpsService
        from pelagos.services.peers import PeerGateway

        engine = str(body.get("engine"))
        if engine not in OPS_ENGINES:
            raise ValidationError("engine must be bind, v4, v6 or d2", [field_error("engine", "invalid")])
        params = body.get("params") or {}
        if not isinstance(params, dict):
            raise ValidationError("params must be an object", [field_error("params", "object expected")])
        ops = OpsService(self.ctx, self.registry, PeerGateway(self.ctx))
        output = ops.run_received(
            engine,
            str(body.get("name") or ""),
            params,
            bool(body.get("confirm")),
            user=str(body.get("user") or "unknown"),
            caller=caller,
            client_ip=body.get("client_ip") if isinstance(body.get("client_ip"), str) else None,
        )
        return {"output": output}

    # Web certificate --------------------------------------------------------------------------

    def _certs(self) -> Any:
        from pelagos.core.webcert.manager import CertManager

        return CertManager(self.ctx)

    def certs_status(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        return self._certs().status()

    def certs_run(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        """Start this node's issuance in the background; the caller polls certs.status for the job."""
        from pelagos.core.webcert.manager import Busy, CertFailure

        certs = self._certs()
        actor = str(body.get("actor") or "unknown")
        job_id = str(body.get("job_id") or "") or None
        # Refused at once while another request runs here: the caller would wait for a job never started.
        try:
            with certs.exclusive():
                pass
        except Busy as exc:
            raise PeerActionError("conflict", str(exc)) from None

        def run() -> None:
            try:
                certs.issue(actor=actor, trigger="apply", job_id=job_id)
            except CertFailure as exc:
                log.info("certificate request from %s failed: %s", caller, exc)

        threading.Thread(target=run, name="webcert-issue", daemon=True).start()
        return {"started": True}

    def certs_request(self, body: dict[str, Any], caller: str) -> Any:
        certs = self._certs()
        actor = str(body.get("actor") or "unknown")
        if body.get("drop"):
            certs.drop_request(actor)
            return {"dropped": True}
        names = body.get("names") or []
        if not isinstance(names, list):
            raise ValidationError("names must be a list", [field_error("names", "list expected")])
        return certs.make_request(str(body.get("key_type") or "ec-p256"), [str(n) for n in names], actor)

    def _material(self, certs: Any, body: dict[str, Any]) -> Any:
        from pelagos.core.webcert import pem

        key_pem = None
        if body.get("key_sealed"):
            if self.ctx.secrets is None:
                raise ValidationError("no master key on this node", [field_error("key", "no master key")])
            key_pem = self.ctx.secrets.decrypt(f"certs/upload/{self.ctx.node.id}", str(body["key_sealed"]))
        try:
            return certs.material(
                str(body.get("certs_pem") or ""),
                None,
                key_pem,
                use_pending_key=bool(body.get("use_pending_key")),
            )
        except pem.CertError as exc:
            raise ValidationError(str(exc), [field_error("cert_pem", str(exc))]) from None

    def certs_check(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        certs = self._certs()
        return certs.check(self._material(certs, body)).to_dict()

    def certs_upload(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        from pelagos.core.webcert.manager import CertFailure

        certs = self._certs()
        mat = self._material(certs, body)
        try:
            out = certs.upload(
                mat, str(body.get("actor") or "unknown"), used_pending=bool(body.get("use_pending_key"))
            )
        except CertFailure as exc:
            return {
                "installed": False,
                "error": str(exc),
                "checks": exc.report.to_dict() if exc.report else None,
            }
        return {"installed": True, **out}

    def certs_self_signed(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        from pelagos.core.webcert.manager import CertFailure

        try:
            return self._certs().self_signed(str(body.get("actor") or "unknown"))
        except CertFailure as exc:
            raise ValidationError(str(exc), [field_error("certificate", str(exc))]) from None


def _created_by(body: dict[str, Any]) -> str:
    return str(body.get("created_by") or "")


def refusal_of(exc: BaseException) -> PeerActionError | None:
    """The answer a peer gets for a service or connector error; None for anything unexpected."""
    if isinstance(exc, ServiceError):
        return PeerActionError(exc.code, exc.detail, exc.errors)
    if isinstance(exc, ValidationFailed):
        r = exc.result
        return PeerActionError(
            "engine_validation_failed",
            f"{r.tool} rejected the change",
            [{"field": r.tool, "message": r.output, "node_id": r.node_id}],
        )
    if isinstance(exc, PreconditionFailed | SecretError):
        return PeerActionError("precondition_failed", str(exc))
    if isinstance(exc, NotSupported):
        return PeerActionError("not_supported", str(exc))
    if isinstance(exc, ConnectorUnavailable | ConnectorTimeout | ConnectorDenied):
        return PeerActionError("engine_unavailable", str(exc))
    if isinstance(exc, ConnectorError):
        return PeerActionError("conflict", str(exc))
    return None
