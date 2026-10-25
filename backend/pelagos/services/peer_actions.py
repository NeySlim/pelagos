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
ADOPT_PLAN = "dhcp.adopt.plan"
CONFIG_PLAN = "dhcp.config.plan"
OPS_RUN = "ops.run"


class PeerActions:
    """The ActionHandler given to ReplicationApp; `registry` is the services ConnectorRegistry."""

    def __init__(self, ctx: NodeContext, registry: Any, lock: threading.RLock | None = None) -> None:
        self.ctx = ctx
        self.registry = registry
        self.lock = lock if lock is not None else threading.RLock()
        self.handlers: dict[str, Callable[[dict[str, Any], str], Any]] = {
            ZONE_PLAN: self.zone_plan,
            ADOPT_PLAN: self.adopt_plan,
            CONFIG_PLAN: self.config_plan,
            OPS_RUN: self.ops_run,
        }

    def __call__(self, name: str, body: dict[str, Any], caller: str) -> Any:
        handler = self.handlers.get(name)
        if handler is None:
            raise PeerActionError("not_supported", f"this node does not serve action {name}")
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

    # Plan builds ----------------------------------------------------------------------------

    def zone_plan(self, body: dict[str, Any], caller: str) -> dict[str, Any]:
        from pelagos.services.dns_service import parse_change

        backend = self.registry.dns
        if backend is None:
            raise EngineUnavailable("this node does not run BIND")
        change = parse_change(body.get("change"), "change")
        return self._plan(backend.plan_zone_change(change, _created_by(body)))

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

    def _dhcp_backend(self, body: dict[str, Any]) -> tuple[Engine, Any]:
        engine = DHCP_ENGINES.get(str(body.get("engine")))
        if engine is None:
            raise ValidationError("engine must be kea4, kea6 or d2", [field_error("engine", "invalid")])
        backend = self.registry.backend(engine)
        if backend is None:
            raise EngineUnavailable(f"this node does not run {engine.value}")
        return engine, backend

    def _plan(self, plan: Plan) -> dict[str, Any]:
        plan.target_node_ids = [self.ctx.node.id]
        return {"plan": plan.to_dict()}

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
