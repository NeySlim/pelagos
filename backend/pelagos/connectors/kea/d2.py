# SPDX-License-Identifier: Apache-2.0
"""D2 (kea-dhcp-ddns) connector: statistics per key, configuration read and the config replace plan.

TSIG secrets never go into the configuration file on Kea 3.x: a clear
`secret` in a submitted configuration is written to a 0640 secret file next
to the D2 configuration through the write pipeline, and the key references it
with `secret-file`. The secret itself stays out of the Plan.
"""

from __future__ import annotations

import hashlib
import re
from datetime import timedelta
from pathlib import Path
from typing import Any

from pelagos.connectors.base import ConnectorContext, ConnectorError, DdnsBackend, PreconditionFailed
from pelagos.connectors.kea.commands import normalize_version
from pelagos.connectors.kea.config import canonical, config_diff, normalize_root
from pelagos.connectors.kea.control_socket import KeaControlSocket
from pelagos.connectors.kea.schema import config_schema
from pelagos.core.write_pipeline import FileChange
from pelagos.domain import (
    Change,
    ChangeOp,
    D2Stats,
    Engine,
    NodeApplyResult,
    Plan,
    PlanScope,
    PlanState,
    Precondition,
    PreconditionKind,
    ValidationResult,
    utcnow,
)

_KEY_STAT = re.compile(r"^key\[(?P<key>[^\]]+)\]\.(?P<name>.+)$")
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
ROOT = "DhcpDdns"


def reduce_d2_stats(node_id: str, stats: dict[str, Any]) -> D2Stats:
    """statistic-get-all gives name -> [[value, timestamp], ...]; keep the latest value."""
    totals: dict[str, int] = {}
    per_key: dict[str, dict[str, int]] = {}
    for name, samples in stats.items():
        value = int(samples[0][0]) if samples else 0
        m = _KEY_STAT.match(name)
        if m:
            per_key.setdefault(m.group("key"), {})[m.group("name")] = value
        else:
            totals[name] = value
    return D2Stats(node_id=node_id, collected_at=utcnow(), totals=totals, per_key=per_key, raw=stats)


def secret_file_name(key_name: str) -> str:
    return _SAFE.sub("_", key_name.rstrip(".")) + ".secret"


def externalize_secrets(config: dict[str, Any], secret_dir: Path) -> tuple[dict[str, Any], dict[Path, str]]:
    """Move clear `secret` values of tsig-keys to secret files; returns (config, {path: secret})."""
    out = dict(config)
    files: dict[Path, str] = {}
    keys = []
    for key in config.get("tsig-keys") or []:
        key = dict(key)
        secret = key.pop("secret", None)
        if secret and not key.get("secret-file"):
            path = secret_dir / secret_file_name(str(key.get("name", "key")))
            key["secret-file"] = str(path)
            files[path] = str(secret)
        elif secret:
            key["secret"] = secret
        keys.append(key)
    if "tsig-keys" in config:
        out["tsig-keys"] = keys
    return out, files


def mask_secrets(config: dict[str, Any]) -> dict[str, Any]:
    out = dict(config)
    if "tsig-keys" in config:
        out["tsig-keys"] = [
            {**k, "secret": "***"} if k.get("secret") else dict(k) for k in config["tsig-keys"]
        ]
    return out


class D2Backend(DdnsBackend):
    def __init__(self, ctx: ConnectorContext) -> None:
        super().__init__(ctx)
        cfg = ctx.engine_config
        self.socket = KeaControlSocket(
            Path(cfg.get("socket_dir", "/run/kea")) / cfg.get("d2_socket", "kea-ddns-ctrl-socket")
        )
        self.conf_path = Path(cfg.get("d2_conf", "/etc/kea/kea-dhcp-ddns.conf"))
        self.secret_dir = Path(cfg.get("d2_secret_dir", str(self.conf_path.parent)))
        self.secret_group: str | None = cfg.get("kea_group")
        self.backup_root = Path(ctx.backup_root) / "d2"
        self.plan_ttl = int((ctx.settings or {}).get("plan_ttl_seconds", 600))
        # Secrets and backup directories of plans built here, keyed by plan id; never serialized.
        self._pending_secrets: dict[str, dict[Path, str]] = {}
        self._backups: dict[str, Path] = {}

    # Observation ----------------------------------------------------------------------

    def capabilities(self) -> dict[str, Any]:
        try:
            version = self.socket.version()
            return {"running": True, "version": version or None, "control_socket": str(self.socket.path)}
        except Exception as exc:
            return {
                "running": False,
                "version": None,
                "control_socket": str(self.socket.path),
                "error": str(exc),
            }

    def status(self) -> dict[str, Any]:
        return self.socket.status()

    def config_schema(self) -> dict[str, Any]:
        return config_schema("d2", normalize_version(self.socket.version()))

    def config_get(self) -> dict[str, Any]:
        return self.socket.config_get()[ROOT]

    def config_hash(self) -> str:
        return self.socket.config_hash()

    def stats(self) -> D2Stats:
        return reduce_d2_stats(self.ctx.node_id, self.socket.statistic_get_all())

    def config_test(self, config: dict[str, Any]) -> ValidationResult:
        resp = self.socket.send("config-test", {ROOT: config})
        return ValidationResult(
            ok=int(resp.get("result", 1)) == 0,
            tool="config-test",
            output=str(resp.get("text", "")),
            node_id=self.ctx.node_id,
        )

    # Plan ----------------------------------------------------------------------------------

    def plan_config_replace(self, config: dict[str, Any], created_by: str = "") -> Plan:
        if ROOT in config and len(config) <= 2:
            config = config[ROOT]
        before = self.config_get()
        current_hash = self.config_hash()
        config = normalize_root(config, normalize_version(self.socket.version()))
        new_cfg, secrets = externalize_secrets(config, self.secret_dir)
        if secrets:
            # The files do not exist yet, so Kea cannot test this configuration before apply.
            validation = ValidationResult(
                ok=True,
                tool="config-test",
                output="deferred: secret files are written at apply",
                node_id=self.ctx.node_id,
            )
        else:
            validation = self.config_test(new_cfg)
        changes = [Change(ChangeOp.REPLACE, "config", before=before, after=new_cfg)]
        for path, secret in secrets.items():
            digest = hashlib.sha256(secret.encode()).hexdigest()
            changes.append(
                Change(ChangeOp.ADD, f"secret-file/{path.name}", after={"path": str(path), "sha256": digest})
            )
        plan = Plan(
            scope=PlanScope.D2_CONFIG,
            node_id=self.ctx.node_id,
            summary="kea-dhcp-ddns: replace configuration"
            + (f" ({len(secrets)} secret file(s))" if secrets else ""),
            created_by=created_by,
            engine=Engine.D2,
            changes=changes,
            diff=config_diff(before, mask_secrets(new_cfg), str(self.conf_path)),
            preconditions=[
                Precondition(
                    kind=PreconditionKind.CONFIG_HASH,
                    subject="d2:config",
                    value=current_hash,
                    node_id=self.ctx.node_id,
                )
            ],
            validations=[validation],
            target_node_ids=[self.ctx.node_id],
            state=PlanState.VALIDATED if validation.ok else PlanState.FAILED,
            expires_at=utcnow() + timedelta(seconds=self.plan_ttl),
            error=None if validation.ok else validation.output,
        )
        if secrets:
            self._pending_secrets[plan.id] = secrets
        return plan

    # Apply and rollback -------------------------------------------------------------------------

    def _config_change(self, plan: Plan) -> Change:
        for change in plan.changes:
            if change.target == "config":
                return change
        raise ConnectorError("plan has no config change")

    def _pipeline(self, new_cfg: dict[str, Any], before_hash: str, label: str) -> Any:
        def reload() -> str:
            self.socket.call("config-set", {ROOT: new_cfg})
            written = self.socket.call("config-write")
            return f"config-set, config-write {written.get('filename', '')}"

        def verify() -> bool:
            return self.config_hash() != before_hash or canonical(self.config_get()) == canonical(new_cfg)

        return self.ctx.pipeline_factory(
            self.backup_root,
            validate=lambda: self.config_test(new_cfg),
            reload=reload,
            verify=verify,
            label=label,
        )

    def apply(self, plan: Plan) -> NodeApplyResult:
        for p in plan.preconditions:
            if p.kind is PreconditionKind.CONFIG_HASH and p.node_id in (None, self.ctx.node_id):
                observed = self.config_hash()
                if observed != p.value:
                    raise PreconditionFailed(p, observed)
        change = self._config_change(plan)
        return self._write(dict(change.after), plan.id, self._pending_secrets.pop(plan.id, {}))

    def rollback(self, plan: Plan) -> NodeApplyResult:
        change = self._config_change(plan)
        result = self._write(dict(change.before), f"{plan.id}-rollback", {})
        backup = self._backups.pop(plan.id, None)
        if backup is not None and result.ok:
            # Secret files written by the plan go back to what they were (or disappear).
            self._pipeline(dict(change.before), "", f"{plan.id}-restore").restore(backup)
        return result

    def _write(self, new_cfg: dict[str, Any], label: str, secrets: dict[Path, str]) -> NodeApplyResult:
        before_hash = self.config_hash()
        files = [
            FileChange(path=path, content=secret.encode(), mode=0o640, group=self.secret_group)
            for path, secret in secrets.items()
        ]
        pipeline = self._pipeline(new_cfg, before_hash, label)
        # The configuration file itself is written by Kea (config-write); back it up alongside.
        targets = [*secrets]
        if self.conf_path.exists():
            targets.append(self.conf_path)
        # Own label: pipeline.run() makes its backup right after, possibly within the same millisecond.
        snapshot = self._pipeline(new_cfg, before_hash, f"{label}-before")
        try:
            backup_dir = snapshot.backup(targets) if targets else None
        except OSError as exc:
            return NodeApplyResult(node_id=self.ctx.node_id, ok=False, message=f"backup failed: {exc}")
        if backup_dir is not None and not label.endswith("-rollback"):
            self._backups[label] = backup_dir
        try:
            if files:
                result = pipeline.run(files)
                ok, rolled_back, error = result.ok, result.rolled_back, result.error
                steps = ", ".join(f"{s['name']}:{'ok' if s['ok'] else 'failed'}" for s in result.steps)
            else:
                validation = self.config_test(new_cfg)
                if not validation.ok:
                    return NodeApplyResult(
                        node_id=self.ctx.node_id, ok=False, message=f"config-test: {validation.output}"
                    )
                self.socket.call("config-set", {ROOT: new_cfg})
                self.socket.call("config-write")
                ok, rolled_back, error, steps = True, False, None, "config-test, config-set, config-write"
        except ConnectorError as exc:
            # config-set refused or config-write failed after it: put the running config back.
            rolled_back = self._restore_running(before_hash)
            return NodeApplyResult(
                node_id=self.ctx.node_id, ok=False, message=str(exc), rolled_back=rolled_back
            )
        if not ok and self.config_hash() != before_hash:
            rolled_back = self._restore_running(before_hash) or rolled_back
        message = (
            f"{steps}; config-hash {before_hash[:12]} -> {self.config_hash()[:12]}"
            if ok
            else (error or "failed")
        )
        return NodeApplyResult(node_id=self.ctx.node_id, ok=ok, message=message, rolled_back=rolled_back)

    def _restore_running(self, before_hash: str) -> bool:
        try:
            if self.config_hash() == before_hash:
                return True
            self.socket.call("config-reload")
            return self.config_hash() == before_hash
        except ConnectorError:
            return False
