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
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from pelagos.connectors.base import ConnectorContext, ConnectorError, DdnsBackend, PreconditionFailed
from pelagos.connectors.kea.commands import normalize_version
from pelagos.connectors.kea.config import canonical, config_diff, normalize_root
from pelagos.connectors.kea.configfile import ADOPT_FILE, ADOPT_TARGETS, KeaConfigFile
from pelagos.connectors.kea.control_socket import DEFAULT_COMMAND_TIMEOUT, KeaControlSocket
from pelagos.connectors.kea.schema import config_schema
from pelagos.connectors.kea.secrets import masked_refusal
from pelagos.core import settings_registry as reg
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
    messages,
    utcnow,
)
from pelagos.domain.messages import Message

_KEY_STAT = re.compile(r"^key\[(?P<key>[^\]]+)\]\.(?P<name>.+)$")
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
ROOT = "DhcpDdns"
MASK = "***"


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
        # With both set, the secret file wins and the clear secret is dropped.
        secret = key.pop("secret", None)
        if secret and not key.get("secret-file"):
            path = secret_dir / secret_file_name(str(key.get("name", "key")))
            key["secret-file"] = str(path)
            files[path] = str(secret)
        keys.append(key)
    if "tsig-keys" in config:
        out["tsig-keys"] = keys
    return out, files


def has_clear_secrets(config: dict[str, Any]) -> bool:
    return any(k.get("secret") for k in config.get("tsig-keys") or [])


@dataclass(slots=True)
class _PlanPrivate:
    """What a plan needs at apply or rollback but must never carry: secrets, backup path."""

    expires_at: datetime
    secrets: dict[Path, str]
    before: dict[str, Any] | None = None  # the real before state when it holds clear secrets
    backup: Path | None = None
    after_hash: str | None = None  # config-hash right after the apply: rollback refuses once it moved


def unmask_d2_keys(config: dict[str, Any], running: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Masked tsig-key secrets take the running key of the same name: its clear secret, or its
    secret-file; returns (config, names of keys with no running value)."""
    if not any(isinstance(k, dict) and k.get("secret") == MASK for k in config.get("tsig-keys") or []):
        return config, []
    known = {str(k.get("name")): k for k in running.get("tsig-keys") or [] if isinstance(k, dict)}
    keys, missing = [], []
    for key in config.get("tsig-keys") or []:
        if isinstance(key, dict) and key.get("secret") == MASK:
            key = dict(key)
            name = str(key.get("name", ""))
            run = known.get(name) or {}
            if run.get("secret-file"):
                key.pop("secret")
                key.setdefault("secret-file", run["secret-file"])
            elif run.get("secret") and run["secret"] != MASK:
                key["secret"] = run["secret"]
            elif key.get("secret-file"):
                key.pop("secret")
            else:
                missing.append(f"tsig-keys/{name}")
        keys.append(key)
    return {**config, "tsig-keys": keys}, missing


def has_masked_secrets(config: Any) -> bool:
    return isinstance(config, dict) and any(k.get("secret") == MASK for k in config.get("tsig-keys") or [])


def mask_secrets(config: dict[str, Any]) -> dict[str, Any]:
    out = dict(config)
    if "tsig-keys" in config:
        out["tsig-keys"] = [
            {**k, "secret": MASK} if k.get("secret") else dict(k) for k in config["tsig-keys"]
        ]
    return out


class D2Backend(DdnsBackend):
    def __init__(self, ctx: ConnectorContext) -> None:
        super().__init__(ctx)
        cfg = ctx.engine_config
        self.socket = KeaControlSocket(
            Path(cfg.get("socket_dir", "/run/kea")) / cfg.get("d2_socket", "kea-ddns-ctrl-socket"),
            command_timeout=float(cfg.get("command_timeout", DEFAULT_COMMAND_TIMEOUT)),
        )
        self.conf_path = Path(cfg.get("d2_conf", "/etc/kea/kea-dhcp-ddns.conf"))
        self.secret_dir = Path(cfg.get("d2_secret_dir", str(self.conf_path.parent)))
        self.secret_group: str | None = cfg.get("kea_group")
        self.backup_root = Path(ctx.backup_root) / "d2"
        self.plan_ttl = int(reg.get(ctx.settings, "plans.ttl_seconds"))
        # Per plan id, never serialized; dropped once the plan can no longer be applied or rolled back.
        self._private: dict[str, _PlanPrivate] = {}
        self.file = KeaConfigFile(
            self.conf_path,
            ROOT,
            "d2",
            lambda: self.socket,
            ctx.pipeline_factory,
            self.backup_root,
            ctx.node_id,
            cwd=Path(cfg.get("kea_cwd", "/")),
        )

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

    def _sweep(self) -> None:
        now = utcnow()
        for plan_id in [k for k, v in self._private.items() if v.expires_at <= now]:
            del self._private[plan_id]

    def plan_config_replace(self, config: dict[str, Any], created_by: str = "") -> Plan:
        self._sweep()
        if ROOT in config and len(config) <= 2:
            config = config[ROOT]
        before = self.config_get()
        self.file.guard(before)
        current_hash = self.config_hash()
        config = normalize_root(config, normalize_version(self.socket.version()))
        config, missing = unmask_d2_keys(config, before)
        if missing:
            raise ConnectorError(masked_refusal(missing))
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
        masked_before = mask_secrets(before)
        changes = [Change(ChangeOp.REPLACE, "config", before=masked_before, after=new_cfg)]
        for path, secret in secrets.items():
            digest = hashlib.sha256(secret.encode()).hexdigest()
            changes.append(
                Change(ChangeOp.ADD, f"secret-file/{path.name}", after={"path": str(path), "sha256": digest})
            )
        plan = Plan(
            scope=PlanScope.D2_CONFIG,
            node_id=self.ctx.node_id,
            **_summary(
                messages.msg("plan.kea.replace_config", engine="kea-dhcp-ddns"),
                messages.msg("note.secret_files", count=len(secrets)) if secrets else None,
            ),
            created_by=created_by,
            engine=Engine.D2,
            changes=changes,
            diff=config_diff(masked_before, mask_secrets(new_cfg), str(self.conf_path)),
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
        clear_before = has_clear_secrets(before)
        if secrets or clear_before:
            self._private[plan.id] = _PlanPrivate(
                expires_at=plan.expires_at or utcnow() + timedelta(seconds=self.plan_ttl),
                secrets=secrets,
                before=before if clear_before else None,
            )
        return plan

    # Secrets of plans applied on several nodes ---------------------------------------------------

    def plan_secrets(self, plan_id: str) -> dict[str, str]:
        """{secret file path: clear secret} held for a plan this backend built; sealed into the plan
        by `core.plan_secrets.seal_backend_secrets` before the plan goes to peers."""
        self._sweep()
        private = self._private.get(plan_id)
        return {str(path): secret for path, secret in (private.secrets if private else {}).items()}

    def accept_plan_secrets(self, plan: Plan, secrets: dict[str, str]) -> None:
        """Secrets of a plan built on another node: only the files the plan declares, matching digests."""
        self._sweep()
        declared = {
            str(c.after.get("path")): str(c.after.get("sha256") or "")
            for c in plan.changes
            if c.target.startswith("secret-file/") and isinstance(c.after, dict)
        }
        accepted: dict[Path, str] = {}
        for path, secret in secrets.items():
            if path not in declared:
                raise ConnectorError(f"secret for {path} is not declared by plan {plan.id}")
            if declared[path] and hashlib.sha256(secret.encode()).hexdigest() != declared[path]:
                raise ConnectorError(f"secret for {path} does not match the plan digest")
            if not self._is_secret_path(path):
                raise ConnectorError(f"secret path {path} is outside {self.secret_dir}")
            accepted[Path(path)] = secret
        if not accepted:
            return
        expires = utcnow() + timedelta(seconds=self.plan_ttl)
        private = self._private.setdefault(plan.id, _PlanPrivate(expires_at=expires, secrets={}))
        private.secrets = accepted

    def _is_secret_path(self, path: str) -> bool:
        """Peers may only write `<d2_secret_dir>/<secret_file_name(...)>`, never an arbitrary file."""
        candidate = Path(path)
        name = candidate.name
        return (
            candidate.is_absolute()
            and ".." not in candidate.parts
            and candidate.parent.resolve() == self.secret_dir.resolve()
            and name.endswith(".secret")
            and name == secret_file_name(name[: -len(".secret")])
        )

    # Apply and rollback -------------------------------------------------------------------------

    def _config_change(self, plan: Plan) -> Change:
        for change in plan.changes:
            if change.target == "config":
                return change
        raise ConnectorError("plan has no config change")

    def _pipeline(
        self,
        new_cfg: dict[str, Any],
        before_hash: str,
        label: str,
        doc: Any = None,
        before_body: dict[str, Any] | None = None,
    ) -> Any:
        def reload() -> str:
            self.socket.call("config-set", {ROOT: new_cfg})
            return f"config-set, {self.file.persist(doc, before_body or {}, label, [new_cfg])}"

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
        self._sweep()
        adopt = next((c for c in plan.changes if c.target in ADOPT_TARGETS), None)
        if adopt is not None:
            return self._apply_adopt(plan, adopt)
        change = self._config_change(plan)
        private = self._private.get(plan.id)
        secrets = private.secrets if private else {}
        if private:
            # Secrets are no longer needed; what rollback needs stays for the rollback window.
            private.secrets = {}
            private.expires_at = utcnow() + timedelta(seconds=self.plan_ttl)
        return self._remember(plan.id, self._write(dict(change.after), plan.id, secrets))

    def _remember(self, plan_id: str, result: NodeApplyResult) -> NodeApplyResult:
        if result.ok:
            private = self._private.setdefault(
                plan_id, _PlanPrivate(expires_at=utcnow() + timedelta(seconds=self.plan_ttl), secrets={})
            )
            try:
                private.after_hash = self.config_hash()
            except ConnectorError:
                private.after_hash = None
        return result

    def _check_stale(self, plan: Plan) -> None:
        """A rollback after a later D2 change (another plan, the key switch, a hand edit) would undo
        it with this plan's whole before state: refused once the running hash moved."""
        private = self._private.get(plan.id)
        if private is None or private.after_hash is None:
            return
        observed = self.config_hash()
        if observed != private.after_hash:
            raise PreconditionFailed(
                Precondition(PreconditionKind.CONFIG_HASH, "d2:config", private.after_hash, self.ctx.node_id),
                observed,
            )

    def rollback(self, plan: Plan) -> NodeApplyResult:
        self._sweep()
        self._check_stale(plan)
        adopt = next((c for c in plan.changes if c.target in ADOPT_TARGETS), None)
        if adopt is not None:
            return self._rollback_adopt(plan, adopt)
        change = self._config_change(plan)
        private = self._private.pop(plan.id, None)
        before = private.before if private and private.before is not None else change.before
        if has_masked_secrets(before):
            return NodeApplyResult(
                node_id=self.ctx.node_id,
                ok=False,
                message="the before state of this plan is no longer held; restore from the backup directory",
            )
        result = self._write(dict(before), f"{plan.id}-rollback", {})
        backup = private.backup if private else None
        if backup is not None and result.ok:
            # Secret files written by the plan go back to what they were (or disappear).
            self._pipeline(dict(before), "", f"{plan.id}-restore").restore(backup, reload=False)
        return result

    # Adopt (section 9) ---------------------------------------------------------------------------

    def plan_adopt(self, source: str, created_by: str = "") -> Plan:
        """adopt "file": config-test and config-set of what the file says; adopt "running": the file
        is rewritten to say what kea-dhcp-ddns runs (patched losslessly, else config-write)."""
        self._sweep()
        running = self.config_get()
        current_hash = self.config_hash()
        doc = self.file.document()
        change, diff, differences = self.file.plan_adopt(source, running, doc)
        if source == "file":
            body = (doc.value if doc else {}).get(ROOT)
            validation = (
                self.config_test(body)
                if isinstance(body, dict)
                else ValidationResult(
                    ok=False, tool="read", output=f"no {ROOT} object", node_id=self.ctx.node_id
                )
            )
        else:
            validation = ValidationResult(
                ok=True, tool="lossless-editor", output=change.after["mode"], node_id=self.ctx.node_id
            )
        summary = messages.msg(
            "plan.kea.adopt_file" if source == "file" else "plan.kea.write_running",
            engine="kea-dhcp-ddns",
            path=str(self.conf_path),
        )
        plan = Plan(
            scope=PlanScope.D2_CONFIG,
            node_id=self.ctx.node_id,
            **_summary(summary, None if differences else messages.msg("note.no_difference")),
            created_by=created_by,
            engine=Engine.D2,
            changes=[change],
            diff=diff,
            preconditions=[
                Precondition(PreconditionKind.CONFIG_HASH, "d2:config", current_hash, self.ctx.node_id),
                *self.file.preconditions(doc),
            ],
            validations=[validation],
            target_node_ids=[self.ctx.node_id],
            requires_confirmation=True,
            state=PlanState.VALIDATED if validation.ok else PlanState.FAILED,
            expires_at=utcnow() + timedelta(seconds=self.plan_ttl),
            error=None if validation.ok else validation.output,
        )
        # The running configuration holds clear TSIG secrets: it stays out of the plan.
        self._private[plan.id] = _PlanPrivate(
            expires_at=plan.expires_at or utcnow() + timedelta(seconds=self.plan_ttl),
            secrets={},
            before=running,
        )
        return plan

    def _apply_adopt(self, plan: Plan, change: Change) -> NodeApplyResult:
        try:
            message, backup = self.file.apply_adopt(change, plan.id, self.config_test)
        except ConnectorError as exc:
            return NodeApplyResult(node_id=self.ctx.node_id, ok=False, message=str(exc))
        private = self._private.setdefault(
            plan.id, _PlanPrivate(expires_at=utcnow() + timedelta(seconds=self.plan_ttl), secrets={})
        )
        private.backup = backup
        private.expires_at = utcnow() + timedelta(seconds=self.plan_ttl)
        return self._remember(plan.id, NodeApplyResult(node_id=self.ctx.node_id, ok=True, message=message))

    def _rollback_adopt(self, plan: Plan, change: Change) -> NodeApplyResult:
        private = self._private.pop(plan.id, None)
        if change.target == ADOPT_FILE:
            if private is None or private.before is None:
                return NodeApplyResult(
                    node_id=self.ctx.node_id,
                    ok=False,
                    message="the configuration this plan replaced is no longer held",
                )
            try:
                self.socket.call("config-set", {ROOT: private.before})
            except ConnectorError as exc:
                return NodeApplyResult(node_id=self.ctx.node_id, ok=False, message=str(exc))
            return NodeApplyResult(
                node_id=self.ctx.node_id,
                ok=True,
                message="previous running configuration set back",
                rolled_back=True,
            )
        if private is None or private.backup is None:
            return NodeApplyResult(
                node_id=self.ctx.node_id,
                ok=False,
                message=f"no backup recorded for this plan; restore {self.conf_path} from {self.backup_root}",
            )
        ok = self.file.restore(private.backup)
        return NodeApplyResult(
            node_id=self.ctx.node_id,
            ok=ok,
            message=f"files restored from {private.backup}" if ok else f"restoring {private.backup} failed",
            rolled_back=ok,
        )

    def _write(self, new_cfg: dict[str, Any], label: str, secrets: dict[Path, str]) -> NodeApplyResult:
        before_hash = self.config_hash()
        before_body = self.config_get()
        try:
            doc = self.file.guard(before_body)
        except ConnectorError as exc:
            return NodeApplyResult(node_id=self.ctx.node_id, ok=False, message=str(exc))
        files = [
            FileChange(path=path, content=secret.encode(), mode=0o640, group=self.secret_group)
            for path, secret in secrets.items()
        ]
        pipeline = self._pipeline(new_cfg, before_hash, label, doc, before_body)
        # The configuration files are written by Kea (config-write) or patched: back them up alongside.
        targets = [*secrets, *self.file.files(doc)]
        # Own label: pipeline.run() makes its backup right after, possibly within the same millisecond.
        snapshot = self._pipeline(new_cfg, before_hash, f"{label}-before")
        try:
            backup_dir = snapshot.backup(targets) if targets else None
        except OSError as exc:
            return NodeApplyResult(node_id=self.ctx.node_id, ok=False, message=f"backup failed: {exc}")
        if backup_dir is not None and not label.endswith("-rollback"):
            private = self._private.setdefault(
                label, _PlanPrivate(expires_at=utcnow() + timedelta(seconds=self.plan_ttl), secrets={})
            )
            private.backup = backup_dir
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
                written = self.file.persist(doc, before_body, label, [new_cfg])
                ok, rolled_back, error, steps = True, False, None, f"config-test, config-set, {written}"
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


def _summary(base: Message, note: Message | None) -> dict[str, Any]:
    """Plan summary and summary_message, with an optional "(note)" suffix."""
    m = base if note is None else messages.msg("common.with_note", text=base, note=note)
    return {"summary": messages.render(m), "summary_message": m}
