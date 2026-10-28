# SPDX-License-Identifier: Apache-2.0
"""D2 (kea-dhcp-ddns) connector: statistics per key, configuration read and the config replace plan.

A clear `secret` in a submitted configuration is written to a 0640 secret file
(Kea group) through the write pipeline, and the key references it with
`secret-file`. The secret itself stays out of the Plan. The file goes next to the
D2 configuration when this process may create files there, else to
`<conf dir>/pelagos` (pelagos:<kea group> 2750, made by the privileged helper:
Debian's /etc/kea is _kea:_kea 0750). When neither works or Kea predates
`secret-file`, the secret stays inline (Kea 3.1 and later refuse that at config-test).
"""

from __future__ import annotations

import grp
import hashlib
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from pelagos.connectors.base import ConnectorContext, ConnectorError, DdnsBackend, PreconditionFailed
from pelagos.connectors.kea.commands import normalize_version
from pelagos.connectors.kea.config import canonical, config_diff, normalize_root, version_tuple
from pelagos.connectors.kea.configfile import (
    ADOPT_FILE,
    ADOPT_TARGETS,
    KeaConfigFile,
    with_helper,
)
from pelagos.connectors.kea.control_socket import DEFAULT_COMMAND_TIMEOUT, KeaControlSocket
from pelagos.connectors.kea.schema import config_schema
from pelagos.connectors.kea.secrets import masked_refusal
from pelagos.core import settings_registry as reg
from pelagos.core.plan_secrets import SECRET_FILE_PREFIX, SECRET_INLINE_PREFIX
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

log = logging.getLogger(__name__)

# D2 `secret-file` exists since Kea 2.5.8 (src/bin/d2/d2_lexer.ll at tags Kea-2.5.7 and
# Kea-2.5.8, github.com/isc-projects/kea, checked 2026-10-28); every version accepts `secret`.
SECRET_FILE_SINCE = (2, 5, 8)
SECRET_SUBDIR = "pelagos"  # noqa: S105 (installer.keasetup.D2_SECRET_SUBDIR)
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


def _writable(directory: Path) -> bool:
    return os.access(directory, os.W_OK | os.X_OK)


def has_clear_secrets(config: dict[str, Any]) -> bool:
    return any(k.get("secret") for k in config.get("tsig-keys") or [])


@dataclass(slots=True)
class _PlanPrivate:
    """What a plan needs at apply or rollback but must never carry: secrets, backup path."""

    expires_at: datetime
    secrets: dict[Path, str]
    inline: dict[str, str] = field(default_factory=dict)  # key name -> new clear secret kept inline
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


def new_inline_secrets(config: dict[str, Any], running: dict[str, Any]) -> dict[str, str]:
    """{key name: clear secret} of the inline secrets `config` adds or changes against `running`."""
    old = {str(k.get("name")): k.get("secret") for k in running.get("tsig-keys") or [] if isinstance(k, dict)}
    return {
        str(k.get("name")): str(k["secret"])
        for k in config.get("tsig-keys") or []
        if isinstance(k, dict) and k.get("secret") and k["secret"] != old.get(str(k.get("name")))
    }


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
        self.conf_secret_dir = self.secret_dir
        self.own_secret_dir: Path | None = (
            None if "d2_secret_dir" in cfg else self.conf_path.parent / SECRET_SUBDIR
        )
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
        inline = has_clear_secrets(config) and self._secret_files_blocked()
        new_cfg, secrets = (config, {}) if inline else externalize_secrets(config, self.secret_dir)
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
        # Inline secrets stay out of the plan too: new or changed ones travel as secret-inline changes.
        inline_new = new_inline_secrets(new_cfg, before) if inline else {}
        after = mask_secrets(new_cfg) if inline else new_cfg
        changes = [Change(ChangeOp.REPLACE, "config", before=masked_before, after=after)]
        for path, secret in secrets.items():
            digest = hashlib.sha256(secret.encode()).hexdigest()
            changes.append(
                Change(
                    ChangeOp.ADD,
                    f"{SECRET_FILE_PREFIX}{path.name}",
                    after={"path": str(path), "sha256": digest},
                )
            )
        for name, secret in inline_new.items():
            digest = hashlib.sha256(secret.encode()).hexdigest()
            changes.append(
                Change(
                    ChangeOp.REPLACE, f"{SECRET_INLINE_PREFIX}{name}", after={"key": name, "sha256": digest}
                )
            )
        plan = Plan(
            scope=PlanScope.D2_CONFIG,
            node_id=self.ctx.node_id,
            **_summary(
                messages.msg("plan.kea.replace_config", engine="kea-dhcp-ddns"),
                messages.msg("note.secret_files", count=len(secrets))
                if secrets
                else messages.msg("note.secrets_inline")
                if inline
                else None,
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
        if secrets or inline_new or clear_before:
            self._private[plan.id] = _PlanPrivate(
                expires_at=plan.expires_at or utcnow() + timedelta(seconds=self.plan_ttl),
                secrets=secrets,
                inline=inline_new,
                before=before if clear_before else None,
            )
        return plan

    def _kea_group(self) -> str | None:
        """Configured `kea_group`, else the group of the D2 configuration file, else of its directory."""
        if self.secret_group:
            return self.secret_group
        for path in (self.conf_path, self.secret_dir):
            try:
                return grp.getgrgid(path.stat().st_gid).gr_name
            except (OSError, KeyError):
                continue
        return None

    def _secret_files_blocked(self) -> str | None:
        """Why clear secrets cannot go to files here (None when they can): Kea too old, or a
        file Kea can read (Kea group, 0640) cannot be created in the secret directory."""
        version = normalize_version(self.socket.version())
        reason = None
        if version_tuple(version) < SECRET_FILE_SINCE:
            reason = f"Kea {version} has no secret-file"
        elif not _writable(self.secret_dir) and not self._use_own_secret_dir():
            reason = f"{self.secret_dir} is not writable by this process"
        else:
            group = self._kea_group()
            try:
                gid = grp.getgrnam(group).gr_gid if group else None
            except KeyError:
                gid = None
            if gid is None:
                reason = "the Kea group is unknown"
            elif os.geteuid() != 0 and gid not in (os.getegid(), *os.getgroups()):
                reason = f"this process is not in group {group}"
        if reason:
            log.info("D2 TSIG secrets kept inline: %s", reason)
        return reason

    def _use_own_secret_dir(self) -> bool:
        """Switches to <conf dir>/pelagos, asking the privileged helper to make it when missing."""
        own = self.own_secret_dir
        if own is None:
            return False
        if not own.is_dir():
            from pelagos.installer import helper

            if helper.available():
                try:
                    helper.HelperClient(timeout=30).call("d2_secret_dir")
                except helper.HelperError as exc:
                    log.warning("D2 secret directory %s not created: %s", own, exc)
        if own.is_dir() and _writable(own):
            self.secret_dir = own
            return True
        return False

    # Secrets of plans applied on several nodes ---------------------------------------------------

    def plan_secrets(self, plan_id: str) -> dict[str, str]:
        """{secret file path or secret-inline/<key>: clear secret} held for a plan this backend built;
        sealed into the plan by `core.plan_secrets.seal_backend_secrets` before it goes to peers."""
        self._sweep()
        private = self._private.get(plan_id)
        if private is None:
            return {}
        out = {str(path): secret for path, secret in private.secrets.items()}
        out.update({f"{SECRET_INLINE_PREFIX}{name}": secret for name, secret in private.inline.items()})
        return out

    def accept_plan_secrets(self, plan: Plan, secrets: dict[str, str]) -> None:
        """Secrets of a plan built on another node: only the files the plan declares, matching digests."""
        self._sweep()
        declared: dict[str, str] = {}
        for c in plan.changes:
            if isinstance(c.after, dict) and c.target.startswith(SECRET_FILE_PREFIX):
                declared[str(c.after.get("path"))] = str(c.after.get("sha256") or "")
            elif isinstance(c.after, dict) and c.target.startswith(SECRET_INLINE_PREFIX):
                declared[c.target] = str(c.after.get("sha256") or "")
        accepted: dict[Path, str] = {}
        inline: dict[str, str] = {}
        for path, secret in secrets.items():
            if path not in declared:
                raise ConnectorError(f"secret for {path} is not declared by plan {plan.id}")
            if declared[path] and hashlib.sha256(secret.encode()).hexdigest() != declared[path]:
                raise ConnectorError(f"secret for {path} does not match the plan digest")
            if path.startswith(SECRET_INLINE_PREFIX):
                inline[path[len(SECRET_INLINE_PREFIX) :]] = secret
                continue
            if not self._is_secret_path(path):
                raise ConnectorError(f"secret path {path} is outside {self.secret_dir}")
            accepted[Path(path)] = secret
        if not accepted and not inline:
            return
        expires = utcnow() + timedelta(seconds=self.plan_ttl)
        private = self._private.setdefault(plan.id, _PlanPrivate(expires_at=expires, secrets={}))
        private.secrets = accepted
        private.inline = inline

    def _is_secret_path(self, path: str) -> bool:
        """Peers may only write `<d2_secret_dir>/<secret_file_name(...)>`, never an arbitrary file."""
        candidate = Path(path)
        name = candidate.name
        return (
            candidate.is_absolute()
            and ".." not in candidate.parts
            and candidate.parent.resolve()
            in {d.resolve() for d in (self.secret_dir, self.conf_secret_dir, self.own_secret_dir) if d}
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
        sent: list[bool] = []

        def reload() -> str:
            if sent:
                # The restore after a failed apply: the files are back, D2 must run what it ran before
                # (never new_cfg, which may name secret files the restore just removed).
                return self._reload_before(before_hash, before_body)
            sent.append(True)
            self.socket.call("config-set", {ROOT: new_cfg})
            return f"config-set, {self.file.persist(doc, before_body or {}, label, [new_cfg])}"

        def verify() -> bool:
            return self.config_hash() != before_hash or canonical(self.config_get()) == canonical(new_cfg)

        return with_helper(
            self.ctx.pipeline_factory(
                self.backup_root,
                validate=lambda: self.config_test(new_cfg),
                reload=reload,
                verify=verify,
                label=label,
            )
        )

    def _reload_before(self, before_hash: str, before_body: dict[str, Any] | None) -> str:
        """D2 back on its configuration from before the plan: config-reload of the restored files,
        else config-set of the running configuration read before the write (when it is clear)."""
        if self.config_hash() == before_hash:
            return "running configuration unchanged"
        try:
            self.socket.call("config-reload")
        except ConnectorError as exc:
            log.warning("config-reload after a failed D2 write: %s", exc)
        if self.config_hash() == before_hash:
            return "config-reload of the restored files"
        if before_body is not None and not has_masked_secrets(before_body):
            self.socket.call("config-set", {ROOT: before_body})
            if self.config_hash() == before_hash:
                return "config-set of the configuration from before the plan"
        raise ConnectorError("D2 runs neither the new nor its previous configuration; check it")

    def preflight(self, plan: Plan) -> str | None:
        """Why applying `plan` here would fail on a file it must write (None when every one can be
        written now); the plan service asks every target before any node applies."""
        adopt = next((c for c in plan.changes if c.target in ADOPT_TARGETS), None)
        if adopt is not None and adopt.target == ADOPT_FILE:
            return None
        secret_dirs = {
            Path(str(c.after.get("path"))).parent
            for c in plan.changes
            if c.target.startswith(SECRET_FILE_PREFIX) and isinstance(c.after, dict)
        }
        for d in sorted(secret_dirs):
            if not _writable(d):
                return f"cannot write the TSIG secret files in {d}"
        try:
            return self.file.write_problem()
        except ConnectorError as exc:
            return str(exc)

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
        inline = private.inline if private else {}
        if private:
            # Secrets are no longer needed; what rollback needs stays for the rollback window.
            private.secrets, private.inline = {}, {}
            private.expires_at = utcnow() + timedelta(seconds=self.plan_ttl)
        new_cfg, missing = self._clear_after(dict(change.after), inline)
        if missing:
            return NodeApplyResult(
                node_id=self.ctx.node_id,
                ok=False,
                message=f"secrets of {', '.join(missing)} are no longer held for this plan; plan again",
            )
        return self._remember(plan.id, self._write(new_cfg, plan.id, secrets))

    def _clear_after(self, after: dict[str, Any], inline: dict[str, str]) -> tuple[dict[str, Any], list[str]]:
        """A masked plan config with its inline secrets: the plan's new ones, else the running ones
        (unchanged since planning, the config-hash precondition says so)."""
        if not has_masked_secrets(after):
            return after, []
        keys = [
            {**k, "secret": inline[str(k.get("name"))]}
            if isinstance(k, dict) and k.get("secret") == MASK and str(k.get("name")) in inline
            else k
            for k in after.get("tsig-keys") or []
        ]
        return unmask_d2_keys({**after, "tsig-keys": keys}, self.config_get())

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
            FileChange(path=path, content=secret.encode(), mode=0o640, group=self._kea_group())
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
