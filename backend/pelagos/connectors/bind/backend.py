# SPDX-License-Identifier: Apache-2.0
"""BindBackend: DnsBackend over rndc, statistics-channel, AXFR, signed UPDATE and managed include files."""

from __future__ import annotations

import json
import os
import shutil
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

import dns.update

from pelagos.connectors.base import (
    ConnectorContext,
    ConnectorDenied,
    ConnectorError,
    ConnectorUnavailable,
    DnsBackend,
    NotSupported,
    PreconditionFailed,
)
from pelagos.connectors.bind import handover, ops, staticzone, zonefile
from pelagos.connectors.bind import rrset as rr
from pelagos.connectors.bind.configplan import (
    ConfigPlanner,
    RenderResult,
    file_sha256,
    reparse_check,
    run_checkconf,
    sha256_text,
    validate_render,
)
from pelagos.connectors.bind.dns_client import DnsClient, TsigKey
from pelagos.connectors.bind.extras import BindExtras, is_added_zone_change
from pelagos.connectors.bind.namedconf.resolve import ConfigFiles, build_tree, files_tree, key_secret
from pelagos.connectors.bind.rndc import (
    RndcClient,
    RndcNotFound,
    find_binary,
    parse_dnssec_status,
    zone_args,
    zone_status_from,
)
from pelagos.connectors.bind.stats import StatsClient
from pelagos.connectors.bind.viewkeys import global_key_name, view_key_name
from pelagos.connectors.bind.zonefile import ZoneFileError
from pelagos.core.write_pipeline import FileChange
from pelagos.domain import (
    BindConfigTree,
    BindInstanceStats,
    Change,
    DnsCapabilities,
    NodeApplyResult,
    Plan,
    RRset,
    Zone,
    ZoneStatus,
    messages,
)
from pelagos.domain.common import Engine
from pelagos.domain.dns import normalize_name
from pelagos.domain.messages import Message
from pelagos.domain.plan import (
    ChangeOp,
    PlanScope,
    PlanState,
    Precondition,
    PreconditionKind,
    ValidationResult,
)

DEFAULT_VIEW = "_default"
RCODE_PREREQ = {"YXDOMAIN", "YXRRSET", "NXDOMAIN", "NXRRSET"}
WRITTEN_FILE = "pelagos-written.json"  # in the backup directory: sha256 of what the plan wrote
MAX_DETAILS = 256  # audit material kept per process; callers should pop_details() after copying


RELOAD_WAIT = 30.0
RELOAD_POLL = 0.2


def _zone_kind(change: Any) -> str | None:
    side = change.after if isinstance(change.after, dict) else change.before
    return side.get("kind") if isinstance(side, dict) else None


class BindBackend(BindExtras, DnsBackend):
    def __init__(self, ctx: ConnectorContext) -> None:
        super().__init__(ctx)
        cfg = ctx.engine_config
        self.named_conf = Path(cfg.get("named_conf", "/etc/bind/named.conf"))
        self.include_dir = Path(cfg.get("include_dir", "/etc/bind/pelagos"))
        self.zone_dir = Path(cfg["zone_dir"]) if cfg.get("zone_dir") else None
        self.group = cfg.get("group")  # group of the managed files (bind or named), None keeps defaults
        self.rndc = RndcClient(
            Path(cfg.get("rndc_conf", "/etc/bind/pelagos/rndc-pelagos.conf")),
            server=cfg.get("rndc_address", "127.0.0.1"),
            port=int(cfg.get("rndc_port", 953)),
            key_path=Path(cfg.get("rndc_key", "/etc/bind/rndc.key")),
        )
        self.stats = StatsClient(cfg.get("statistics_url", "http://127.0.0.1:8053/json/v1"))
        self.dns = DnsClient(cfg.get("query_address", "127.0.0.1"), int(cfg.get("query_port", 53)))
        self.checkconf = cfg.get("checkconf") or find_binary("named-checkconf")
        self.checkzone = cfg.get("checkzone") or find_binary("named-checkzone")
        # `rndc reload <zone>` only queues the load: the new serial shows up later on large zones.
        self.reload_wait = float(cfg.get("reload_wait_seconds", RELOAD_WAIT))
        # Per plan: UPDATE text and rcode, pipeline steps, backup directory (for the caller's audit entry).
        self.details: dict[str, dict[str, Any]] = {}

    # Settings and keys -----------------------------------------------------------

    @property
    def dns_settings(self) -> dict[str, Any]:
        return dict(self.ctx.settings.get("dns", {}) or {})

    def key_name(self, role: str) -> str:
        return global_key_name(self.dns_settings, role)

    def _key(self, role: str, name: str | None = None) -> TsigKey | None:
        """TSIG key: managed keys.conf first (what named loads, rotated by key plans), then the
        cluster secrets, then a key statement of the user configuration."""
        name = name or self.key_name(role)
        try:
            files: ConfigFiles | None = ConfigFiles.load(self.named_conf)
        except OSError:
            files = None
        found = key_secret(files, name, self.include_dir) if files else None
        if found is None:
            secret = self.ctx.get_secret(f"tsig/{name}")
            if secret:
                return TsigKey(name, secret, "hmac-sha256")
            found = key_secret(files, name) if files else None
        if found is None:
            return None
        algorithm, secret = found
        return TsigKey(name, secret, algorithm)

    def _require_key(self, role: str, view: str | None = None) -> TsigKey:
        name = self._view_key_name(role, view)
        key = self._key(role, name)
        if key is None:
            raise ConnectorDenied(f"TSIG key {name or self.key_name(role)} is not available on this node")
        return key

    def _view_key_name(self, role: str, view: str | None) -> str | None:
        """Views are selected by key (`match-clients { key ...; }`): `dns.view_keys.<view>.<role>`."""
        return view_key_name(self.dns_settings, role, view)

    def _plan_ttl(self) -> int:
        return int(self.ctx.settings.get("plan_ttl_seconds", 600))

    def _new_plan(self, scope: PlanScope, summary: Message, created_by: str) -> Plan:
        plan = Plan(
            scope=scope,
            node_id=self.ctx.node_id,
            summary=messages.render(summary),
            summary_message=summary,
            created_by=created_by,
            engine=Engine.BIND,
        )
        plan.expires_at = plan.created_at + timedelta(seconds=self._plan_ttl())
        plan.target_node_ids = [self.ctx.node_id]
        return plan

    # Observation -------------------------------------------------------------------

    def capabilities(self) -> DnsCapabilities:
        caps = DnsCapabilities(engine=Engine.BIND)
        try:
            version = self.rndc.status().get("version", "")
            caps.rndc = caps.running = True
            caps.version = (
                version.split()[1].split("-")[0] if version.startswith("BIND ") else version or None
            )
        except ConnectorError:
            pass
        try:
            data = self.stats.fetch("/server")
            caps.statistics_channel = caps.running = True
            caps.version = caps.version or data.get("version")
        except ConnectorError:
            pass
        if not caps.running:
            # Any DNS answer (even REFUSED) proves the daemon runs; only transport errors mean it does not.
            try:
                self.dns.soa_serial(".")
                caps.running = True
            except ConnectorError:
                caps.running = False
        try:
            tree = self.read_config(check=False)
            caps.views = list(tree.views)
            caps.dnssec = any(z.dnssec_policy or z.inline_signing for z in tree.zones) or any(
                e.name == "dnssec-policy" for e in tree.options
            )
            caps.catalog_zones = any(e.name == "catalog-zones" for e in tree.options) or any(
                "catalog-zones" in z.extra for z in tree.zones
            )
        except (OSError, ConnectorError):
            pass
        caps.tsig_read_key = self.key_name("read") if self._key("read") else None
        caps.tsig_admin_key = self.key_name("admin") if self._key("admin") else None
        return caps

    def server_status(self) -> dict[str, str]:
        return self.rndc.status()

    def _files(self) -> ConfigFiles:
        files = ConfigFiles.load(self.named_conf)
        _require_user_conf(files)
        return files

    def read_config(self, check: bool = True) -> BindConfigTree:
        files = self._files()
        tree = build_tree(files, self.ctx.node_id, self.include_dir)
        if check:
            result = run_checkconf(self.checkconf, self.named_conf)
            tree.pelagos["checkconf"] = {"ok": result.ok, "output": result.output}
        return tree

    def config_files_tree(self) -> dict[str, Any]:
        """`GET /advanced/bind/tree` payload."""
        return files_tree(self._files(), self.include_dir)

    def list_zones(self, view: str | None = None) -> list[Zone]:
        """Zones of named.conf, then the ones named loaded from elsewhere (addzone, catalogs)."""
        tree = self.read_config(check=False)
        zones = tree.zones + self.extra_zones(tree)
        return [z for z in zones if view is None or z.view == view]

    def zone_status(self, zone: str, view: str | None = None) -> ZoneStatus:
        try:
            raw = self.rndc.zonestatus(zone, view)
        except RndcNotFound as exc:
            st = zone_status_from(zone, view, self.ctx.node_id, {})
            st.error = str(exc)
            return st
        st = zone_status_from(zone, view, self.ctx.node_id, raw)
        try:
            st.serial = self.soa_serial(zone, view)
        except ConnectorError as exc:
            st.error = f"SOA query failed: {exc}"
        return st

    def wait_for_serial(self, zone: str, view: str | None, serial: int) -> bool | None:
        """True once named serves `serial` (or the zone is signed: inline signing keeps its own),
        False when named reports the zone failed to load, None when the deadline passed first."""
        deadline = time.monotonic() + self.reload_wait
        while True:
            st = self.zone_status(zone, view)
            if st.error is None and (st.config_serial == serial or bool(st.signed)):
                return True
            if _load_failed(st):
                return False
            if time.monotonic() >= deadline:
                return None
            time.sleep(RELOAD_POLL)

    def soa_serial(self, zone: str, view: str | None = None) -> int | None:
        if view in (None, DEFAULT_VIEW):
            return self.dns.soa_serial(zone)
        return self.dns.soa_serial(zone, self._require_key("read", view))

    def read_zone(self, zone: str, view: str | None = None) -> list[RRset]:
        try:
            return self.dns.axfr(zone, self._require_key("read", view))
        except ConnectorDenied:
            # A static primary refusing the transfer is read from its file, as named loaded it.
            static = self.static_zone(zone, view)
            if static is None:
                raise
            try:
                return staticzone.load(static, self._directory()).rrsets()
            except (ZoneFileError, OSError):
                raise ConnectorDenied(f"AXFR of {zone} refused and its zone file is not readable") from None

    # Zones as configured on this node --------------------------------------------------

    def config_zone(self, zone: str, view: str | None = None) -> Zone | None:
        name = normalize_name(zone)
        want = view or DEFAULT_VIEW
        try:
            zones = self.list_zones()
        except (OSError, ConnectorError):
            return None
        found = [z for z in zones if z.name == name and z.view == want]
        return found[0] if found else None

    def static_zone(self, zone: str, view: str | None = None) -> Zone | None:
        """The zone when this node holds it as a static primary (its file is edited, no UPDATE)."""
        found = self.config_zone(zone, view)
        if not staticzone.is_static(found):
            return None
        # named has the last word: a zone it reports dynamic (inherited rules, addzone) takes UPDATEs.
        try:
            status = self.rndc.zonestatus(zone, None if view in (None, DEFAULT_VIEW) else view)
        except ConnectorError:
            return found
        return None if status.get("dynamic", "").lower() == "yes" else found

    def _directory(self) -> Path:
        for entry in self.read_config(check=False).options:
            if entry.name == "directory" and entry.value.strip():
                return Path(entry.value.strip().strip('"'))
        return self.named_conf.parent

    def instance_stats(self) -> BindInstanceStats:
        return self.stats.instance_stats(self.ctx.node_id)

    def dnssec_status(self, zone: str, view: str | None = None) -> dict[str, Any]:
        out = parse_dnssec_status(self.rndc.dnssec_status(zone, view))
        out["zone"] = normalize_name(zone)
        out["view"] = view or DEFAULT_VIEW
        return self.dnssec_details(out["zone"], None if view in (None, DEFAULT_VIEW) else view, out)

    # RRset plans ---------------------------------------------------------------------

    def plan_rrset_changes(
        self, zone: str, changes: list[Change], view: str | None = None, created_by: str = ""
    ) -> Plan:
        zone = normalize_name(zone)
        view = None if view in (None, DEFAULT_VIEW) else view
        if view is not None:
            self._view_key_name("admin", view)  # raises NotSupported without a key for the view
        plan = self._new_plan(PlanScope.DNS_RRSET, messages.msg("plan.rrset.changes", zone=zone), created_by)
        current = self.read_zone(zone, view)
        allowed = self.dns_settings.get("update_types_admin")
        resolved, errors = rr.resolve_changes(
            zone,
            changes,
            current,
            allowed_types=allowed,
            default_ttl=int(self.dns_settings.get("default_ttl", 3600)),
        )
        plan.changes = [rr.to_change(zone, rc, view) for rc in resolved]
        plan.diff = rr.diff_text(resolved)
        messages.set_text(plan, "summary", rr.summary_message(zone, resolved))
        plan.preconditions = rr.preconditions(resolved, self.ctx.node_id, view)
        soa = next((r for r in current if r.rtype == "SOA" and r.name == zone), None)
        if soa is not None:
            serial = soa.rdata[0].split()[2]
            plan.preconditions.append(
                Precondition(PreconditionKind.SOA_SERIAL, zone, serial, self.ctx.node_id)
            )
        ok = not errors and bool(resolved)
        if not resolved and not errors:
            errors.append("no change")
        plan.validations = [
            ValidationResult(
                ok=ok, tool="dnspython", output="\n".join(errors) or "ok", node_id=self.ctx.node_id
            )
        ]
        static = self.static_zone(zone, view)
        if ok and static is not None:
            messages.add_note(plan, "summary", messages.msg("note.static_file_edit"))
            plan.validations.extend(self._static_preview(plan, static, resolved, soa))
            ok = all(v.ok for v in plan.validations)
            errors = [v.output for v in plan.validations if not v.ok]
        plan.state = PlanState.VALIDATED if ok else PlanState.FAILED
        plan.error = None if ok else "; ".join(errors)
        return plan

    def _static_preview(
        self, plan: Plan, zone: Zone, rcs: list[rr.RRsetChange], soa: RRset | None
    ) -> list[ValidationResult]:
        """The zone file diff, its FILE_SHA256 preconditions and the checks of a static zone edit."""
        node = self.ctx.node_id
        try:
            zf = staticzone.load(zone, self._directory())
            loaded = int(soa.rdata[0].split()[2]) if soa is not None else None
            texts, serial = staticzone.render(zf, rcs, loaded)
        except (ZoneFileError, OSError) as exc:
            return [ValidationResult(ok=False, tool="zonefile", output=str(exc), node_id=node)]
        plan.diff = staticzone.diff(zf, texts)
        plan.preconditions.extend(
            Precondition(PreconditionKind.FILE_SHA256, str(p), sha256_text(zf.texts[p]), node) for p in texts
        )
        out = [
            ValidationResult(
                ok=True,
                tool="zonefile",
                output=f"{staticzone.FILE_MODE_NOTE}: {', '.join(str(p) for p in texts)}, serial {serial}, "
                "then rndc reload (NOTIFY to the secondaries)",
                node_id=node,
            )
        ]
        check = staticzone.check_copy(self.checkzone, zf, texts)
        check.node_id = node
        out.append(check)
        problem = staticzone.write_problem(list(texts))
        if problem:
            out.append(ValidationResult(ok=False, tool="permissions", output=problem, node_id=node))
        return out

    def _apply_static(self, plan: Plan, zone: Zone, rcs: list[rr.RRsetChange], label: str) -> NodeApplyResult:
        """Edit the zone file of a static primary: render, check, write, rndc reload, verify."""
        node = self.ctx.node_id
        view = None if zone.view == DEFAULT_VIEW else zone.view
        details = self._plan_details(plan.id)
        if label == "apply":
            self._check_file_preconditions(plan)
        try:
            zf = staticzone.load(zone, self._directory())
            try:
                loaded = self.soa_serial(zone.name, view)
            except ConnectorError:
                loaded = None
            texts, serial = staticzone.render(zf, rcs, loaded)
        except (ZoneFileError, OSError) as exc:
            return NodeApplyResult(node_id=node, ok=False, message=f"zone file: {exc}")
        problem = staticzone.write_problem(list(texts))
        if problem:
            return NodeApplyResult(node_id=node, ok=False, message=problem)
        check = staticzone.check_copy(self.checkzone, zf, texts)
        if not check.ok:
            return NodeApplyResult(node_id=node, ok=False, message=f"named-checkzone: {check.output}")

        def validate() -> ValidationResult:
            return staticzone.run_checkzone(self.checkzone, zone.name, zf.main, zf.directory)

        pending: list[bool] = []

        def verify() -> bool:
            # False (restore the file) only when named definitely refused it; once the deadline
            # passes the load may still finish, so the file stays and the result says so.
            loaded = self.wait_for_serial(zone.name, view, serial)
            if loaded is None:
                pending.append(True)
                return True
            return loaded

        pipeline = self.ctx.pipeline_factory(
            backup_root=self.ctx.backup_root,
            validate=validate,
            reload=lambda: self.reload(zone.name, view) or "reload done",
            verify=verify,
            label=f"{plan.id}-{label}" if label != "apply" else plan.id,
        )
        outcome = pipeline.run(
            [FileChange(path=p, content=zonefile.encode(t), create_dirs=False) for p, t in texts.items()]
        )
        details[label] = {
            "request": {
                "mode": "file",
                "zone": zone.name,
                "files": [str(p) for p in texts],
                "serial": serial,
            },
            "response": {
                "steps": outcome.steps,
                "backup_dir": str(outcome.backup_dir) if outcome.backup_dir else None,
            },
        }
        if outcome.ok:
            done = "reload still in progress" if pending else "rndc reload done"
            message = f"zone file edited, serial {serial}, {done}"
            return NodeApplyResult(node_id=node, ok=True, message=message)
        return NodeApplyResult(
            node_id=node,
            ok=False,
            message=outcome.error or "zone file write failed",
            rolled_back=outcome.rolled_back,
        )

    def _send_rrset(self, plan: Plan, rcs: list[rr.RRsetChange], label: str) -> NodeApplyResult:
        zone, view = _plan_zone(plan)
        key = self._require_key("admin", view)
        text = rr.update_text(zone, rcs)
        details = self._plan_details(plan.id)
        details[label] = {"request": {"update": text, "key": key.name}}

        def build(msg: dns.update.Update) -> None:
            rr.build_update(msg, rcs)

        rcode = self.dns.update(zone, key, build)
        details[label]["response"] = {"rcode": rcode}
        if rcode == "NOERROR":
            return NodeApplyResult(node_id=self.ctx.node_id, ok=True, message=f"UPDATE {rcode}")
        if rcode in RCODE_PREREQ:
            msg = f"UPDATE prerequisite failed ({rcode}): the records changed since the plan was built"
        else:
            msg = f"UPDATE failed: {rcode}"
        return NodeApplyResult(node_id=self.ctx.node_id, ok=False, message=msg)

    # File plans ------------------------------------------------------------------------

    def _planner(self) -> ConfigPlanner:
        planner = ConfigPlanner(
            self.named_conf,
            self.include_dir,
            self.ctx.node_id,
            zone_dir=self.zone_dir,
            default_ns=self.dns_settings.get("default_ns"),
        )
        _require_user_conf(planner.files)
        return planner

    def _render(
        self, plan_scope: PlanScope, changes: list[Change], replay: bool = False
    ) -> tuple[ConfigPlanner, RenderResult]:
        planner = self._planner()
        planner.replay = replay  # a node replaying a plan skips handovers it does not need
        for change in changes:
            if plan_scope is PlanScope.DNS_ZONE:
                planner.zone_change(change)
            else:
                planner.apply_change(change)
        result = planner.finish()
        result.errors.extend(reparse_check(result.texts, result.zone_files))
        return planner, result

    def _file_plan(self, scope: PlanScope, changes: list[Change], summary: Message, created_by: str) -> Plan:
        plan = self._new_plan(scope, summary, created_by)
        planner, result = self._render(scope, changes)
        plan.changes = result.changes
        plan.diff = result.diff()
        plan.preconditions = result.preconditions(self.ctx.node_id)
        plan.requires_confirmation = result.requires_confirmation
        if result.errors:
            plan.validations = [
                ValidationResult(
                    ok=False, tool="parser", output="\n".join(result.errors), node_id=self.ctx.node_id
                )
            ]
        elif not result.changed_paths():
            plan.validations = [
                ValidationResult(ok=False, tool="parser", output="no change", node_id=self.ctx.node_id)
            ]
        else:
            plan.validations = validate_render(planner, self.checkconf, self.checkzone)
            for v in plan.validations:
                v.node_id = self.ctx.node_id
        ok = all(v.ok for v in plan.validations)
        plan.state = PlanState.VALIDATED if ok else PlanState.FAILED
        plan.error = None if ok else "; ".join(v.output for v in plan.validations if not v.ok)
        return plan

    def plan_zone_change(self, change: Change, created_by: str = "") -> Plan:
        op = ChangeOp(change.op)
        view, _, name = change.target.partition("/")
        existing = self.config_zone(name, view or DEFAULT_VIEW) if name else None
        if is_added_zone_change(change, existing):
            return self.plan_added_zone(change, existing, created_by)
        summary = messages.msg("plan.zone.change", target=change.target, op=messages.op(op))
        return self._file_plan(PlanScope.DNS_ZONE, [change], summary, created_by)

    def plan_config_change(self, changes: list[Change], created_by: str = "") -> Plan:
        kinds = {c.target.split("/", 1)[0] for c in changes}
        scope = PlanScope.DNS_CONFIG
        if len(kinds) == 1:
            scope = {"keys": PlanScope.DNS_KEY, "acls": PlanScope.DNS_ACL}.get(kinds.pop(), scope)
        targets = [messages.msg("plan.change", op=messages.op(c.op), target=c.target) for c in changes]
        return self._file_plan(scope, changes, messages.msg("plan.bind.config", changes=targets), created_by)

    def plan_include_setup(self, created_by: str = "") -> Plan:
        """Create the managed files and the include lines in the user files (import step)."""
        change = Change(ChangeOp.ADD, "pelagos/includes")
        return self._file_plan(PlanScope.DNS_CONFIG, [change], messages.msg("plan.bind.includes"), created_by)

    def _check_file_preconditions(self, plan: Plan) -> None:
        for pre in plan.preconditions:
            if pre.kind is not PreconditionKind.FILE_SHA256:
                continue
            if pre.node_id not in (None, self.ctx.node_id):
                continue
            observed = file_sha256(Path(pre.subject))
            if observed != pre.value:
                raise PreconditionFailed(pre, observed)

    def _file_mode(self, path: Path, zone_files: dict[Path, str]) -> tuple[int | None, str | None]:
        if path in zone_files:
            return 0o664, self.group
        if path.is_relative_to(self.include_dir):
            return 0o640, self.group
        return None, None  # user files keep their owner, group and mode

    def _verify(self, plan: Plan) -> Any:
        if plan.scope is not PlanScope.DNS_ZONE:
            return lambda: bool(self.rndc.status())

        def verify() -> bool:
            for change in plan.changes:
                view, _, name = change.target.partition("/")
                view = None if view in ("", DEFAULT_VIEW) else view
                # Root hints are not a zone rndc zonestatus knows: the reload itself is the check.
                if _zone_kind(change) == "hint":
                    if not self.rndc.status():
                        return False
                    continue
                # rndc names the redirect zone "-redirect", as "." would be the root zone.
                if _zone_kind(change) == "redirect":
                    name = "-redirect"
                try:
                    self.rndc.zonestatus(name, view)
                    present = True
                except RndcNotFound:
                    present = False
                except ConnectorError as exc:
                    # A transferred zone (secondary, mirror) waiting for its primary is configured.
                    if "not loaded" not in str(exc):
                        raise
                    present = True
                if present == (ChangeOp(change.op) is ChangeOp.DELETE):
                    return False
            return True

        return verify

    def _apply_files(self, plan: Plan) -> NodeApplyResult:
        self._check_file_preconditions(plan)
        _, result = self._render(plan.scope, plan.changes, replay=True)
        if result.errors:
            return NodeApplyResult(node_id=self.ctx.node_id, ok=False, message="; ".join(result.errors))
        paths = result.changed_paths()
        if not paths:
            return NodeApplyResult(
                node_id=self.ctx.node_id, ok=True, message="already applied: no file change"
            )
        file_changes = []
        for path in paths:
            mode, group = self._file_mode(path, result.zone_files)
            is_zone = path in result.zone_files
            if is_zone:
                self._ensure_zone_dir(path.parent)
            file_changes.append(
                FileChange(
                    path=path,
                    content=result.texts[path].encode(),
                    mode=mode,
                    group=group,
                    create_dirs=not is_zone,
                )
            )
        verify = self._verify(plan)
        moved = [c.target for c in plan.changes if handover.is_handover(c)]
        if moved:
            verify = self._verify_handover(verify, moved)
        pipeline = self.ctx.pipeline_factory(
            backup_root=self.ctx.backup_root,
            validate=lambda: run_checkconf(self.checkconf, self.named_conf),
            reload=lambda: self.reconfig() or "reconfig done",
            verify=verify,
            label=plan.id,
        )
        outcome = pipeline.run(file_changes)
        if outcome.ok and outcome.backup_dir:
            # What this plan wrote: rollback refuses to restore over a later change. Zone files are
            # left out: named rewrites them with dynamic updates.
            written = {str(p): sha256_text(result.texts[p]) for p in paths if p not in result.zone_files}
            try:
                record = Path(outcome.backup_dir) / WRITTEN_FILE
                fd = os.open(record, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
                with os.fdopen(fd, "w") as fh:
                    fh.write(json.dumps(written, indent=1))
            except OSError:
                pass
        self._set_details(
            plan.id,
            {
                "request": {"files": [str(p) for p in paths]},
                "response": {
                    "steps": outcome.steps,
                    "backup_dir": str(outcome.backup_dir) if outcome.backup_dir else None,
                },
            },
        )
        if outcome.ok:
            return NodeApplyResult(
                node_id=self.ctx.node_id, ok=True, message=f"{len(paths)} file(s) written, reconfig done"
            )
        return NodeApplyResult(
            node_id=self.ctx.node_id,
            ok=False,
            message=outcome.error or "write pipeline failed",
            rolled_back=outcome.rolled_back,
        )

    def _verify_handover(self, verify: Any, targets: list[str]) -> Any:
        """After the reload the effective value of every moved statement must be what it was."""
        before = handover.snapshot(handover.print_effective(self.checkconf, self.named_conf), targets)

        def check() -> bool:
            if not verify():
                return False
            after = handover.snapshot(handover.print_effective(self.checkconf, self.named_conf), targets)
            return not handover.unchanged(before, after)

        return check

    def _ensure_zone_dir(self, directory: Path) -> None:
        """Zone directories are setgid and group writable: named creates journals and transferred
        files there. Created here, not by the pipeline, so the umask does not decide."""
        missing: list[Path] = []
        d = directory
        while not d.exists():
            missing.append(d)
            d = d.parent
        for d in reversed(missing):
            try:
                d.mkdir(mode=0o2775)
                if self.group:
                    shutil.chown(d, group=self.group)
                os.chmod(d, 0o2775)  # noqa: S103 (named must write journals in it)
            except (OSError, LookupError) as exc:
                raise ConnectorError(f"cannot create zone directory {d}: {exc}") from exc

    def _plan_details(self, plan_id: str) -> dict[str, Any]:
        if plan_id not in self.details:
            self._set_details(plan_id, {})
        return self.details[plan_id]

    def _set_details(self, plan_id: str, value: dict[str, Any]) -> None:
        self.details.pop(plan_id, None)
        self.details[plan_id] = value
        while len(self.details) > MAX_DETAILS:
            self.details.pop(next(iter(self.details)))

    def pop_details(self, plan_id: str) -> dict[str, Any]:
        """Audit material of a plan, removed once the caller has copied it into the audit entry."""
        return self.details.pop(plan_id, {})

    def _check_rollback_safe(self, backup: Path) -> None:
        """Refuse to restore a backup over files changed after this plan wrote them."""
        try:
            written = json.loads((backup / WRITTEN_FILE).read_text())
        except FileNotFoundError:
            return  # the apply failed before writing, or an older backup: nothing to compare
        except (OSError, ValueError) as exc:
            raise ConnectorError(f"unreadable {backup / WRITTEN_FILE}: {exc}") from exc
        changed = [p for p, digest in written.items() if file_sha256(Path(p)) != digest]
        if changed:
            raise PreconditionFailed(
                Precondition(PreconditionKind.FILE_SHA256, changed[0], written[changed[0]], self.ctx.node_id),
                file_sha256(Path(changed[0]))
                + f" (changed since this plan was applied: {', '.join(changed)}; rollback refused)",
            )

    def _backup_dir(self, plan: Plan) -> Path | None:
        recorded = self.details.get(plan.id, {}).get("response", {}).get("backup_dir")
        if recorded:
            return Path(recorded)
        found = sorted(self.ctx.backup_root.glob(f"*-{plan.id}"))
        return found[-1] if found else None

    # Apply and rollback ---------------------------------------------------------------

    def apply(self, plan: Plan) -> NodeApplyResult:
        self.forget_extra_zones()
        try:
            if plan.scope is PlanScope.DNS_ZONE and plan.changes and ops.is_op(plan.changes[0]):
                return self._apply_op(plan)
            if plan.scope is PlanScope.DNS_ZONE and _added_zone_plan(plan):
                return self._apply_added_zone(plan)
            if plan.scope is PlanScope.DNS_RRSET:
                zone, view = _plan_zone(plan)
                rcs = rr.rrset_changes_from_plan(zone, plan.changes)
                # The node holding the file decides: a static primary here is edited in its file.
                static = self.static_zone(zone, view)
                if static is not None:
                    return self._apply_static(plan, static, rcs, "apply")
                return self._send_rrset(plan, rcs, "apply")
            if plan.scope in (PlanScope.DNS_ZONE, PlanScope.DNS_CONFIG, PlanScope.DNS_KEY, PlanScope.DNS_ACL):
                return self._apply_files(plan)
            raise NotSupported(f"plan scope {plan.scope} is not a BIND plan")
        except ConnectorError as exc:
            return NodeApplyResult(node_id=self.ctx.node_id, ok=False, message=str(exc))

    def rollback(self, plan: Plan) -> NodeApplyResult:
        self.forget_extra_zones()
        try:
            if plan.scope is PlanScope.DNS_ZONE and plan.changes and ops.is_op(plan.changes[0]):
                return NodeApplyResult(
                    node_id=self.ctx.node_id, ok=False, message="an rndc operation cannot be rolled back"
                )
            if plan.scope is PlanScope.DNS_ZONE and _added_zone_plan(plan):
                return self._apply_added_zone(plan, rollback=True)
            if plan.scope is PlanScope.DNS_RRSET:
                zone, view = _plan_zone(plan)
                rcs = [rr.inverse(rc) for rc in reversed(rr.rrset_changes_from_plan(zone, plan.changes))]
                static = self.static_zone(zone, view)
                if static is not None:
                    # The inverse edit with a new serial: secondaries transfer the restored records.
                    result = self._apply_static(plan, static, rcs, "rollback")
                else:
                    result = self._send_rrset(plan, rcs, "rollback")
                result.rolled_back = result.ok
                return result
            backup = self._backup_dir(plan)
            if backup is None:
                return NodeApplyResult(
                    node_id=self.ctx.node_id, ok=False, message="no backup found for this plan"
                )
            self._check_rollback_safe(backup)
            pipeline = self.ctx.pipeline_factory(
                backup_root=self.ctx.backup_root,
                validate=lambda: run_checkconf(self.checkconf, self.named_conf),
                reload=lambda: self.reconfig() or "reconfig done",
                label=f"{plan.id}-rollback",
            )
            outcome = pipeline.restore(backup)
            self._plan_details(plan.id)["rollback"] = {
                "steps": outcome.steps,
                "backup_dir": str(backup),
            }
            return NodeApplyResult(
                node_id=self.ctx.node_id,
                ok=outcome.ok,
                message="restored " + str(backup) if outcome.ok else (outcome.error or "rollback failed"),
                rolled_back=outcome.ok,
            )
        except ConnectorError as exc:
            return NodeApplyResult(node_id=self.ctx.node_id, ok=False, message=str(exc))

    # Operations ------------------------------------------------------------------------

    def reconfig(self) -> str:
        return self.rndc.run("reconfig")

    def reload(self, zone: str | None = None, view: str | None = None) -> str:
        return self.rndc.run("reload", *(zone_args(zone, view) if zone else []))

    def notify(self, zone: str, view: str | None = None) -> str:
        return self.rndc.run("notify", *zone_args(zone, view))

    def retransfer(self, zone: str, view: str | None = None) -> str:
        return self.rndc.run("retransfer", *zone_args(zone, view))

    def freeze(self, zone: str, view: str | None = None) -> str:
        return self.rndc.run("freeze", *zone_args(zone, view))

    def thaw(self, zone: str, view: str | None = None) -> str:
        return self.rndc.run("thaw", *zone_args(zone, view))

    def sync(self, zone: str | None = None, clean: bool = False) -> str:
        return self.rndc.run("sync", *(["-clean"] if clean else []), *([zone_args(zone)[0]] if zone else []))


def _require_user_conf(files: ConfigFiles) -> None:
    key = str(files.user_conf)
    if key in files.missing or key in files.unreadable:
        reason = "missing" if key in files.missing else "not readable"
        raise ConnectorUnavailable(f"{key} is {reason}")


def _added_zone_plan(plan: Plan) -> bool:
    change = plan.changes[0] if plan.changes else None
    if change is None:
        return False
    sides = [s for s in (change.before, change.after) if isinstance(s, dict)]
    return any(s.get("source") == "addzone" for s in sides)


def _plan_zone(plan: Plan) -> tuple[str, str | None]:
    """Zone and view of an RRset plan, from the first change target `[<view>/]<zone>/<owner>/<type>`."""
    if not plan.changes:
        raise NotSupported("plan has no change")
    target = plan.changes[0].target
    return rr.target_zone(target), rr.target_view(target)


def _load_failed(st: Any) -> bool:
    """zonestatus marks a zone whose last load failed (`rndc zonestatus`: "load failed" state)."""
    raw = st.raw if isinstance(getattr(st, "raw", None), dict) else {}
    text = " ".join(str(v) for v in raw.values()).lower()
    return "load failed" in text or "not loaded" in text
