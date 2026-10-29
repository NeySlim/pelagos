# SPDX-License-Identifier: Apache-2.0
"""BindBackend: DnsBackend over rndc, statistics-channel, AXFR, signed UPDATE and managed include files."""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
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
    ZoneTooLarge,
    ZoneWithoutRecords,
)
from pelagos.connectors.bind import failover, handover, hints, ops, roles, staticzone, zonefile, zonerestore
from pelagos.connectors.bind import rrset as rr
from pelagos.connectors.bind.builtin_zones import is_builtin_zone
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
from pelagos.connectors.bind.namedconf.resolve import (
    ConfigFiles,
    build_tree,
    files_tree,
    inherited_zone_lists,
    key_secret,
)
from pelagos.connectors.bind.restoreplan import BindRestore
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
from pelagos.core import permguard
from pelagos.core import settings_registry as reg
from pelagos.core.write_pipeline import FileChange, WritePipeline
from pelagos.domain import (
    BindConfigTree,
    BindInstanceStats,
    Change,
    DnsCapabilities,
    NodeApplyResult,
    Plan,
    RRset,
    Zone,
    ZoneKind,
    ZoneStatus,
    messages,
)
from pelagos.domain.common import Engine
from pelagos.domain.dns import NO_RECORD_KINDS, SOA_KINDS, normalize_name
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
PROBE_TIMEOUT = 2.0
# A planned promotion waits this long for the copy to reach the frozen primary's serial.
SYNC_WAIT = 30.0
SYNC_POLL = 0.5
RELOAD_POLL = 0.2
# A refused AXFR is not asked again for this long (a config change through a plan resets it).
AXFR_RETRY_SECONDS = 6 * 3600.0
SIZE_CACHE_SECONDS = 60.0


def _zone_kind(change: Any) -> str | None:
    side = change.after if isinstance(change.after, dict) else change.before
    return side.get("kind") if isinstance(side, dict) else None


class BindBackend(BindExtras, BindRestore, DnsBackend):
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
        # (zone, view) -> monotonic time of a refused AXFR and named's "last configured" then; cleared
        # when a plan of this process changes the configuration.
        self._axfr_refused: dict[tuple[str, str], tuple[float, str | None]] = {}
        # Set by the web process only: the most records one read_zone may take (None: unbounded).
        self.read_limit: Callable[[], int | None] | None = None
        self._sizes: dict[tuple[str, str], tuple[float, int | None]] = {}

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

    def read_key(self, view: str | None) -> TsigKey | None:
        """Key that selects `view` for reads, None for the default view; NotSupported without a key
        configured for the view, ConnectorDenied when its secret is not on this node."""
        if view in (None, "", DEFAULT_VIEW):
            return None
        return self._require_key("read", view)

    def inherited_lists(self) -> dict[str | None, dict[str, list[str]]]:
        """also_notify and allow_transfer a zone without its own inherits, per view (None: options)."""
        return inherited_zone_lists(self._files())

    def _plan_ttl(self) -> int:
        return int(reg.get(self.ctx.settings, "plans.ttl_seconds"))

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
                # Short: a stopped named never answers, and callers hold the engine lock meanwhile.
                DnsClient(self.dns.server, self.dns.port, timeout=PROBE_TIMEOUT).soa_serial(".")
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
        files = self._files()
        tree = build_tree(files, self.ctx.node_id, self.include_dir)
        zones = tree.zones + self.extra_zones(tree)
        roles.mark(zones, roles.zone_roles(files))
        return [z for z in zones if view is None or z.view == view]

    def zone_status(self, zone: str, view: str | None = None) -> ZoneStatus:
        try:
            raw = self.rndc.zonestatus(zone, view)
        except RndcNotFound as exc:
            st = zone_status_from(zone, view, self.ctx.node_id, {})
            # named keeps no zone object for a forward zone: its status is its kind, not an error.
            local = self.config_zone(zone, view)
            if local is not None and local.kind in NO_RECORD_KINDS:
                st.kind = local.kind
            else:
                st.error = str(exc)
            return st
        st = zone_status_from(zone, view, self.ctx.node_id, raw)
        if st.kind is not None and st.kind not in SOA_KINDS:
            # An SOA query would leave this node (forwarded or resolved): zonestatus is all there is.
            st.serial = st.config_serial if st.kind is ZoneKind.STUB else None
            return st
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
        local = self.config_zone(zone, view)
        if local is not None and local.kind in NO_RECORD_KINDS:
            raise ZoneWithoutRecords(local.name, local.view, local.kind.value)
        if is_builtin_zone(zone) and (local is None or not local.dynamic):
            # Distribution zones are local files and refuse transfers: never ask named for them.
            if local is None or not local.file:
                raise ConnectorDenied(f"{zone} is a built-in zone without a readable file")
            return self._read_zone_file(local, zone)
        key = (normalize_name(zone), view or DEFAULT_VIEW)
        limit = self._bounded(key)
        asked = self._axfr_refused.get(key)
        # A reconfig (a plan from another process granting the transfer) makes the refusal stale.
        if (
            asked is not None
            and time.monotonic() - asked[0] < AXFR_RETRY_SECONDS
            and asked[1] == self._last_configured()
        ):
            static = self.static_zone(zone, view)
            if static is None:
                raise ConnectorDenied(f"AXFR of {zone} was refused earlier, not asked again yet")
            return self._read_zone_file(static, zone)
        try:
            bound = {} if limit is None else {"max_names": limit}
            rrsets = self.dns.axfr(zone, self._require_key("read", view), **bound)
        except ZoneTooLarge as exc:
            raise ZoneTooLarge(key[0], key[1], exc.size, exc.limit) from None
        except ConnectorDenied:
            self._axfr_refused[key] = (time.monotonic(), self._last_configured())
            # A static primary refusing the transfer is read from its file, as named loaded it.
            static = self.static_zone(zone, view)
            if static is None:
                raise
            return self._read_zone_file(static, zone)
        self._axfr_refused.pop(key, None)
        return rrsets

    def _bounded(self, key: tuple[str, str]) -> int | None:
        """The read limit, after refusing a zone whose node count (rndc zonestatus) is above it."""
        limit = self.read_limit() if self.read_limit is not None else None
        if limit is None:
            return None
        now = time.monotonic()
        hit = self._sizes.get(key)
        if hit is None or now - hit[0] > SIZE_CACHE_SECONDS:
            try:
                nodes = self.rndc.zonestatus(key[0], None if key[1] == DEFAULT_VIEW else key[1]).get("nodes")
            except ConnectorError:
                nodes = None
            hit = (now, int(nodes) if nodes and nodes.isdigit() else None)
            self._sizes[key] = hit
        if hit[1] is not None and hit[1] > limit:
            raise ZoneTooLarge(key[0], key[1], hit[1], limit)
        return limit

    def _last_configured(self) -> str | None:
        try:
            return self.rndc.status().get("last configured")
        except ConnectorError:
            return None

    def _read_zone_file(self, zone: Zone, name: str) -> list[RRset]:
        try:
            return staticzone.load(zone, self._directory()).rrsets()
        except (ZoneFileError, OSError):
            raise ConnectorDenied(f"AXFR of {name} refused and its zone file is not readable") from None

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

    def root_hints(self, zones: list[Zone] | None = None) -> dict[str, dict[str, Any]]:
        """Hints file of each `type hint` zone, keyed "<view>/<zone>" (connectors.bind.hints.read)."""
        zones = self.list_zones() if zones is None else zones
        found = [z for z in zones if z.kind is ZoneKind.HINT and z.file]
        if not found:
            return {}
        directory = self._directory()
        out = {}
        for zone in found:
            path = Path(zone.file)  # type: ignore[arg-type]
            out[f"{zone.view}/{zone.name}"] = hints.read(path if path.is_absolute() else directory / path)
        return out

    def rpz_dir(self) -> Path:
        """Where the RPZ zone files and the rewrite log live (the plan creates it with the first zone)."""
        return self.default_zone_dir() / "rpz"

    def rpz_zone_loaded(self, zone: str) -> bool:
        try:
            status = self.rndc.zonestatus(zone)
        except ConnectorError as exc:
            if "not loaded" in str(exc) or isinstance(exc, RndcNotFound):
                return False
            raise
        return status.get("loaded", "yes").lower() != "no"

    def rpz_zone_info(self, zone: str) -> dict[str, str]:
        return self.rndc.zonestatus(zone)

    def rpz_state_path(self) -> Path:
        configured = self.ctx.engine_config.get("rpz_state")
        return Path(configured) if configured else self.ctx.backup_root.parent.parent / "rpz-state.json"

    def rpz_env(self, log_path: str = "") -> Any:
        """Where this node keeps RPZ zone files and how to reload and check them (pelagos.rpz.sync)."""
        from pelagos.connectors.bind import rpzplan
        from pelagos.rpz.sync import SyncEnv

        directory = self.rpz_dir()
        return SyncEnv(
            node_id=self.ctx.node_id,
            rpz_dir=directory,
            state_path=self.rpz_state_path(),
            reload=lambda zone: self.reload(zone),
            zone_loaded=self.rpz_zone_loaded,
            zone_info=self.rpz_zone_info,
            checkzone=self.checkzone,
            group=self.group,
            log_path=Path(log_path) if log_path else rpzplan.log_path(directory.parent),
        )

    def rpz_node_state(self) -> dict[str, Any]:
        """What the collector recorded for RPZ on this node, and the memory it has (snapshot kind rpz)."""
        from pelagos.rpz import estimate, sync

        return {"state": sync.load_state(self.rpz_state_path()), "ram_mb": estimate.node_ram_mb()}

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
            default_ttl=int(reg.get(self.ctx.settings, "dns.default_ttl_seconds")),
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
        planner.zone_reader = lambda zone, view: self.dns.axfr(
            zone, self._require_key("read", None if view == DEFAULT_VIEW else view)
        )
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

    def plan_zone_changes(self, changes: list[Change], created_by: str = "") -> Plan:
        """Several zone statements of managed files in one plan (one write, one reconfig): the
        parts of a DDNS failover on one node."""
        if len(changes) == 1:
            return self.plan_zone_change(changes[0], created_by)
        targets = ", ".join(c.target for c in changes)
        summary = messages.msg("plan.zone.change", target=targets, op=messages.op(ChangeOp.REPLACE))
        return self._file_plan(PlanScope.DNS_ZONE, changes, summary, created_by)

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

    def _write_set(self, plan: Plan) -> tuple[Any, list[Any], list[Path], list[FileChange]]:
        """What applying a file plan writes: (render result, demoted changes, zone directories it
        creates, file changes). The apply and the permission guard both read it from here."""
        _, result = self._render(plan.scope, plan.changes, replay=True)
        demoted = [c for c in result.changes if isinstance(c.after, dict) and failover.DEMOTE in c.after]
        dirs = [Path(str(change.after["file"])).parent for change in demoted]
        file_changes = []
        for path in result.changed_paths():
            mode, group = self._file_mode(path, result.zone_files)
            is_zone = path in result.zone_files
            if is_zone:
                dirs.append(path.parent)
            file_changes.append(
                FileChange(
                    path=path,
                    content=result.texts[path].encode(),
                    mode=mode,
                    group=group,
                    create_dirs=not is_zone,
                )
            )
        file_changes += [
            FileChange(path=p, content=b"", create_dirs=False, remove=True) for p in result.removed
        ]
        return result, demoted, list(dict.fromkeys(dirs)), file_changes

    # Permission guard (core.permguard) -------------------------------------------------------

    def default_zone_dir(self) -> Path:
        """Where new zone files go: [engines.bind] zone_dir, else <options directory>/pelagos."""
        return self.zone_dir or self._directory() / "pelagos"

    def permission_targets(self, plan: Plan | None = None) -> list[permguard.Target]:
        """Every path applying `plan` creates, writes or reads here; without a plan, the paths every
        plan and the RPZ sync may touch (the collector's periodic check)."""
        from pelagos.installer import helper

        group = self.group
        privileged = helper.available()
        backups = permguard.backup_target(self.ctx.backup_root, "bind")

        def zone_dir(d: Path, purpose: str = "zone_dir") -> permguard.Target:
            return permguard.Target(d, permguard.DIR, "bind", purpose, group=group, subdirs=True)

        if plan is None:
            out = [zone_dir(self.default_zone_dir())]
            rpz = self.rpz_dir()
            if rpz.exists() or (self.ctx.settings.get("rpz") or {}).get("subscriptions"):
                out.append(zone_dir(rpz, "rpz_dir"))
            out.append(
                permguard.Target(
                    self.include_dir,
                    permguard.DIR,
                    "bind",
                    "include_dir",
                    group,
                    owner="pelagos",
                    dir_mode=0o2750,
                )
            )
            return [*out, backups]
        out: list[permguard.Target] = []
        if plan.scope is PlanScope.DNS_RRSET:
            zone, view = _plan_zone(plan)
            static = self.static_zone(zone, view)
            if static is None or not static.file:
                return []  # dynamic UPDATE: no file
            path = Path(static.file)
            if not path.is_absolute():
                path = self._directory() / path
            return [permguard.Target(path, permguard.FILE, "bind", "zone_file"), backups]
        if plan.scope is PlanScope.DNS_ZONE and plan.changes and ops.is_op(plan.changes[0]):
            return []
        if plan.scope is PlanScope.DNS_ZONE and plan.changes and zonerestore.is_content(plan.changes[0]):
            after = plan.changes[0].after or {}
            path = Path(str(after.get("file") or ""))
            return [
                zone_dir(path.parent),
                permguard.Target(path, permguard.FILE, "bind", "zone_file"),
                backups,
            ]
        if plan.scope is PlanScope.DNS_ZONE and _added_zone_plan(plan):
            after = plan.changes[0].after or {}
            if after.get("file_path"):
                path = Path(str(after["file_path"]))
                out += [
                    zone_dir(path.parent),
                    permguard.Target(path, permguard.FILE, "bind", "zone_file", group, 0o664),
                ]
                out.append(backups)
            return out
        if plan.scope not in (PlanScope.DNS_ZONE, PlanScope.DNS_CONFIG, PlanScope.DNS_KEY, PlanScope.DNS_ACL):
            return []
        result, _demoted, dirs, file_changes = self._write_set(plan)
        if result.errors:
            return []
        rpz = self.rpz_dir()
        out += [zone_dir(d, "rpz_dir" if d == rpz else "zone_dir") for d in dirs]
        for fc in file_changes:
            if fc.path.parent in dirs:
                continue  # written inside a directory this plan creates or already probed
            user_file = not fc.remove and fc.mode is None
            purpose = "config_file" if user_file else "include_file" if fc.mode == 0o640 else "zone_file"
            out.append(
                permguard.Target(
                    fc.path,
                    permguard.FILE,
                    "bind",
                    purpose,
                    fc.group or group,
                    fc.mode,
                    privileged and user_file,
                )
            )
        return [*out, backups] if file_changes else out

    def permission_checks(self, plan: Plan | None = None) -> list[permguard.Check]:
        return permguard.run(self.permission_targets(plan))

    def _apply_files(self, plan: Plan) -> NodeApplyResult:
        self._check_file_preconditions(plan)
        if plan.scope is PlanScope.DNS_ZONE:
            self._sync_promoted(plan.changes)
        result, demoted, dirs, file_changes = self._write_set(plan)
        if result.errors:
            return NodeApplyResult(node_id=self.ctx.node_id, ok=False, message="; ".join(result.errors))
        paths = result.changed_paths()
        if not paths:
            for d in dirs:
                self._ensure_zone_dir(d)
            return NodeApplyResult(
                node_id=self.ctx.node_id, ok=True, message="already applied: no file change"
            )
        for d in dirs:
            self._ensure_zone_dir(d)
        verify = self._verify(plan)
        moved = [c.target for c in plan.changes if handover.is_handover(c)]
        if moved:
            verify = self._verify_handover(verify, moved)
        pipeline = self._config_pipeline(
            backup_root=self.ctx.backup_root,
            validate=lambda: run_checkconf(self.checkconf, self.named_conf),
            reload=lambda: self.reconfig() or "reconfig done",
            verify=verify,
            label=plan.id,
        )
        outcome = pipeline.run(file_changes)
        self._axfr_refused.clear()
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
            message = f"{len(paths)} file(s) written, reconfig done"
            if result.removed:
                message += f", {len(result.removed)} stale zone file(s) moved to the backup"
            for change in demoted:
                message += "; " + self._retransfer(change.target)
            return NodeApplyResult(node_id=self.ctx.node_id, ok=True, message=message)
        return NodeApplyResult(
            node_id=self.ctx.node_id,
            ok=False,
            message=outcome.error or "write pipeline failed",
            rolled_back=outcome.rolled_back,
        )

    def _config_pipeline(self, **kwargs: Any) -> Any:
        """The write pipeline of configuration plans: user files this process may not write (Debian's
        named.conf.local is root:bind 0644) go through the privileged helper."""
        pipeline = self.ctx.pipeline_factory(**kwargs)
        if isinstance(pipeline, WritePipeline):
            pipeline.privileged = self._write_user_file
        return pipeline

    def _write_user_file(self, path: Path, content: bytes) -> None:
        from pelagos.installer import helper

        if path.resolve().is_relative_to(self.include_dir.resolve()) or not helper.available():
            raise PermissionError(f"cannot write {path}: not writable by this process")
        try:
            helper.HelperClient(timeout=60).call(
                "bind_user_write", path=str(path), content=content.decode(), sha256=file_sha256(path)
            )
        except helper.HelperError as exc:
            raise PermissionError(f"cannot write {path} through the privileged helper: {exc}") from None

    def _retransfer(self, target: str) -> str:
        """A demoted copy takes the zone again from the new primary (the reconfig started it empty)."""
        view, _, name = target.partition("/")
        try:
            self.retransfer(name, None if view in ("", DEFAULT_VIEW) else view)
            return f"retransfer of {name} started"
        except ConnectorError as exc:  # the empty copy asks its primary at load anyway
            return f"retransfer of {name} not started: {exc}"

    def _sync_promoted(self, changes: list[Change]) -> None:
        """Before a planned promotion reads its copy: wait until the copy serves the serial of the
        frozen old primary (`promote.sync`), asking named to refresh it meanwhile."""
        for change in changes:
            promote = failover.promotion(change.after) if isinstance(change.after, dict) else None
            sync = promote.get("sync") if promote else None
            if not isinstance(sync, dict):
                continue
            view, _, name = change.target.partition("/")
            view = None if view in ("", DEFAULT_VIEW) else view
            client = DnsClient(str(sync.get("address")), int(sync.get("port") or 53), timeout=PROBE_TIMEOUT)
            target = client.soa_serial(name, self.read_key(view) if view else None)
            if target is None:
                raise ConnectorError(f"the old primary does not serve {name}: cannot wait for its serial")
            deadline = time.monotonic() + SYNC_WAIT
            while True:
                if self.soa_serial(name, view) == target:
                    break
                if time.monotonic() > deadline:
                    raise ConnectorError(
                        f"the copy of {name} did not reach serial {target} of the old primary"
                        f" within {SYNC_WAIT:g} s"
                    )
                try:
                    self.rndc.run("refresh", *zone_args(name, view))
                except ConnectorError:
                    pass
                time.sleep(SYNC_POLL)

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
        """Zone directories are group writable and given to the BIND group (setgid when their parent
        is): named creates journals and transferred files there. Never S_ISGID in a mode argument."""
        try:
            permguard.make_group_dir(directory, self.group)
        except (OSError, LookupError) as exc:
            error = permguard.apply_error(exc, str(directory))
            failure = ConnectorError(messages.render(error))
            failure.message = error  # type: ignore[attr-defined]
            raise failure from exc

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
            if plan.scope is PlanScope.DNS_ZONE and plan.changes and zonerestore.is_content(plan.changes[0]):
                return self._apply_zone_content(plan, "apply")
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
            return NodeApplyResult(
                node_id=self.ctx.node_id,
                ok=False,
                message=str(exc),
                message_message=getattr(exc, "message", None),
            )

    def rollback(self, plan: Plan) -> NodeApplyResult:
        self.forget_extra_zones()
        try:
            if plan.scope is PlanScope.DNS_ZONE and plan.changes and zonerestore.is_content(plan.changes[0]):
                return self._apply_zone_content(plan, "rollback")
            if plan.scope is PlanScope.DNS_ZONE and plan.changes and ops.is_op(plan.changes[0]):
                return self._rollback_op(plan)
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
            pipeline = self._config_pipeline(
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
