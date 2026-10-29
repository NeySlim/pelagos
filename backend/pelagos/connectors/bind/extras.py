# SPDX-License-Identifier: Apache-2.0
"""BindBackend features beyond named.conf: zones added with rndc addzone, catalog zones, DNSSEC
policies and key operations, and rndc operations carried by plans (run on a peer node).

A mixin over BindBackend: it uses the backend's rndc, statistics and DNS clients, keys and planner.
"""

from __future__ import annotations

import difflib
import time
from pathlib import Path
from typing import Any

from pelagos.connectors.base import ConnectorError, NotSupported
from pelagos.connectors.bind import addzone, catalog, dnssec, ops
from pelagos.connectors.bind.configplan import initial_ns, run_checkzone, zone_file_text
from pelagos.connectors.bind.managed import ManagedFiles
from pelagos.connectors.bind.namedconf.lexer import ParseError
from pelagos.connectors.bind.rndc import RndcNotFound, zone_args
from pelagos.core.write_pipeline import FileChange
from pelagos.domain import BindConfigTree, Change, NodeApplyResult, Plan, RRset, Zone, messages
from pelagos.domain.dns import ZoneKind, ZoneSource, normalize_name
from pelagos.domain.plan import ChangeOp, PlanScope, PlanState, ValidationResult

DEFAULT_VIEW = "_default"
EXTRA_CACHE_SECONDS = 5.0


class BindExtras:
    """Mixed into BindBackend; every method relies on the backend's attributes."""

    _extra_cache: tuple[float, list[Zone]] | None = None

    # Zones outside named.conf ------------------------------------------------------------

    def forget_extra_zones(self) -> None:
        self._extra_cache = None

    def extra_zones(self, tree: BindConfigTree) -> list[Zone]:
        """Added zones (source addzone) and catalog members (source catalog) loaded by named."""
        now = time.monotonic()
        if self._extra_cache is not None and now - self._extra_cache[0] < EXTRA_CACHE_SECONDS:
            return list(self._extra_cache[1])
        config = {(z.view, z.name) for z in tree.zones}
        try:
            loaded = addzone.loaded_zones(self.stats.fetch("/zones"))
        except ConnectorError:
            nzf = addzone.nzf_zones(self._directory(), list(tree.views))
            out = [z for z in nzf if (z.view, z.name) not in config]
            self._extra_cache = (now, out)
            return list(out)
        members = self._catalog_members(tree)
        out: list[Zone] = []
        for view, name, kind in loaded:
            if (view, name) in config:
                continue
            if (view, name) in members:
                zone = Zone(name=name, kind=addzone.kind_from_stats(kind), view=view)
                zone.source = ZoneSource.CATALOG
                zone.extra["catalog"] = members[(view, name)]
            else:
                zone = self._added_zone(name, view, kind)
            out.append(zone)
        self._extra_cache = (now, out)
        return list(out)

    def _added_zone(self, name: str, view: str, kind: str) -> Zone:
        where = None if view == DEFAULT_VIEW else view
        store = self._nz_store(view)
        try:
            text = self.rndc.run("showzone", *zone_args(name, where))
            return addzone.zone_from_showzone(text, view, store)
        except (ConnectorError, ParseError, ValueError):
            zone = Zone(name=name, kind=addzone.kind_from_stats(kind), view=view, config_path=store)
            zone.source = ZoneSource.ADDZONE
            return zone

    def _nz_store(self, view: str) -> str:
        directory = self._directory()
        nzf = directory / f"{view}.nzf"
        return str(nzf if nzf.exists() else directory / f"{view}.nzd")

    def _catalog_members(self, tree: BindConfigTree) -> dict[tuple[str, str], str]:
        """(view, member) -> catalog for every consumed catalog this node can read."""
        out: dict[tuple[str, str], str] = {}
        try:
            consumed = catalog.consumed_catalogs(self._files())
        except (OSError, ConnectorError):
            return out
        for cat in consumed:
            try:
                # A direct transfer: read_zone looks the zone up in list_zones, which lands back here.
                where = None if cat.view == DEFAULT_VIEW else cat.view
                rrsets = self.dns.axfr(cat.zone, self._require_key("read", where))
            except (ConnectorError, NotSupported):
                continue
            for member in catalog.members(cat.zone, rrsets)[0]:
                out[(cat.view, member["zone"])] = cat.zone
        return out

    def _read_catalog(self, zone: str, view: str) -> list[RRset]:
        return self.read_zone(zone, None if view == DEFAULT_VIEW else view)

    # Catalog zones ------------------------------------------------------------------------

    def catalog_zones(self) -> list[dict[str, Any]]:
        """Consumed catalogs (catalog-zones statements) and produced ones (local primaries whose
        `version` TXT names a catalog schema), each with its members as read now."""
        items: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for cat in catalog.consumed_catalogs(self._files()):
            seen.add((cat.view, cat.zone))
            items.append(
                self._catalog_item(
                    cat.zone,
                    cat.view,
                    "consumer",
                    {
                        "statement": cat.statement,
                        "default_primaries": cat.default_primaries,
                        "options": cat.options,
                    },
                )
            )
        for zone in self.list_zones():
            if zone.kind is not ZoneKind.PRIMARY or (zone.view, zone.name) in seen:
                continue
            view = None if zone.view == DEFAULT_VIEW else zone.view
            try:
                key = self._require_key("read", view) if view else None
                version = self.dns.query("version." + zone.name, "TXT", key)
            except (ConnectorError, NotSupported):
                continue
            if catalog.is_catalog(version):
                items.append(
                    self._catalog_item(zone.name, zone.view, "producer", {"source": zone.source.value})
                )
        return items

    def _catalog_item(self, zone: str, view: str, role: str, extra: dict[str, Any]) -> dict[str, Any]:
        item: dict[str, Any] = {"zone": zone, "view": view, "role": role, **extra}
        try:
            members, version = catalog.members(zone, self._read_catalog(zone, view))
            item.update(members=members, member_count=len(members), version=version, error=None)
        except (ConnectorError, NotSupported) as exc:
            item.update(members=[], member_count=0, version=None, error=str(exc))
        return item

    # DNSSEC -------------------------------------------------------------------------------

    def dnssec_policies(self) -> list[dict[str, Any]]:
        files = self._files()
        found = dnssec.policies(files, self.include_dir)
        zones = self.list_zones()
        for entry in found:
            entry["used_by"] = sorted(f"{z.view}/{z.name}" for z in zones if z.dnssec_policy == entry["name"])
        return found

    def dnssec_details(self, zone: str, view: str | None, status: dict[str, Any]) -> dict[str, Any]:
        """Key fields for the screens, DS records of the KSK/CSK and what the parent must do."""
        dnssec.enrich_status(status)
        status["ds"] = []
        status["cds"] = []
        status["ds_guidance"] = []
        if not status.get("signed"):
            return status
        try:
            key = self._require_key("read", view)
            dnskeys = self.dns.query(zone, "DNSKEY", key) or []
            status["cds"] = self.dns.query(zone, "CDS", key) or []
        except (ConnectorError, NotSupported) as exc:
            status["ds_error"] = str(exc)
            return status
        ds = dnssec.ds_records(zone, dnskeys)
        status["ds"] = list(ds.values())
        for key_entry in status.get("keys", []):
            key_entry["ds"] = ds.get(key_entry.get("tag"))
        status["ds_guidance"] = dnssec.ds_guidance(status, ds)
        return status

    # Operations carried by a plan ------------------------------------------------------------

    def plan_operation(
        self, name: str, zone: str, view: str | None, args: dict[str, Any] | None = None, created_by: str = ""
    ) -> Plan:
        """An rndc operation as a plan: previewed (DNSSEC key operations need confirmation) and
        applied on the node that runs it."""
        args = dict(args or {})
        view = None if view in (None, DEFAULT_VIEW) else view
        command = ops.command_text(name, zone, view, args)  # validates name and arguments
        summary = messages.msg("plan.zone.operation", zone=normalize_name(zone), command=command)
        plan = self._new_plan(PlanScope.DNS_ZONE, summary, created_by)
        plan.changes = [
            Change(ChangeOp.REPLACE, ops.target(name, zone, view), after=ops.check_args(name, args))
        ]
        plan.diff = f"+{command}"
        plan.requires_confirmation = name in ops.DNSSEC_OPS
        plan.validations = [
            ValidationResult(
                ok=True, tool="rndc", output=f"{command} (cannot be rolled back)", node_id=self.ctx.node_id
            )
        ]
        plan.state = PlanState.VALIDATED
        return plan

    def _apply_op(self, plan: Plan) -> NodeApplyResult:
        node = self.ctx.node_id
        change = plan.changes[0]
        try:
            name, view, zone = ops.parse_target(change.target)
            args = ops.rndc_args(name, zone, view, dict(change.after or {}))
        except ops.OpError as exc:
            return NodeApplyResult(node_id=node, ok=False, message=str(exc))
        details = self._plan_details(plan.id)
        details["request"] = {"rndc": args}
        try:
            output = self.rndc.run(*args)
        except ConnectorError as exc:
            details["response"] = {"error": str(exc)}
            return NodeApplyResult(node_id=node, ok=False, message=f"rndc {args[0]} failed: {exc}")
        details["response"] = {"output": output}
        return NodeApplyResult(
            node_id=node, ok=True, message=output.strip() or f"rndc {' '.join(args[:2])} done"
        )

    def _rollback_op(self, plan: Plan) -> NodeApplyResult:
        """Only a freeze has an inverse (thaw): the first step of a planned DDNS switchover."""
        node = self.ctx.node_id
        try:
            name, view, zone = ops.parse_target(plan.changes[0].target)
        except ops.OpError as exc:
            return NodeApplyResult(node_id=node, ok=False, message=str(exc))
        if name != "freeze":
            return NodeApplyResult(node_id=node, ok=False, message="an rndc operation cannot be rolled back")
        args = ops.rndc_args("thaw", zone, view, {})
        try:
            output = self.rndc.run(*args)
        except ConnectorError as exc:
            return NodeApplyResult(node_id=node, ok=False, message=f"rndc thaw failed: {exc}")
        self._plan_details(plan.id)["rollback"] = {"rndc": args, "output": output}
        return NodeApplyResult(
            node_id=node, ok=True, message=output.strip() or "rndc thaw done", rolled_back=True
        )

    # Zones added with rndc addzone ----------------------------------------------------------

    def _allow_new_zones(self, view: str) -> bool:
        files = self._files()
        found = None
        for res in files.statements():
            if res.node.name != "allow-new-zones" or len(res.parents) != 1:
                continue
            parent = res.parents[0]
            if parent.name == "options" and found is None:
                found = res.node.args[:1] == ["yes"]
            elif parent.name == "view" and parent.args[:1] == [view]:
                return res.node.args[:1] == ["yes"]
        return bool(found)

    def plan_added_zone(self, change: Change, existing: Zone | None, created_by: str = "") -> Plan:
        """rndc addzone / modzone / delzone; a new primary gets its initial zone file first."""
        op = ChangeOp(change.op)
        view, _, name = change.target.partition("/")
        view = view or DEFAULT_VIEW
        name = normalize_name(name)
        command = {ChangeOp.ADD: "addzone", ChangeOp.REPLACE: "modzone", ChangeOp.DELETE: "delzone"}[op]
        summary = messages.msg("plan.zone.added", target=change.target, op=messages.op(op), command=command)
        plan = self._new_plan(PlanScope.DNS_ZONE, summary, created_by)
        node = self.ctx.node_id
        errors: list[str] = []
        validations: list[ValidationResult] = []
        before = None
        if existing is not None:
            before = existing.to_dict()
            before["config"] = self._showzone_block(existing)
        after = None
        diff: list[str] = []
        if op is not ChangeOp.DELETE:
            try:
                after, file_text = self._added_zone_after(change, name, view, op)
            except (ValueError, KeyError) as exc:
                errors.append(str(exc))
                file_text = None
            if after is not None and file_text is not None:
                check = run_checkzone(self.checkzone, name, file_text)
                check.node_id = node
                validations.append(check)
                diff.extend(
                    difflib.unified_diff(
                        [], file_text.splitlines(keepends=True), fromfile="/dev/null", tofile=after["file"]
                    )
                )
        if op is ChangeOp.ADD and not self._allow_new_zones(view):
            errors.append("allow-new-zones is not enabled (options or view): rndc addzone would be refused")
        if op is ChangeOp.ADD and existing is not None:
            errors.append(f"zone {name} already exists in view {view}")
        if op is not ChangeOp.ADD and existing is None:
            errors.append(f"zone {name} is not an added zone in view {view}")
        where = addzone.where(Zone(name=name, kind=ZoneKind.PRIMARY, view=view))
        if before is not None and before.get("config"):
            diff.append(
                f"-rndc {'addzone' if op is not ChangeOp.ADD else command} {where} {before['config']}\n"
            )
        if after is not None:
            diff.append(f"+rndc {command} {where} {after['config']}\n")
        elif op is ChangeOp.DELETE:
            diff.append(f"+rndc delzone {where} (the zone file is kept)\n")
        plan.changes = [Change(op, f"{view}/{name}", before=before, after=after, node_ids=change.node_ids)]
        plan.diff = "".join(d if d.endswith("\n") else d + "\n" for d in diff)
        plan.requires_confirmation = op is ChangeOp.DELETE
        validations.insert(
            0,
            ValidationResult(
                ok=not errors, tool="rndc", output="\n".join(errors) or f"rndc {command}", node_id=node
            ),
        )
        plan.validations = validations
        ok = all(v.ok for v in validations)
        plan.state = PlanState.VALIDATED if ok else PlanState.FAILED
        plan.error = None if ok else "; ".join(v.output for v in validations if not v.ok)
        return plan

    def _showzone_block(self, zone: Zone) -> str | None:
        where = None if zone.view == DEFAULT_VIEW else zone.view
        try:
            text = self.rndc.run("showzone", *zone_args(zone.name, where))
        except ConnectorError:
            return None
        return text.strip()[text.strip().index("{") :] if "{" in text else None

    def _added_zone_after(
        self, change: Change, name: str, view: str, op: ChangeOp
    ) -> tuple[dict[str, Any], str | None]:
        if not isinstance(change.after, dict):
            raise ValueError("`after` must be a Zone object")
        raw = dict(change.after)
        raw.update(name=name, view=view)
        zone = Zone.from_dict(
            {k: v for k, v in raw.items() if k not in ("ns", "records", "source", "config")}
        )
        zone.source = ZoneSource.ADDZONE
        planner = self._planner()
        file_text = None
        if zone.kind in (ZoneKind.SECONDARY, ZoneKind.STUB) and not zone.primaries:
            raise ValueError(f"a {zone.kind.value} zone needs primaries")
        if zone.kind is ZoneKind.FORWARD and not zone.forwarders:
            raise ValueError("a forward zone needs forwarders")
        initial: dict[str, Any] = {}
        if zone.kind in (ZoneKind.PRIMARY, ZoneKind.SECONDARY, ZoneKind.MIRROR):
            path = planner._zone_file_path(zone)
            zone.file = zone.file or str(path)
            if op is ChangeOp.ADD and zone.kind is ZoneKind.PRIMARY and not path.exists():
                records = [RRset.from_dict(r) for r in raw.get("records") or []]
                ns = initial_ns(name, raw.get("ns") or planner.default_ns, records)
                file_text = zone_file_text(name, ns, records)
                initial = {"ns": ns, "records": [r.to_dict() for r in records], "file_path": str(path)}
        after = zone.to_dict()
        after.update(initial)
        after["source"] = ZoneSource.ADDZONE.value
        after["config"] = addzone.config_block(zone, ManagedFiles.zone_statement(zone))
        return after, file_text

    def _apply_added_zone(self, plan: Plan, rollback: bool = False) -> NodeApplyResult:
        node = self.ctx.node_id
        change = plan.changes[0]
        op = ChangeOp(change.op)
        view, _, name = change.target.partition("/")
        where = None if view in ("", DEFAULT_VIEW) else view
        location = zone_args(name, where)
        if rollback:
            op = {
                ChangeOp.ADD: ChangeOp.DELETE,
                ChangeOp.DELETE: ChangeOp.ADD,
                ChangeOp.REPLACE: ChangeOp.REPLACE,
            }[op]
            config = (change.before or {}).get("config")
        else:
            config = (change.after or {}).get("config")
        if op is not ChangeOp.DELETE and not config:
            return NodeApplyResult(node_id=node, ok=False, message="no zone configuration to send")
        args = {
            ChangeOp.ADD: ["addzone", *location, str(config)],
            ChangeOp.REPLACE: ["modzone", *location, str(config)],
            ChangeOp.DELETE: ["delzone", *location],
        }[op]
        details = self._plan_details(plan.id)
        label = "rollback" if rollback else "apply"
        after = change.after or {}
        file_path = after.get("file_path") if not rollback and op is ChangeOp.ADD else None
        self.forget_extra_zones()
        if file_path and not Path(file_path).exists():
            # A new primary: its zone file goes through the pipeline, rndc addzone is the reload.
            text = zone_file_text(
                name,
                list(after.get("ns") or ["localhost."]),
                [RRset.from_dict(r) for r in after.get("records") or []],
            )
            self._ensure_zone_dir(Path(file_path).parent)
            pipeline = self.ctx.pipeline_factory(
                backup_root=self.ctx.backup_root,
                validate=lambda: run_checkzone(self.checkzone, name, text),
                reload=lambda: self.rndc.run(*args) or "addzone done",
                verify=lambda: self._zone_present(name, where),
                label=plan.id,
            )
            outcome = pipeline.run(
                [
                    FileChange(
                        path=Path(file_path),
                        content=text.encode(),
                        mode=0o664,
                        group=self.group,
                        create_dirs=False,
                    )
                ]
            )
            details[label] = {
                "request": {"rndc": args[:-1], "file": file_path},
                "response": {"steps": outcome.steps},
            }
            return NodeApplyResult(
                node_id=node,
                ok=outcome.ok,
                message="zone file written, rndc addzone done"
                if outcome.ok
                else (outcome.error or "addzone failed"),
                rolled_back=outcome.rolled_back,
            )
        details[label] = {"request": {"rndc": args}}
        try:
            output = self.rndc.run(*args)
        except ConnectorError as exc:
            details[label]["response"] = {"error": str(exc)}
            return NodeApplyResult(node_id=node, ok=False, message=f"rndc {args[0]} failed: {exc}")
        details[label]["response"] = {"output": output}
        return NodeApplyResult(
            node_id=node, ok=True, message=output.strip() or f"rndc {args[0]} done", rolled_back=rollback
        )

    def _zone_present(self, name: str, view: str | None) -> bool:
        try:
            self.rndc.zonestatus(name, view)
            return True
        except RndcNotFound:
            return False


def is_added_zone_change(change: Change, existing: Zone | None) -> bool:
    """A zone plan handled by rndc addzone/modzone/delzone instead of zones.conf."""
    if existing is not None:
        return existing.source is ZoneSource.ADDZONE
    after = change.after if isinstance(change.after, dict) else {}
    return ChangeOp(change.op) is ChangeOp.ADD and after.get("source") == ZoneSource.ADDZONE.value
