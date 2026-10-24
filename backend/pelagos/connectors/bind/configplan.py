# SPDX-License-Identifier: Apache-2.0
"""File plans for BIND: zone, key, ACL, option and raw statement changes rendered into managed files.

The same rendering runs at plan time (for the diff and validation) and at apply time against the
files as they are then, so a plan can be applied on any node; FILE_SHA256 preconditions pin the
files of the node that built the plan.
"""

from __future__ import annotations

import base64
import difflib
import hashlib
import re
import secrets
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pelagos.connectors.bind.dns_client import ALGORITHMS
from pelagos.connectors.bind.managed import (
    DEFAULT_VIEW,
    AclSpec,
    KeySpec,
    ManagedFiles,
    note_comment,
    plan_include_lines,
)
from pelagos.connectors.bind.namedconf.grammar import statement_info
from pelagos.connectors.bind.namedconf.lexer import ParseError
from pelagos.connectors.bind.namedconf.resolve import (
    MANAGED_HEADER,
    ConfigFiles,
    build_tree,
    materialize,
    parse,
    zone_from_node,
)
from pelagos.connectors.bind.namedconf.tree import ConfigDocument, parse_statements, unquote
from pelagos.connectors.bind.rrset import owner_name
from pelagos.domain.dns import BindConfigTree, RRset, Zone, ZoneKind, ZoneSource, normalize_name
from pelagos.domain.plan import Change, ChangeOp, Precondition, PreconditionKind, ValidationResult

MASK = "****"
DIGEST_BYTES = {
    "hmac-md5": 16,
    "hmac-sha1": 20,
    "hmac-sha224": 28,
    "hmac-sha256": 32,
    "hmac-sha384": 48,
    "hmac-sha512": 64,
}
_SECRET_RE = re.compile(r'(\bsecret\s+)"[^"]*"')
ABSENT = "absent"


class PlanError(ValueError):
    """A change that cannot be rendered (conflict with the user files, bad value, unknown target)."""


def mask_secrets(text: str) -> str:
    return _SECRET_RE.sub(lambda m: m.group(1) + f'"{MASK}"', text)


def new_secret(algorithm: str = "hmac-sha256") -> str:
    return base64.b64encode(secrets.token_bytes(DIGEST_BYTES.get(algorithm, 32))).decode()


def sha256_text(text: str | None) -> str:
    return ABSENT if text is None else hashlib.sha256(text.encode()).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256_text(path.read_text()) if path.is_file() else ABSENT


@dataclass(slots=True)
class RenderResult:
    texts: dict[Path, str] = field(default_factory=dict)  # new content of every touched file
    originals: dict[Path, str | None] = field(default_factory=dict)
    changes: list[Change] = field(default_factory=list)  # normalized, before filled
    errors: list[str] = field(default_factory=list)
    zone_files: dict[Path, str] = field(default_factory=dict)  # new zone files (subset of texts)
    requires_confirmation: bool = False

    def changed_paths(self) -> list[Path]:
        return [p for p, t in self.texts.items() if self.originals.get(p) != t]

    def diff(self) -> str:
        chunks: list[str] = []
        for path in self.changed_paths():
            before = mask_secrets(self.originals.get(path) or "")
            after = mask_secrets(self.texts[path])
            chunks.append(
                "".join(
                    difflib.unified_diff(
                        before.splitlines(keepends=True),
                        after.splitlines(keepends=True),
                        fromfile=str(path) if self.originals.get(path) is not None else "/dev/null",
                        tofile=str(path),
                    )
                )
            )
        return "".join(c if c.endswith("\n") else c + "\n" for c in chunks if c)

    def preconditions(self, node_id: str | None) -> list[Precondition]:
        return [
            Precondition(PreconditionKind.FILE_SHA256, str(p), sha256_text(self.originals.get(p)), node_id)
            for p in self.changed_paths()
        ]


class ConfigPlanner:
    """Renders changes against the current files. One instance per plan or apply."""

    def __init__(
        self,
        user_conf: Path,
        include_dir: Path,
        node_id: str = "",
        zone_dir: Path | None = None,
        default_ns: list[str] | None = None,
    ) -> None:
        self.user_conf = Path(user_conf)
        self.managed = ManagedFiles(Path(include_dir))
        self.files = ConfigFiles.load(self.user_conf)
        self.tree: BindConfigTree = build_tree(self.files, node_id, self.managed.include_dir)
        self.zone_dir = Path(zone_dir) if zone_dir else self._default_zone_dir()
        self.default_ns = default_ns or []
        self.result = RenderResult()
        self.node_id = node_id
        self._docs: dict[Path, ConfigDocument] = {}

    # Documents -----------------------------------------------------------------

    def _default_zone_dir(self) -> Path:
        directory = self.option("directory")
        base = Path(unquote(directory)) if directory else self.user_conf.parent
        return base / "pelagos"

    def option(self, name: str) -> str | None:
        for entry in self.tree.options:
            if entry.name == name:
                return entry.value
        return None

    def doc(self, path: Path) -> ConfigDocument:
        path = Path(path)
        if path not in self._docs:
            original = path.read_text() if path.is_file() else None
            self.result.originals[path] = original
            self._docs[path] = self.managed.document(path, original)
        return self._docs[path]

    def _set_text(self, path: Path, text: str) -> None:
        if path not in self.result.originals:
            self.result.originals[path] = path.read_text() if path.is_file() else None
        self.result.texts[path] = text

    def finish(self) -> RenderResult:
        for path, doc in self._docs.items():
            self.result.texts[path] = doc.serialize()
        self._ensure_pelagos_conf()
        return self.result

    def _ensure_pelagos_conf(self) -> None:
        # A managed file that pelagos.conf includes must exist, or named-checkconf fails.
        touched = {p.name for p in self.result.texts if p.parent == self.managed.include_dir}
        if touched & {"keys.conf", "acls.conf", "zones.conf", "policies.conf"}:
            for p in (self.managed.keys_conf, self.managed.acls_conf, self.managed.zones_conf):
                if p not in self.result.texts and not p.is_file():
                    self._set_text(p, MANAGED_HEADER + "\n")
            if not self.managed.pelagos_conf.is_file() and self.managed.pelagos_conf not in self.result.texts:
                self._set_text(self.managed.pelagos_conf, self.managed.render_pelagos_conf())

    # Dispatch --------------------------------------------------------------------

    def apply_change(self, change: Change) -> None:
        try:
            target = change.target
            if target.startswith("keys/"):
                self.key_change(change, target[len("keys/") :])
            elif target.startswith("acls/"):
                self.acl_change(change, target[len("acls/") :])
            elif target.startswith("options/"):
                self.option_change(change, target[len("options/") :])
            elif target.startswith("raw:"):
                self.raw_change(change, target[len("raw:") :])
            elif target == "pelagos/includes":
                self.include_setup(change)
            elif target.startswith("dnssec-policy/"):
                self.policy_change(change, target[len("dnssec-policy/") :])
            else:
                raise PlanError(f"unknown dns.config target {target!r}")
        except (PlanError, ParseError, ValueError, KeyError) as exc:
            self.result.errors.append(f"{change.target}: {exc}")

    # DNSSEC policies -----------------------------------------------------------------

    def policy_change(self, change: Change, name: str) -> None:
        """dnssec-policy statements live in policies.conf, which pelagos.conf includes."""
        from pelagos.connectors.bind import dnssec

        dnssec.check_name(name)
        for entry in dnssec.policies(self.files, self.managed.include_dir):
            if entry["name"] == name and entry["source"] != "pelagos":
                raise PlanError(f"dnssec-policy {name} is defined in a user file; Pelagos never edits it")
        doc = self.doc(self.managed.policies_conf)
        existing = self.managed.find(doc, "dnssec-policy", name)
        before = existing.serialize().strip() if existing is not None else None
        op = ChangeOp(change.op)
        used = sorted(z.name for z in self.tree.zones if z.dnssec_policy == name)
        if op is ChangeOp.DELETE:
            if existing is None:
                raise PlanError(f"dnssec-policy {name} is not managed by Pelagos")
            if used:
                raise PlanError(f"dnssec-policy {name} is used by {', '.join(used)}")
            self.managed.remove(doc, "dnssec-policy", name)
            self.result.requires_confirmation = True
            self.result.changes.append(Change(op, change.target, before=before, after=None))
            return
        if op is ChangeOp.ADD and existing is not None:
            raise PlanError(f"dnssec-policy {name} already exists; use replace")
        if op is ChangeOp.REPLACE and existing is None:
            raise PlanError(f"dnssec-policy {name} is not managed by Pelagos")
        after = change.after if isinstance(change.after, dict) else {}
        statement = dnssec.render_policy(name, list(after.get("statements") or []))
        self.managed.upsert(doc, statement, "dnssec-policy", name, None)
        self.result.requires_confirmation = self.result.requires_confirmation or bool(used)
        self.result.changes.append(
            Change(op, change.target, before=before, after={"name": name, "text": statement.strip(), **after})
        )
        self._include_policies()

    def _include_policies(self) -> None:
        """Add `include ".../policies.conf";` to pelagos.conf, keeping the rest of that file."""
        path = self.managed.pelagos_conf
        text = self.result.texts.get(path)
        if text is None:
            text = path.read_text() if path.is_file() else self.managed.render_pelagos_conf()
        doc = parse(text, str(path))
        target = str(self.managed.policies_conf)
        if any(n.kind == "include" and n.args and n.args[0] == target for n in doc.statements()):
            return
        doc.add_statement(f'include "{target}";')
        self._set_text(path, doc.serialize())

    # Zones -------------------------------------------------------------------------

    def user_zone(self, name: str, view: str) -> Zone | None:
        for zone in self.tree.zones:
            if zone.name == name and zone.view == view and zone.source is ZoneSource.USER_CONF:
                return zone
        return None

    def zone_change(self, change: Change) -> None:
        try:
            self._zone_change(change)
        except (PlanError, ParseError, ValueError, KeyError) as exc:
            self.result.errors.append(f"{change.target}: {exc}")

    def _zone_change(self, change: Change) -> None:
        view, sep, name = change.target.partition("/")
        if not sep or not name:
            raise PlanError("target must be <view>/<zone>")
        view = view or DEFAULT_VIEW
        name = normalize_name(name)
        op = ChangeOp(change.op)
        self._check_zone_includes(view)
        if self.user_zone(name, view) is not None:
            raise PlanError(f"zone {name} is defined in a user file; Pelagos never edits it")
        path = self.managed.zones_file(view)
        doc = self.doc(path)
        existing = self.managed.find(doc, "zone", name)
        before = (
            zone_from_node(existing, view, str(path), True, self.managed.note_of(doc, existing)).to_dict()
            if existing is not None
            else None
        )
        if op is ChangeOp.DELETE:
            if existing is None:
                raise PlanError(f"zone {name} is not managed by Pelagos in view {view}")
            self.managed.remove(doc, "zone", name)
            self.result.requires_confirmation = True
            self.result.changes.append(
                Change(op, change.target, before=before, after=None, node_ids=change.node_ids)
            )
            return
        if op is ChangeOp.ADD and existing is not None:
            raise PlanError(f"zone {name} already exists in {path.name}; use replace")
        if op is ChangeOp.REPLACE and existing is None:
            raise PlanError(f"zone {name} is not managed by Pelagos in view {view}")
        if not isinstance(change.after, dict):
            raise PlanError("`after` must be a Zone object")
        raw = dict(change.after)
        raw["name"] = name
        raw["view"] = view
        secondary = raw.get("secondary") if isinstance(raw.get("secondary"), dict) else None
        if secondary and secondary.get("origin") not in (None, self.node_id):
            # A peer of the node that holds the new primary: the zone is its secondary here.
            raw = {
                "name": name,
                "view": view,
                "kind": ZoneKind.SECONDARY.value,
                "primaries": list(secondary.get("primaries") or []),
                "notes": raw.get("notes"),
            }
        zone = Zone.from_dict({k: v for k, v in raw.items() if k not in ("ns", "records", "secondary")})
        zone.source = ZoneSource.PELAGOS
        zone.config_path = str(path)
        if zone.kind in (ZoneKind.SECONDARY, ZoneKind.STUB, ZoneKind.MIRROR) and not zone.primaries:
            if zone.kind is not ZoneKind.MIRROR:
                raise PlanError(f"a {zone.kind.value} zone needs primaries")
        if zone.kind is ZoneKind.FORWARD and not zone.forwarders:
            raise PlanError("a forward zone needs forwarders")
        initial: dict[str, Any] = {}
        if op is ChangeOp.ADD and zone.kind is ZoneKind.PRIMARY:
            initial = self._new_zone_file(zone, raw)
        if zone.kind in (ZoneKind.SECONDARY, ZoneKind.MIRROR):
            # named writes the transferred zone there, so it must stay in a Pelagos directory.
            previous = before.get("file") if before else None
            if not zone.file or zone.file != previous:
                zone.file = str(self._zone_file_path(zone))
        statement = self.managed.zone_statement(zone)
        self.managed.upsert(doc, statement, "zone", name.rstrip(".") or ".", note_comment(zone.notes))
        after = zone.to_dict()
        after["config_path"] = str(path)
        # Kept so that apply on any node renders the same initial zone file.
        after.update(initial)
        if secondary:
            after["secondary"] = secondary  # every node renders its own side of the pair
        self.result.changes.append(
            Change(op, change.target, before=before, after=after, node_ids=change.node_ids)
        )

    def _check_zone_includes(self, view: str) -> None:
        pel = self.tree.pelagos
        if view == DEFAULT_VIEW:
            if pel.get("has_views"):
                raise PlanError("the configuration uses views: a zone needs a view")
            if not pel.get("include_line_present"):
                raise PlanError(f"{self.managed.pelagos_conf} is not included from {self.user_conf}")
        else:
            if view not in self.tree.views:
                raise PlanError(f"no view {view!r} in the configuration")
            if not pel.get("view_includes_present", {}).get(view):
                raise PlanError(f"view {view!r} does not include {self.managed.view_conf(view)}")

    def _directory(self) -> Path:
        directory = self.option("directory")
        return Path(unquote(directory)) if directory else self.user_conf.parent

    def _zone_file_path(self, zone: Zone) -> Path:
        """Absolute path of a zone file Pelagos or named writes: under zone_dir or `directory` only."""
        if zone.file:
            p = Path(zone.file)
            p = p if p.is_absolute() else self._directory() / p
        else:
            p = self.zone_dir / f"{zone.name.rstrip('.') or 'root'}.db"
        resolved = p.resolve()
        for root in (self.zone_dir, self._directory()):
            if resolved.is_relative_to(root.resolve()):
                return p
        raise PlanError(f"zone file {p} is outside {self.zone_dir} and the options directory")

    def _new_zone_file(self, zone: Zone, raw: dict[str, Any]) -> dict[str, Any]:
        """A primary zone gets an initial zone file (SOA, NS, optional records) unless one exists."""
        path = self._zone_file_path(zone)
        zone.file = zone.file or str(path)
        if path.exists() or path in self.result.texts:
            return {}
        ns = [normalize_name(n) for n in (raw.get("ns") or self.default_ns or ["localhost."])]
        records = [RRset.from_dict(r) if isinstance(r, dict) else r for r in raw.get("records") or []]
        for record in records:
            # Relative owners hang off the zone; anything outside the zone is refused.
            record.name = owner_name(record.name, zone.name)
        self._set_text(path, zone_file_text(zone.name, ns, records))
        self.result.zone_files[path] = self.result.texts[path]
        return {"ns": ns, "records": [r.to_dict() for r in records]}

    # Keys, ACLs, options -------------------------------------------------------

    def _user_entry(self, entries: list[Any], name: str) -> Any:
        for e in entries:
            if e.name == name and not e.managed:
                return e
        return None

    def key_change(self, change: Change, name: str) -> None:
        if self._user_entry(self.tree.keys, name) is not None:
            raise PlanError(f"key {name} is defined in a user file; Pelagos never edits it")
        doc = self.doc(self.managed.keys_conf)
        existing = {k.name: k for k in self.managed.keys(doc)}.get(name)
        before = existing.masked() if existing else None
        op = ChangeOp(change.op)
        if op is ChangeOp.DELETE:
            if existing is None:
                raise PlanError(f"key {name} is not managed by Pelagos")
            self.managed.remove(doc, "key", name)
            self.result.requires_confirmation = True
            self.result.changes.append(
                Change(op, change.target, before=before, after=None, node_ids=change.node_ids)
            )
            return
        if op is ChangeOp.ADD and existing is not None:
            raise PlanError(f"key {name} already exists; use replace to rotate it")
        if op is ChangeOp.REPLACE:
            if existing is None:
                raise PlanError(f"key {name} is not managed by Pelagos")
            self.result.requires_confirmation = True
        after = dict(change.after or {})
        algorithm = str(after.get("algorithm") or (existing.algorithm if existing else "hmac-sha256")).lower()
        if algorithm not in ALGORITHMS:
            raise PlanError(f"unsupported TSIG algorithm {algorithm}")
        secret = after.get("secret") or new_secret(algorithm)
        try:
            base64.b64decode(secret, validate=True)
        except ValueError as exc:
            raise PlanError("secret is not valid base64") from exc
        notes = after.get("notes", existing.notes if existing else None)
        spec = KeySpec(name=name, algorithm=algorithm, secret=secret, notes=notes)
        self.managed.upsert(doc, self.managed.key_statement(spec), "key", name, note_comment(notes))
        # The secret stays in `after` so every node writes the same key; callers mask it for display.
        self.result.changes.append(
            Change(
                op,
                change.target,
                before=before,
                after={"name": name, "algorithm": algorithm, "secret": secret, "notes": notes},
                node_ids=change.node_ids,
            )
        )

    def acl_change(self, change: Change, name: str) -> None:
        if self._user_entry(self.tree.acls, name) is not None:
            raise PlanError(f"acl {name} is defined in a user file; Pelagos never edits it")
        doc = self.doc(self.managed.acls_conf)
        existing = {a.name: a for a in self.managed.acls(doc)}.get(name)
        before = existing.to_dict() if existing else None
        op = ChangeOp(change.op)
        if op is ChangeOp.DELETE:
            if existing is None:
                raise PlanError(f"acl {name} is not managed by Pelagos")
            self.managed.remove(doc, "acl", name)
            self.result.changes.append(
                Change(op, change.target, before=before, after=None, node_ids=change.node_ids)
            )
            return
        if op is ChangeOp.ADD and existing is not None:
            raise PlanError(f"acl {name} already exists; use replace")
        if op is ChangeOp.REPLACE and existing is None:
            raise PlanError(f"acl {name} is not managed by Pelagos")
        after = dict(change.after or {})
        elements = [str(e).strip().rstrip(";").strip() for e in after.get("elements", []) if str(e).strip()]
        notes = after.get("notes", existing.notes if existing else None)
        spec = AclSpec(name=name, elements=elements, notes=notes)
        statement = self.managed.acl_statement(spec)
        parse_statements(statement)  # raises on unbalanced braces or quotes
        self.managed.upsert(doc, statement, "acl", name, note_comment(notes))
        self.result.changes.append(
            Change(op, change.target, before=before, after=spec.to_dict(), node_ids=change.node_ids)
        )

    def option_change(self, change: Change, name: str) -> None:
        if statement_info("options", name) is None:
            raise PlanError(f"{name} is not an options statement in the BIND grammar")
        if not self.tree.pelagos.get("options_include_present"):
            raise PlanError(f"{self.managed.options_conf} is not included from the options block")
        if self._user_entry(self.tree.options, name) is not None:
            raise PlanError(f"option {name} is set in a user file; Pelagos never edits it")
        doc = self.doc(self.managed.options_conf)
        existing = self.managed.find(doc, name, None)
        before = existing.value_text() if existing is not None else None
        op = ChangeOp(change.op)
        if op is ChangeOp.DELETE:
            if existing is None:
                raise PlanError(f"option {name} is not managed by Pelagos")
            self.managed.remove(doc, name, None)
            self.result.changes.append(
                Change(op, change.target, before=before, after=None, node_ids=change.node_ids)
            )
            return
        if op is ChangeOp.ADD and existing is not None:
            raise PlanError(f"option {name} is already managed; use replace")
        value = change.after.get("value") if isinstance(change.after, dict) else change.after
        if value is None:
            raise PlanError("`after` must be the option value")
        statement = self.managed.option_statement(name, str(value))
        node = self.managed.upsert(doc, statement, name, None, None)
        self.result.changes.append(
            Change(op, change.target, before=before, after=node.value_text(), node_ids=change.node_ids)
        )

    def raw_change(self, change: Change, name: str) -> None:
        path = self.managed.resolve(name)
        if path == self.managed.pelagos_conf.resolve():
            raise PlanError("pelagos.conf is generated; edit the files it includes")
        doc = self.doc(path)
        op = ChangeOp(change.op)
        source = change.before if op is ChangeOp.DELETE and change.before else change.after
        if not isinstance(source, str) or not source.strip():
            raise PlanError("raw changes carry the statement text")
        statements = parse_statements(source)
        if not statements:
            raise PlanError("no statement in the text")
        befores: list[str] = []
        for stmt in statements:
            arg0 = stmt.args[0] if stmt.args else None
            existing = self.managed.find(doc, stmt.name, arg0)
            if existing is not None:
                befores.append(mask_secrets(existing.serialize().strip()))
            if op is ChangeOp.DELETE:
                if existing is None:
                    raise PlanError(f"{stmt.name} {arg0 or ''} is not in {name}".strip())
                self.managed.remove(doc, stmt.name, arg0)
            elif op is ChangeOp.ADD and existing is not None:
                raise PlanError(f"{stmt.name} {arg0 or ''} already exists in {name}; use replace")
            elif op is ChangeOp.REPLACE and existing is None:
                raise PlanError(f"{stmt.name} {arg0 or ''} is not in {name}")
            else:
                self.managed.upsert(doc, stmt.serialize().strip(), stmt.name, arg0, None)
        if op in (ChangeOp.REPLACE, ChangeOp.DELETE) or befores:
            self.result.requires_confirmation = self.result.requires_confirmation or op is ChangeOp.DELETE
        after = None if op is ChangeOp.DELETE else source
        self.result.changes.append(
            Change(
                op, change.target, before="\n".join(befores) or None, after=after, node_ids=change.node_ids
            )
        )

    # Bootstrap -----------------------------------------------------------------------

    def include_setup(self, change: Change) -> None:
        """Create the managed files and add the include lines: the only edits made to user files."""
        views = list(self.tree.views)
        for path, text in self.managed.bootstrap_texts(views).items():
            if not path.exists() and path not in self.result.texts:
                self._set_text(path, text)
        for path, text in plan_include_lines(self.files, self.managed).items():
            self._set_text(Path(path), text)
        self.result.changes.append(
            Change(ChangeOp.ADD, change.target, before=None, after={"views": views}, node_ids=change.node_ids)
        )


def zone_file_text(zone: str, ns: list[str], records: list[RRset], serial: int | None = None) -> str:
    """Initial zone file: SOA with the first NS as primary name server, NS RRset, extra records."""
    from pelagos.domain.common import utcnow

    zone = normalize_name(zone)
    serial = serial or int(utcnow().strftime("%Y%m%d") + "01")
    lines = [
        "$TTL 3600",
        f"{zone} IN SOA {ns[0]} hostmaster.{zone if zone != '.' else ''} ( {serial} 3600 900 1209600 300 )",
    ]
    lines.extend(f"{zone} IN NS {n}" for n in ns)
    for rr in records:
        lines.extend(f"{owner_name(rr.name, zone)} {rr.ttl} IN {rr.rtype} {rd}" for rd in rr.rdata)
    return "\n".join(lines) + "\n"


def run_checkconf(binary: str | None, conf: Path, timeout: float = 30.0) -> ValidationResult:
    if not binary:
        return ValidationResult(ok=False, tool="named-checkconf", output="named-checkconf not found")
    try:
        proc = subprocess.run(
            [binary, str(conf)], capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return ValidationResult(ok=False, tool="named-checkconf", output="named-checkconf timed out")
    except OSError as exc:
        return ValidationResult(ok=False, tool="named-checkconf", output=str(exc))
    return ValidationResult(
        ok=proc.returncode == 0, tool="named-checkconf", output=(proc.stdout + proc.stderr).strip()
    )


def run_checkzone(binary: str | None, zone: str, text: str, timeout: float = 30.0) -> ValidationResult:
    if not binary:
        return ValidationResult(ok=False, tool="named-checkzone", output="named-checkzone not found")
    with tempfile.TemporaryDirectory(prefix="plg-zone-") as d:
        path = Path(d) / "zone.db"
        path.write_text(text)
        try:
            proc = subprocess.run(
                [binary, "-q", normalize_name(zone), str(path)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return ValidationResult(ok=False, tool="named-checkzone", output=str(exc))
    out = (proc.stdout + proc.stderr).strip()
    ok = proc.returncode == 0
    return ValidationResult(
        ok=ok, tool="named-checkzone", output=out or ("ok" if ok else "named-checkzone refused the zone")
    )


def validate_render(
    planner: ConfigPlanner, checkconf: str | None, checkzone: str | None
) -> list[ValidationResult]:
    """named-checkconf on a temp copy of the whole include chain with the new texts; zone files too."""
    result = planner.result
    out: list[ValidationResult] = []
    overrides = {p: t for p, t in result.texts.items() if p not in result.zone_files}
    with tempfile.TemporaryDirectory(prefix="plg-checkconf-") as d:
        try:
            conf = materialize(planner.files, Path(d), overrides)
        except (OSError, ParseError, KeyError) as exc:
            out.append(ValidationResult(ok=False, tool="parser", output=str(exc)))
            return out
        check = run_checkconf(checkconf, conf)
        check.output = check.output.replace(d + "/", "")
        out.append(check)
    for path, text in result.zone_files.items():
        zone = _zone_for_file(result, path)
        if zone:
            out.append(run_checkzone(checkzone, zone, text))
    return out


def _zone_for_file(result: RenderResult, path: Path) -> str | None:
    for change in result.changes:
        if isinstance(change.after, dict) and change.after.get("file") == str(path):
            return change.after.get("name")
    return None


def reparse_check(texts: dict[Path, str], zone_files: dict[Path, str]) -> list[str]:
    """Every rendered configuration file must parse again (a guard on the renderer itself)."""
    errors: list[str] = []
    for path, text in texts.items():
        if path in zone_files:
            continue
        try:
            parse(text, str(path))
        except ParseError as exc:
            errors.append(str(exc))
    return errors
