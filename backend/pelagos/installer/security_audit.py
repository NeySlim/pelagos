# SPDX-License-Identifier: Apache-2.0
"""Security audit of adopted configurations (GET /install/security, POST /install/security/plan).

Findings: hmac-md5/sha1 keys, allow-update by address, open allow-transfer or
recursion, rndc/statistics-channel/Kea HTTP off localhost, Kea sockets with
loose modes, dnssec-validation off. The Kea shared key rotation is one finding
whose steps switch both sides together (design section 9): add the new key to
BIND, switch D2 on every node, remove the old key. Each finding is one line of
the plan; nothing is applied unless the user selected it.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pelagos.domain import (
    Change,
    ChangeOp,
    Plan,
    PlanScope,
    PlanState,
    Precondition,
    PreconditionKind,
    Severity,
    messages,
    zone_updates,
)
from pelagos.domain.messages import Message, join, msg
from pelagos.installer import (
    bind_files,
    bindconf,
    bindsetup,
    drift,
    ha_guard,
    ha_listener,
    keaconf,
    keasetup,
    managed,
    zone_audit,
)
from pelagos.installer.bindconf import ConfigFiles, Statement
from pelagos.installer.jobs import Step

log = logging.getLogger(__name__)

WEAK_ALGORITHMS = frozenset({"hmac-md5", "hmac-md5.sig-alg.reg.int", "hmac-sha1"})
NEW_ALGORITHM = "hmac-sha256"
LOOPBACK = ("127.0.0.1", "::1", "localhost", "127.0.0.1/32", "::1/128")


@dataclass(slots=True)
class Finding:
    id: str
    kind: str
    severity: Severity
    engine: str
    subject: str
    description: str
    proposal: str
    risk: str
    details: dict[str, Any] = field(default_factory=dict)
    # Translatable forms of description, proposal and risk (domain.messages), by field name.
    messages: dict[str, Message] = field(default_factory=dict)

    @classmethod
    def of(
        cls,
        id: str,
        kind: str,
        severity: Severity,
        engine: str,
        subject: str,
        description: str | Message,
        proposal: str | Message,
        risk: str | Message,
        details: dict[str, Any] | None = None,
    ) -> Finding:
        """A finding whose texts may be messages: each one is rendered and kept for the UI."""
        texts: dict[str, str] = {}
        kept: dict[str, Message] = {}
        for name, value in (("description", description), ("proposal", proposal), ("risk", risk)):
            if isinstance(value, dict):
                kept[name] = value
                texts[name] = messages.render(value)
            else:
                texts[name] = value
        return cls(id, kind, severity, engine, subject, **texts, details=details or {}, messages=kept)

    def to_dict(self) -> dict[str, Any]:
        remediable = bool(self.details.get("remediable", True))
        manual = self.details.get("manual") if isinstance(self.details.get("manual"), dict) else None
        return {
            "id": self.id,
            "kind": self.kind,
            "severity": str(self.severity),
            "engine": self.engine,
            "subject": self.subject,
            "description": self.description,
            "proposal": self.proposal,
            "risk": self.risk,
            "remediable": remediable,
            # A firewall rule already keeps other hosts off what the finding exposes.
            "mitigated": bool(self.details.get("mitigated")),
            "description_message": self.messages.get("description"),
            "proposal_message": self.messages.get("proposal"),
            "risk_message": self.messages.get("risk"),
            # What the operator does by hand when no plan can fix it: a specific text, else the proposal.
            "manual_action": None if remediable else messages.render(manual) if manual else self.proposal,
            "manual_action_message": None if remediable else manual or self.messages.get("proposal"),
            # managed_drift: what differs and the plans offered (`<id>#adopt` or `<id>#restore`).
            **{k: self.details[k] for k in ("differences", "actions") if k in self.details},
        }


def finding_id(engine: str, kind: str, subject: str) -> str:
    return f"{engine}:{kind}:{subject}"


# Exceptions ([[exceptions]] of cluster.toml) on audit findings: kind EXCEPTION_KIND, key
# "<node>|<finding id>" for that node only or the bare finding id for every node.
EXCEPTION_KIND = "security_finding"


def exception_keys(node_id: str | None, fid: str) -> list[str]:
    """The keys an exception may name for finding `fid` of `node_id`, this node's first."""
    return [f"{node_id}|{fid}", fid] if node_id else [fid]


def mark_exceptions(
    findings: list[dict[str, Any]], node_id: str | None, exceptions: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Finding dicts with `node_id`, `exception_keys` and `exception` (the record that excepts the
    finding, else None); excepted findings stay listed so the exception remains visible and revocable."""
    records = {
        str(e["key"]): e
        for e in exceptions
        if isinstance(e, dict) and e.get("kind") == EXCEPTION_KIND and e.get("key") is not None
    }
    out = []
    for f in findings:
        keys = exception_keys(node_id, str(f.get("id")))
        found = next((records[k] for k in keys if k in records), None)
        out.append({**f, "node_id": node_id, "exception_keys": keys, "exception": found})
    return out


def _is_address(element: str) -> bool:
    e = element.lstrip("!").strip('"')
    try:
        ipaddress.ip_network(e, strict=False)
        return True
    except ValueError:
        return False


def _open(elements: list[str]) -> bool:
    return any(e.strip('"') == "any" for e in elements)


def _nonlocal_listener(lst: bindconf.Listener) -> bool:
    return not lst.local or any(
        e.strip('"') == "any" or (_is_address(e) and e.strip('"') not in LOOPBACK) for e in lst.allow
    )


# BIND ------------------------------------------------------------------------------------------


@dataclass(slots=True)
class BindAuditInput:
    """What the BIND audit reads: the user files (with paths and spans) and the rndc key in use."""

    files: ConfigFiles
    rndc_key: str | None = None  # key name the control channel uses
    rndc_key_file: str | None = None
    kea_keys: set[str] = field(default_factory=set)  # TSIG key names D2 uses
    query_address: str = "127.0.0.1"  # where Pelagos sends its queries
    query_refused: list[str] = field(default_factory=list)  # zones named refuses a SOA query for there
    rndc_key_statements: list[bindconf.KeyDef] = field(
        default_factory=list
    )  # from rndc.key when not included
    file_issues: list[bind_files.FileIssue] = field(default_factory=list)
    named_version: str | None = None


def _file_findings(issues: list[bind_files.FileIssue]) -> list[Finding]:
    """One finding per category of BIND files whose mode or owner is wrong."""
    findings: list[Finding] = []
    for category in bind_files.CATEGORIES:
        mine = [i for i in issues if i.category == category]
        if not mine:
            continue
        items = [
            msg(
                "finding.bind_file_mode.item",
                path=i.path,
                mode=f"{i.mode:04o}",
                owner=bind_files._user(i.uid),
                group=bind_files._group(i.gid),
                reasons=join(
                    [msg(f"finding.bind_file_mode.reason.{r}") for r in i.reasons],
                    ", ",
                ),
            )
            for i in mine
        ]
        findings.append(
            Finding.of(
                finding_id("bind", "bind_file_mode", category),
                "bind_file_mode",
                Severity.CRITICAL if any(i.critical for i in mine) else Severity.WARNING,
                "bind",
                category,
                msg(
                    "finding.bind_file_mode.description",
                    what=msg(f"finding.bind_file_mode.category.{category}"),
                    items=join(items, "; "),
                ),
                msg("finding.bind_file_mode.proposal", commands=join([i.command() for i in mine], "; ")),
                msg("finding.bind_file_mode.risk"),
                {"category": category, "files": [i.to_dict() for i in mine], "remediation": "file_modes"},
            )
        )
    return findings


def _version_finding(options: Statement | None, named_version: str | None) -> Finding | None:
    """version.bind (CHAOS TXT) answers the exact version unless the options set another string."""
    value = bindconf.option_value(options, "version") if options is not None else None
    if value:
        shown = value[0].strip('"')
        if not named_version or named_version.split("-")[0] not in shown:
            return None
    return Finding.of(
        finding_id("bind", "version_disclosed", "options"),
        "version_disclosed",
        Severity.WARNING,
        "bind",
        "options",
        msg("finding.version_disclosed.description", version=named_version or "?"),
        'version "none";',
        msg("finding.version_disclosed.risk"),
        {**(_locator(options) if options is not None else {}), "remediation": "version_hide"},
    )


def _locator(stmt: Statement) -> dict[str, Any]:
    return {"file": stmt.path, "line": stmt.line}


def audit_bind(inp: BindAuditInput) -> list[Finding]:
    files = inp.files
    top = list(files.top_level())
    findings: list[Finding] = []
    seen_keys: set[str] = set()
    key_defs = bindconf.keys(top) + [
        k for k in inp.rndc_key_statements if k.name not in {d.name for d in bindconf.keys(top)}
    ]
    for k in key_defs:
        if k.name in seen_keys or not k.weak:
            continue
        seen_keys.add(k.name)
        sev = Severity.CRITICAL if "md5" in k.algorithm else Severity.WARNING
        loc = _locator(k.stmt)
        if k.name == inp.rndc_key:
            findings.append(
                Finding.of(
                    finding_id("bind", "weak_rndc_key", k.name),
                    "weak_rndc_key",
                    sev,
                    "bind",
                    k.name,
                    msg("finding.weak_rndc_key.description", key=k.name, algorithm=k.algorithm),
                    msg("finding.weak_rndc_key.proposal", key=k.name, new_algorithm=NEW_ALGORITHM),
                    msg("finding.weak_rndc_key.risk"),
                    {"key": k.name, "algorithm": k.algorithm, **loc, "remediation": "rndc_key"},
                )
            )
        elif k.name in inp.kea_keys:
            findings.append(
                Finding.of(
                    finding_id("bind", "weak_shared_kea_key", k.name),
                    "weak_shared_kea_key",
                    sev,
                    "bind",
                    k.name,
                    msg("finding.weak_shared_kea_key.description", key=k.name, algorithm=k.algorithm),
                    msg(
                        "finding.weak_shared_kea_key.proposal",
                        new_key=f"{k.name}-sha256",
                        new_algorithm=NEW_ALGORITHM,
                    ),
                    msg("finding.weak_shared_kea_key.risk"),
                    {
                        "key": k.name,
                        "new_key": f"{k.name}-sha256",
                        "algorithm": k.algorithm,
                        **loc,
                        "remediation": "dual_key",
                    },
                )
            )
        else:
            findings.append(
                Finding.of(
                    finding_id("bind", "weak_tsig_key", k.name),
                    "weak_tsig_key",
                    sev,
                    "bind",
                    k.name,
                    msg("finding.weak_tsig_key.description", key=k.name, algorithm=k.algorithm),
                    msg("finding.weak_tsig_key.proposal", key=k.name, new_algorithm=NEW_ALGORITHM),
                    msg("finding.weak_tsig_key.risk"),
                    {"key": k.name, "algorithm": k.algorithm, **loc, "remediation": "tsig_key"},
                )
            )

    for z in bindconf.zones(top):
        allow_update = z.elements("allow-update")
        addresses = [e for e in allow_update if _is_address(e)]
        subject = f"{z.view}/{z.name}"
        if addresses:
            kea_key = bindsetup.kea_key_of_zone(z)
            findings.append(
                Finding.of(
                    finding_id("bind", "allow_update_by_address", subject),
                    "allow_update_by_address",
                    Severity.CRITICAL,
                    "bind",
                    subject,
                    msg("finding.allow_update_by_address.description", zone=z.name, addresses=addresses),
                    msg(
                        "finding.allow_update_by_address.proposal",
                        policy=bindsetup.update_policy_proposal(z, kea_key),
                    ),
                    msg("finding.allow_update_by_address.risk"),
                    {
                        "zone": z.name,
                        "view": z.view,
                        "kea_key": kea_key,
                        **_locator(z.stmt),
                        "remediation": "update_policy",
                    },
                )
            )
        xfr = z.elements("allow-transfer")
        if _open(xfr):
            findings.append(_open_transfer(subject, z.stmt, xfr, zone=z.name, view=z.view))

    options = bindsetup.find_options(files)
    if options is not None:
        xfr = bindconf.option_value(options, "allow-transfer") or []
        if _open(xfr):
            findings.append(_open_transfer("options", options, xfr))
        recursion = bindconf.option_value(options, "recursion")
        recursive = recursion is None or recursion[0].strip('"') in ("yes", "true", "1")
        allow_rec = bindconf.option_value(options, "allow-recursion")
        allow_cache = bindconf.option_value(options, "allow-query-cache")
        open_rec = (allow_rec is not None and _open(allow_rec)) or (
            allow_rec is None and allow_cache is not None and _open(allow_cache)
        )
        if recursive and open_rec:
            findings.append(
                Finding.of(
                    finding_id("bind", "open_recursion", "options"),
                    "open_recursion",
                    Severity.CRITICAL,
                    "bind",
                    "options",
                    msg("finding.open_recursion.description"),
                    msg(
                        "finding.open_recursion.proposal",
                        statement="allow-recursion { localhost; localnets; };",
                    ),
                    msg("finding.open_recursion.risk"),
                    {
                        **_locator(options),
                        "statement": "allow-recursion" if allow_rec is not None else "allow-query-cache",
                        "remediation": "recursion",
                    },
                )
            )
        dv = bindconf.option_value(options, "dnssec-validation")
        if dv is not None and dv and dv[0].strip('"') in ("no", "false", "0"):
            findings.append(
                Finding.of(
                    finding_id("bind", "dnssec_validation_off", "options"),
                    "dnssec_validation_off",
                    Severity.WARNING,
                    "bind",
                    "options",
                    msg("finding.dnssec_validation_off.description"),
                    "dnssec-validation auto;",
                    msg("finding.dnssec_validation_off.risk"),
                    {**_locator(options), "remediation": "dnssec_validation"},
                )
            )

    findings += _pelagos_access(files, top, {k.name for k in key_defs})
    findings += zone_audit.findings(files, top, {k.name for k in key_defs})
    findings += _file_findings(inp.file_issues)
    if options is not None and (version := _version_finding(options, inp.named_version)):
        findings.append(version)
    if inp.query_refused:
        zones = sorted(inp.query_refused)
        findings.append(
            Finding.of(
                finding_id("bind", "query_refused", inp.query_address),
                "query_refused",
                Severity.WARNING,
                "bind",
                inp.query_address,
                msg("finding.query_refused.description", address=inp.query_address, zones=join(zones, ", ")),
                msg("finding.query_refused.proposal", address=inp.query_address, zones=join(zones, ", ")),
                msg("finding.query_refused.risk"),
                {"zones": zones, "address": inp.query_address, "remediable": False},
            )
        )

    for stmt in (s for s in top if s.name == "controls"):
        for lst in bindconf.inet_listeners(stmt):
            if _nonlocal_listener(lst):
                findings.append(
                    Finding.of(
                        finding_id("bind", "rndc_nonlocal", lst.address),
                        "rndc_nonlocal",
                        Severity.CRITICAL,
                        "bind",
                        f"controls inet {lst.address}",
                        msg(
                            "finding.rndc_nonlocal.description",
                            address=lst.address,
                            allowed=list(lst.allow) or msg("finding.allowed.nothing"),
                        ),
                        "controls { inet 127.0.0.1 port "
                        f"{lst.port or 953} allow {{ 127.0.0.1; }} "
                        f"keys {{ {', '.join(lst.keys) or 'rndc-key'}; }}; }};",
                        msg("finding.rndc_nonlocal.risk"),
                        {
                            **_locator(stmt),
                            "port": lst.port or 953,
                            "keys": lst.keys,
                            "remediation": "controls",
                        },
                    )
                )
                break
    for stmt in (s for s in top if s.name == "statistics-channels"):
        for lst in bindconf.inet_listeners(stmt):
            # A channel bound to loopback is unreachable from outside whatever its allow list says.
            if not lst.local:
                findings.append(
                    Finding.of(
                        finding_id("bind", "stats_nonlocal", lst.address),
                        "stats_nonlocal",
                        Severity.WARNING,
                        "bind",
                        f"statistics-channels inet {lst.address}",
                        msg(
                            "finding.stats_nonlocal.description",
                            address=lst.address,
                            allowed=list(lst.allow) or msg("finding.allowed.all"),
                        ),
                        f"statistics-channels {{ inet 127.0.0.1 port {lst.port or 80} "
                        "allow { 127.0.0.1; }; };",
                        msg("finding.stats_nonlocal.risk"),
                        {**_locator(stmt), "port": lst.port or 80, "remediation": "stats"},
                    )
                )
                break
    return findings


def _unquoted(elements: list[str]) -> list[str]:
    return [e.replace('"', "") for e in elements]


def _grants_key(zone: bindconf.ZoneDef, key: str) -> bool:
    if f"key {key}" in _unquoted(zone.elements("allow-update")):
        return True
    rules = _unquoted(zone.elements("update-policy"))
    return any(r.startswith("grant ") and r.split()[1:2] == [key] for r in rules)


COPY_KINDS = ("secondary", "slave", "mirror")


def _update_key_finding(subject: str, z: bindconf.ZoneDef, key: str, top: list[Statement]) -> Finding:
    """Pelagos signs its UPDATEs with `key`: add it where the zone's update rules live, keys kept."""
    inherits = False
    if z.stmt.sub("update-policy") is not None:
        where = msg("finding.update_without_admin_key.where_policy")
    elif z.stmt.sub("allow-update") is not None:
        where = msg("finding.update_without_admin_key.where_allow_update")
    else:
        inherits = True
        inherited = zone_audit.inherited_allow_update(top, z.view)
        where = (
            msg(
                "finding.update_without_admin_key.where_inherited_at",
                location=f"{inherited.path}:{inherited.line}",
            )
            if inherited
            else msg("finding.update_without_admin_key.where_inherited")
        )
    return Finding.of(
        finding_id("bind", "update_without_admin_key", subject),
        "update_without_admin_key",
        Severity.WARNING,
        "bind",
        subject,
        msg("finding.update_without_admin_key.description", zone=z.name, key=key),
        msg("finding.update_without_admin_key.proposal", key=key, where=where),
        msg(
            "finding.update_without_admin_key.risk_inherited"
            if inherits
            else "finding.update_without_admin_key.risk"
        ),
        {"zone": z.name, "view": z.view, "key": key, **_locator(z.stmt), "remediation": "update_key_add"},
    )


def _grants_effective(z: bindconf.ZoneDef, key: str, top: list[Statement]) -> bool:
    if _grants_key(z, key):
        return True
    if z.stmt.sub("update-policy") is not None or z.stmt.sub("allow-update") is not None:
        return False
    return f"key {key}" in _unquoted(zone_audit.update_rules(z, top) or [])


def _narrow_grant(z: bindconf.ZoneDef, key: str) -> tuple[Statement, list[str]] | None:
    """The first `zonesub` grant of `key` and the editable types its grants leave out, if any."""
    pol = z.stmt.sub("update-policy")
    if pol is None or pol.block is None:
        return None
    first: Statement | None = None
    granted: set[str] = set()
    for rule in pol.block.statements:
        words = [w.strip('"') for w in rule.words]
        if rule.name != "grant" or words[:2] != [key, "zonesub"]:
            continue
        types = {w.upper() for w in words[2:]}
        if not types or "ANY" in types:
            return None
        first = first or rule
        granted |= types
    missing = [t for t in UPDATE_TYPES_ADMIN if t not in granted]
    return (first, missing) if first is not None and missing else None


def _narrow_grant_finding(subject: str, z: bindconf.ZoneDef, key: str) -> Finding | None:
    """A grant older than the editor's type list: writing the missing types would be REFUSED."""
    narrow = _narrow_grant(z, key)
    if narrow is None:
        return None
    _rule, missing = narrow
    return Finding.of(
        finding_id("bind", "update_types_narrow", subject),
        "update_types_narrow",
        Severity.WARNING,
        "bind",
        subject,
        msg("finding.update_types_narrow.description", zone=z.name, key=key, types=" ".join(missing)),
        msg("finding.update_types_narrow.proposal", key=key, types=" ".join(missing)),
        msg("finding.update_types_narrow.risk"),
        {"zone": z.name, "view": z.view, "key": key, **_locator(z.stmt), "remediation": "update_types_widen"},
    )


def _pelagos_access(files: ConfigFiles, top: list[Statement], key_names: set[str]) -> list[Finding]:
    """Once adopted, Pelagos reads zones by AXFR with ddi-read and writes them by UPDATE with ddi-admin
    (with several views, the view's own key does both): zones whose transfer or update rules leave the
    key out get a finding that adds it."""
    findings: list[Finding] = []
    read_key, admin_key = managed.READ_KEY, managed.ADMIN_KEY
    options_needed = False
    multi_view = len(zone_audit.views(top)) >= 2
    for z in bindconf.zones(top):
        subject = f"{z.view}/{z.name}"
        dynamic = z.is_primary and zone_audit.takes_updates(z, top)
        static = zone_audit.is_static(z, top) and z.name not in zone_audit.BUILTIN_ZONES
        if multi_view:
            # Until the view has its key (finding view_key), nothing reaches its zones reliably.
            key = zone_audit.view_key_of(top, z.view.strip('"'))
            if key is None or key not in key_names:
                continue
            if dynamic and not _grants_effective(z, key, top):
                findings.append(_update_key_finding(subject, z, key, top))
            elif dynamic and (narrow := _narrow_grant_finding(subject, z, key)):
                findings.append(narrow)
            xfr_stmt = z.stmt.sub("allow-transfer")
            if (dynamic or static or z.kind in COPY_KINDS) and xfr_stmt is not None:
                xfr = z.elements("allow-transfer")
                if not _open(xfr) and f"key {key}" not in _unquoted(xfr):
                    findings.append(
                        _transfer_without_key(subject, xfr_stmt, xfr, zone=z.name, view=z.view, key=key)
                    )
            continue
        if admin_key in key_names and dynamic:
            by_address = any(_is_address(e) for e in z.elements("allow-update"))
            own_rules = z.stmt.sub("update-policy") is not None or z.stmt.sub("allow-update") is not None
            if not own_rules and not _grants_effective(z, admin_key, top):
                findings.append(_update_key_finding(subject, z, admin_key, top))
            elif narrow := _narrow_grant_finding(subject, z, admin_key):
                findings.append(narrow)
            elif own_rules and not by_address and not _grants_key(z, admin_key):
                au = z.stmt.sub("allow-update") is not None
                proposal = (
                    msg(
                        "finding.update_without_admin_key.proposal_replace",
                        policy=bindsetup.update_policy_proposal(z, bindsetup.kea_key_of_zone(z)),
                    )
                    if au
                    else msg(
                        "finding.update_without_admin_key.proposal_grant",
                        statement=f"grant {admin_key} zonesub {' '.join(UPDATE_TYPES_ADMIN)};",
                    )
                )
                findings.append(
                    Finding.of(
                        finding_id("bind", "update_without_admin_key", subject),
                        "update_without_admin_key",
                        Severity.WARNING,
                        "bind",
                        subject,
                        msg("finding.update_without_admin_key.description", zone=z.name, key=admin_key),
                        proposal,
                        msg("finding.update_without_admin_key.risk"),
                        {
                            "zone": z.name,
                            "view": z.view,
                            **_locator(z.stmt),
                            "remediation": "update_policy" if au else "update_policy_grant",
                        },
                    )
                )
        # Static primaries are read and edited through their file; the distribution's own zones
        # (localhost and the like) are left alone.
        if read_key not in key_names or not (dynamic or static or z.kind in COPY_KINDS):
            continue
        xfr_stmt = z.stmt.sub("allow-transfer")
        if xfr_stmt is None:
            options_needed = True
            continue
        xfr = z.elements("allow-transfer")
        if not _open(xfr) and f"key {read_key}" not in _unquoted(xfr):
            findings.append(_transfer_without_key(subject, xfr_stmt, xfr, zone=z.name, view=z.view))
    options = bindsetup.find_options(files)
    if options_needed and options is not None:
        xfr_stmt = options.sub("allow-transfer")
        xfr = bindconf.option_value(options, "allow-transfer") or []
        if xfr_stmt is None:
            # BIND refuses transfers by default: the options block gets an allow-transfer for ddi-read.
            findings.append(_transfer_without_key("options", options, [], add=True))
        elif not _open(xfr) and f"key {read_key}" not in _unquoted(xfr):
            findings.append(_transfer_without_key("options", xfr_stmt, xfr))
    return findings


UPDATE_TYPES_ADMIN = zone_updates.ADMIN_UPDATE_TYPES


def _transfer_without_key(
    subject: str,
    stmt: Statement,
    elements: list[str],
    zone: str | None = None,
    view: str | None = None,
    add: bool = False,
    key: str = managed.READ_KEY,
) -> Finding:
    proposal = "allow-transfer { " + " ".join(f"{e};" for e in [f"key {key}", *elements]) + " };"
    where = (
        msg("finding.transfer_without_read_key.where_zone", zone=zone)
        if zone
        else msg("finding.transfer_without_read_key.where_options")
    )
    return Finding.of(
        finding_id("bind", "transfer_without_read_key", subject),
        "transfer_without_read_key",
        Severity.WARNING,
        "bind",
        subject,
        msg("finding.transfer_without_read_key.description", where=where, key=key),
        proposal if not add else msg("finding.transfer_without_read_key.proposal_add", statement=proposal),
        msg("finding.transfer_without_read_key.risk"),
        {
            "zone": zone,
            "view": view,
            **_locator(stmt),
            "key": key,
            "remediation": "allow_transfer_add" if add else "allow_transfer",
        },
    )


def _open_transfer(
    subject: str, stmt: Statement, elements: list[str], zone: str | None = None, view: str | None = None
) -> Finding:
    kept = [e for e in elements if e.strip('"') != "any"]
    proposal = "allow-transfer { " + " ".join(f"{e};" for e in [f"key {managed.READ_KEY}", *kept]) + " };"
    return Finding.of(
        finding_id("bind", "open_allow_transfer", subject),
        "open_allow_transfer",
        Severity.WARNING,
        "bind",
        subject,
        msg("finding.open_allow_transfer.description_zone", zone=zone)
        if zone
        else msg("finding.open_allow_transfer.description_options"),
        proposal,
        msg("finding.open_allow_transfer.risk"),
        {"zone": zone, "view": view, **_locator(stmt), "remediation": "allow_transfer"},
    )


# Kea -------------------------------------------------------------------------------------------


@dataclass(slots=True)
class KeaAuditInput:
    configs: dict[str, dict[str, Any]]  # engine -> parsed config (kea4, kea6, d2)
    versions: dict[str, str | None] = field(default_factory=dict)
    ctrl_agent: dict[str, Any] | None = None  # parsed kea-ctrl-agent.conf when the agent is enabled
    ctrl_agent_unit: str | None = None
    socket_dir: str | None = None
    socket_dir_mode: int | None = None
    bind_keys: set[str] = field(default_factory=set)
    firewall: ha_listener.Firewall | None = None  # read only when an HA listener is off loopback
    nft: bool = False  # nft is installed: the guard of the HA listener can be set up


def _ha_findings(inp: KeaAuditInput) -> list[Finding]:
    """HA listeners off loopback that take a client without a certificate (kea_ha_listener_open)."""
    findings: list[Finding] = []
    fw = inp.firewall or ha_listener.Firewall()
    for engine, cfg in inp.configs.items():
        version = inp.versions.get(engine)
        for lst in ha_listener.listeners(engine, cfg, version):
            if not lst.open:
                continue
            guard = fw.guard(lst.port)
            can_restrict = ha_listener.supports_restrict(version)
            needs_restrict = can_restrict and not lst.restrict_commands
            remediable = needs_restrict or (guard is None and inp.nft)
            exposure = (
                "finding.kea_ha_listener_open.tls_optional"
                if lst.tls
                else "finding.kea_ha_listener_open.restricted"
                if lst.restrict_commands
                else "finding.kea_ha_listener_open.unrestricted"
            )
            params = {"engine": engine, "address": lst.address}
            description = (
                msg(
                    "finding.kea_ha_listener_open.description_mitigated",
                    **params,
                    exposure=msg(exposure),
                    guard=guard.source,
                    allowed=join(guard.allowed or ["?"], ", "),
                )
                if guard
                else msg("finding.kea_ha_listener_open.description", **params, exposure=msg(exposure))
            )
            peers = join(lst.peers or ["?"], ", ")
            steps = []
            if needs_restrict:
                steps.append(msg("finding.kea_ha_listener_open.step_restrict"))
            if guard is None:
                steps.append(
                    msg("finding.kea_ha_listener_open.step_guard", peers=peers, port=lst.port)
                    if inp.nft
                    else msg("finding.kea_ha_listener_open.step_guard_manual", peers=peers, port=lst.port)
                )
            tls = msg("finding.kea_ha_listener_open.manual_tls", engine=engine)
            by_hand = [s for s in steps if s["key"].endswith("step_guard_manual")] + [tls]
            findings.append(
                Finding.of(
                    finding_id("kea", "kea_ha_listener_open", f"{engine}:{lst.address}"),
                    "kea_ha_listener_open",
                    Severity.WARNING if guard else Severity.CRITICAL,
                    "kea",
                    f"{engine} HA {lst.server} {lst.address}",
                    description,
                    msg("finding.kea_ha_listener_open.proposal", steps=join([*steps, tls], " ")),
                    msg("finding.kea_ha_listener_open.risk"),
                    {
                        "engine": engine,
                        "server": lst.server,
                        "address": lst.host,
                        "port": lst.port,
                        "peers": lst.peers,
                        "tls": lst.tls,
                        "restrict_commands": lst.restrict_commands,
                        "mitigated": guard is not None,
                        "guard": guard.source if guard else None,
                        "guard_allowed": guard.allowed if guard else [],
                        "kea_version": version,
                        "remediable": remediable,
                        "manual": by_hand[0]
                        if len(by_hand) == 1
                        else msg("finding.kea_ha_listener_open.proposal", steps=join(by_hand, " ")),
                        "remediation": "ha_listener",
                    },
                )
            )
    return findings


def audit_kea(inp: KeaAuditInput) -> list[Finding]:
    findings: list[Finding] = _ha_findings(inp)
    if inp.ctrl_agent is not None:
        for lst in keaconf.http_listeners(inp.ctrl_agent):
            plain = lst["socket-type"] == "http"
            if not plain:
                continue
            host = str(lst.get("socket-address"))
            local = host in LOOPBACK
            findings.append(
                Finding.of(
                    finding_id("kea", "kea_ctrl_agent_http", f"{host}:{lst.get('socket-port')}"),
                    "kea_ctrl_agent_http",
                    Severity.WARNING if local else Severity.CRITICAL,
                    "kea",
                    f"kea-ctrl-agent {host}:{lst.get('socket-port')}",
                    msg(
                        "finding.kea_ctrl_agent_http.description"
                        if lst.get("authentication")
                        else "finding.kea_ctrl_agent_http.description_noauth",
                        address=f"{host}:{lst.get('socket-port')}",
                    ),
                    msg("finding.kea_ctrl_agent_http.proposal"),
                    msg("finding.kea_ctrl_agent_http.risk"),
                    {"unit": inp.ctrl_agent_unit, "remediation": "ctrl_agent"},
                )
            )
    for engine, cfg in inp.configs.items():
        try:
            listeners = keaconf.http_listeners(cfg)
        except keaconf.KeaConfigError:
            continue
        for lst in listeners:
            if (
                lst.get("socket-type") == "http"
                and str(lst.get("socket-address", "127.0.0.1")) not in LOOPBACK
            ):
                findings.append(
                    Finding.of(
                        finding_id("kea", "kea_http_socket_plain", f"{engine}:{lst.get('socket-address')}"),
                        "kea_http_socket_plain",
                        Severity.CRITICAL,
                        "kea",
                        f"{engine} http {lst.get('socket-address')}:{lst.get('socket-port')}",
                        msg(
                            "finding.kea_http_socket_plain.description",
                            engine=engine,
                            address=str(lst.get("socket-address")),
                        ),
                        msg("finding.kea_http_socket_plain.proposal"),
                        msg("finding.kea_http_socket_plain.risk"),
                        {"engine": engine, "remediable": False},
                    )
                )
    if inp.socket_dir_mode is not None and inp.socket_dir_mode & 0o027:
        findings.append(
            Finding.of(
                finding_id("kea", "kea_socket_dir_mode", str(inp.socket_dir)),
                "kea_socket_dir_mode",
                Severity.WARNING,
                "kea",
                str(inp.socket_dir),
                msg(
                    "finding.kea_socket_dir_mode.description",
                    path=str(inp.socket_dir),
                    mode=oct(inp.socket_dir_mode),
                ),
                f"chmod 0750 {inp.socket_dir}",
                msg("finding.kea_socket_dir_mode.risk"),
                {"path": inp.socket_dir, "remediation": "socket_dir"},
            )
        )
    d2 = inp.configs.get("d2")
    if d2 is not None:
        for key in keaconf.tsig_keys(d2):
            name = str(key.get("name", ""))
            alg = str(key.get("algorithm", "")).lower()
            if alg in keaconf.WEAK_TSIG and name not in inp.bind_keys:
                # The BIND side is not on this node: still a dual-key switch, D2 half only.
                findings.append(
                    Finding.of(
                        finding_id("kea", "weak_shared_kea_key", name),
                        "weak_shared_kea_key",
                        Severity.CRITICAL if "md5" in alg else Severity.WARNING,
                        "kea",
                        name,
                        msg("finding.weak_shared_kea_key.d2_description", key=name, algorithm=alg),
                        msg("finding.weak_shared_kea_key.d2_proposal", new_key=f"{name}-sha256"),
                        msg("finding.weak_shared_kea_key.risk"),
                        {
                            "key": name,
                            "new_key": f"{name}-sha256",
                            "algorithm": alg,
                            "remediation": "dual_key",
                        },
                    )
                )
            if "secret" in key and keaconf.supports_secret_file(inp.versions.get("d2")):
                findings.append(
                    Finding.of(
                        finding_id("kea", "kea_tsig_clear_secret", name),
                        "kea_tsig_clear_secret",
                        Severity.INFO,
                        "kea",
                        name,
                        msg("finding.kea_tsig_clear_secret.description", key=name),
                        msg("finding.kea_tsig_clear_secret.proposal"),
                        msg("finding.kea_tsig_clear_secret.risk"),
                        {"key": name, "remediation": "secret_file"},
                    )
                )
    return findings


# Collection on the local node ----------------------------------------------------------------


def collect_bind(env: Any) -> BindAuditInput | None:
    paths = env.paths
    if not paths.named_conf.exists():
        return None
    files = bindconf.load_files(paths.named_conf)
    controls = bindsetup.controls_info(files, paths.rndc_key)
    rndc_stmts: list[bindconf.KeyDef] = []
    kf = controls.get("key_file")
    if kf and kf not in files.statements:
        try:
            rndc_stmts = bindconf.keys(bindconf.parse(Path(kf).read_text(), kf))
        except (OSError, bindconf.ParseError):
            rndc_stmts = []
    address, refused = _probe_query_access(env, files)
    extra_keys = [p for p in (kf, str(env.paths.rndc_conf_pelagos), str(env.paths.keys_conf)) if p]
    return BindAuditInput(
        files=files,
        rndc_key=controls.get("key"),
        rndc_key_file=kf,
        rndc_key_statements=rndc_stmts,
        query_address=address,
        query_refused=refused,
        file_issues=bind_files.issues(env, bind_files.paths_by_category(env, files, extra_keys)),
        named_version=env.t.named_version(),
    )


def _probe_query_access(env: Any, files: bindconf.ConfigFiles) -> tuple[str, list[str]]:
    """The query address Pelagos uses (same [engines.bind] source as the collector, local named
    included) and the zones named refuses a SOA query for from it."""
    table = env.bind_table() or {}
    address = str(table.get("query_address") or "127.0.0.1")
    port = int(table.get("query_port") or 53)
    zones = bindsetup.served_zones(files)
    if not zones or not bindsetup.named_running(env):
        return address, []
    return address, bindsetup.refused_zones(env, address, zones, port)


def collect_kea(env: Any) -> KeaAuditInput | None:
    paths = env.paths
    configs: dict[str, dict[str, Any]] = {}
    versions: dict[str, str | None] = {}
    for engine, daemon in keasetup.DAEMONS.items():
        conf = paths.kea_conf(daemon)
        try:
            configs[engine] = keaconf.loads(conf.read_text(), str(conf))
        except (OSError, keaconf.KeaConfigError):
            continue
        versions[engine] = env.t.kea_version(daemon)
    agent = None
    agent_unit = None
    agent_conf = paths.kea_conf("kea-ctrl-agent")
    for unit in ("isc-kea-ctrl-agent.service", "kea-ctrl-agent.service"):
        if env.services.exists(unit) and (env.services.is_enabled(unit) or env.services.is_active(unit)):
            agent_unit = unit
            try:
                agent = keaconf.loads(agent_conf.read_text(), str(agent_conf))
            except (OSError, keaconf.KeaConfigError):
                agent = None
            break
    mode = None
    try:
        mode = stat.S_IMODE(os.stat(paths.kea_socket_dir).st_mode)
    except OSError:
        pass
    if not configs and agent is None:
        return None
    exposed = any(
        lst.open
        for engine, cfg in configs.items()
        for lst in ha_listener.listeners(engine, cfg, versions[engine])
    )
    return KeaAuditInput(
        configs=configs,
        versions=versions,
        ctrl_agent=agent,
        ctrl_agent_unit=agent_unit,
        socket_dir=str(paths.kea_socket_dir),
        socket_dir_mode=mode,
        firewall=ha_listener.read_firewall(env) if exposed else None,
        nft=env.binary("nft") is not None,
    )


def run_audit(env: Any) -> list[Finding]:
    """Every finding on this node, BIND and Kea; a D2 key also defined in local BIND is reported once."""
    bind_in = collect_bind(env)
    kea_in = collect_kea(env)
    d2_keys = (
        {str(k.get("name")) for k in keaconf.tsig_keys(kea_in.configs.get("d2", {}))} if kea_in else set()
    )
    findings: list[Finding] = []
    bind_keys: set[str] = set()
    if bind_in is not None:
        bind_in.kea_keys = d2_keys | {"kea-ddns"}
        bind_keys = {k.name for k in bindconf.keys(list(bind_in.files.top_level()))}
        findings += audit_bind(bind_in)
        if env.remote_bind() is not None:
            # Pelagos reaches this named over the network: moving rndc or the statistics channel to
            # 127.0.0.1 would cut it off, so these listeners are restricted by hand.
            for f in findings:
                if f.kind in ("rndc_nonlocal", "stats_nonlocal"):
                    f.details["remediable"] = False
                    f.details["manual"] = msg("finding.manual.remote_listener", subject=f.subject)
    if kea_in is not None:
        kea_in.bind_keys = bind_keys
        findings += audit_kea(kea_in)
    try:
        findings += drift.audit(env)
    except Exception as exc:  # drift checks never hide the security findings
        log.warning("drift checks not run: %s", exc)
    return findings


# Plan ------------------------------------------------------------------------------------------


def build_security_plan(
    env: Any, finding_ids: list[str], created_by: str = "", d2_node_ids: list[str] | None = None
) -> Plan:
    """One Change per selected finding; the dual-key switch expands into its three ordered changes."""
    findings = {f.id: f for f in run_audit(env)}
    choices: dict[str, str] = {}
    for i, raw in enumerate(finding_ids):
        base, action = drift.split_choice(raw)
        if action:
            finding_ids[i] = base
            choices[base] = action
    finding_ids = list(dict.fromkeys(finding_ids))
    unknown = [i for i in finding_ids if i not in findings]
    if unknown:
        raise ValueError(f"unknown finding id(s): {', '.join(unknown)}")
    local = [env.node_id]
    if d2_node_ids is not None:
        d2_nodes = list(d2_node_ids)
    else:
        d2_nodes = local if env.paths.kea_conf("kea-dhcp-ddns").exists() else []
    changes: list[Change] = []
    preconditions: list[Precondition] = []
    files_seen: set[str] = set()
    # A view key comes first: the grants and transfers of that view's zones use it.
    finding_ids = sorted(finding_ids, key=lambda i: findings[i].kind != "view_key")
    for fid in finding_ids:
        f = findings[fid]
        if not f.details.get("remediable", True):
            raise ValueError(f"{fid} has no automatic remediation; follow its proposal by hand")
        payload = {"finding": f.to_dict(), "details": f.details}
        if f.kind == drift.KIND:
            action = choices.get(fid, "restore")
            if action not in f.details.get("actions", []):
                raise ValueError(f"{fid}: {action} is not offered for this object")
            payload["details"] = {**f.details, "action": action}
        if f.kind == "weak_shared_kea_key":
            new = f.details["new_key"]
            bind_nodes = local if f.engine == "bind" else []
            # Removing the old key on this node is only safe once every D2 has switched: without a
            # known D2 node set, step 3 is left to the operator like the steps of other nodes.
            remove_nodes = bind_nodes if d2_nodes else []
            steps = [
                (
                    "1-bind-add",
                    f"add key {new} ({NEW_ALGORITHM}) and grant it next to {f.subject}",
                    bind_nodes,
                ),
                ("2-d2-switch", f"switch D2 from {f.subject} to {new}", d2_nodes),
                (
                    "3-bind-remove",
                    f"remove {f.subject} from update rules and the configuration",
                    remove_nodes,
                ),
            ]
            for suffix, what, nodes in steps:
                changes.append(
                    Change(
                        ChangeOp.REPLACE,
                        f"security/{fid}/{suffix}",
                        before={"key": f.subject, "algorithm": f.details.get("algorithm")},
                        after={
                            **payload,
                            "step": suffix,
                            "summary": what if nodes else f"manual, on the node that runs it: {what}",
                            "manual": not nodes,
                        },
                        node_ids=list(nodes),
                    )
                )
        else:
            changes.append(
                Change(
                    ChangeOp.REPLACE,
                    f"security/{fid}",
                    before={"description": f.description},
                    after={
                        **payload,
                        "summary": f"{payload['details']['action']} {f.subject}"
                        if f.kind == drift.KIND
                        else f.proposal,
                    },
                    node_ids=[env.node_id],
                )
            )
        path = f.details.get("file")
        if path and path not in files_seen and Path(path).exists():
            files_seen.add(path)
            from pelagos.core.write_pipeline import sha256_file

            preconditions.append(
                Precondition(PreconditionKind.FILE_SHA256, path, sha256_file(Path(path)), env.node_id)
            )
    diff = "\n".join(f"~ {c.target}: {c.after['summary']}" for c in changes)
    return Plan(
        scope=PlanScope.SECURITY,
        node_id=env.node_id,
        summary=messages.render(msg("plan.security", count=len(finding_ids))),
        summary_message=msg("plan.security", count=len(finding_ids)),
        created_by=created_by,
        changes=changes,
        diff=diff,
        preconditions=preconditions,
        target_node_ids=sorted({n for c in changes for n in c.node_ids}),
        requires_confirmation=True,
        state=PlanState.VALIDATED,
    )


def plan_remediation(findings: list[Finding], created_by: str, node_ids: list[str]) -> Plan:
    """Compatibility entry point: plan for already collected findings on the local node."""
    from pelagos.installer.env import InstallerEnv

    env = InstallerEnv.detect()
    return build_security_plan(env, [f.id for f in findings], created_by, d2_node_ids=node_ids or None)


def run_remediation(plan: Plan, job: Any, progress: Any) -> Any:
    """Job runner for security plans (POST /plans/{id}/apply)."""
    from pelagos.installer.env import InstallerEnv
    from pelagos.installer.jobs import apply_plan

    return apply_plan(plan, InstallerEnv.detect(node_id=plan.node_id), job, progress)


# Remediation -----------------------------------------------------------------------------------


def _reload_files(env: Any) -> ConfigFiles:
    return bindconf.load_files(env.paths.named_conf)


def _find_key(
    files: ConfigFiles, name: str, extra_files: list[str] = ()
) -> tuple[str, bindconf.KeyDef] | None:
    for path in [*files.order, *[p for p in extra_files if p not in files.order]]:
        stmts = files.statements.get(path)
        if stmts is None:
            try:
                stmts = bindconf.parse(Path(path).read_text(), path)
            except (OSError, bindconf.ParseError):
                continue
        for k in bindconf.keys(stmts):
            if k.name == name:
                return path, k
    return None


def _file_text(files: ConfigFiles, path: str) -> str:
    return files.texts[path] if path in files.texts else Path(path).read_text()


def _replace_key_text(text: str, key: bindconf.KeyDef, secret: str, name: str | None = None) -> str:
    new = bindconf.format_key(name or key.name, NEW_ALGORITHM, secret).rstrip("\n")
    return bindconf.replace_span(text, key.stmt.start, key.stmt.end, new)


def _run_bind(env: Any, edits: dict[str, str], label: str, restart: bool = False) -> str:
    from pelagos.core.write_pipeline import FileChange

    if env.dry_run:
        return "dry run: would write " + ", ".join(edits)
    pipeline = bindsetup.bind_pipeline(
        env, env.paths.named_conf, label=label, restart=restart, written=[Path(p) for p in edits]
    )
    result = pipeline.run([FileChange(Path(p), t.encode()) for p, t in edits.items()])
    if not result.ok:
        raise RuntimeError(f"{label}: {result.error} (rolled back: {result.rolled_back})")
    return f"{', '.join(edits)} written; " + "; ".join(f"{s['name']} ok" for s in result.steps if s["ok"])


def _zone_stmt(files: ConfigFiles, view: str, zone: str) -> bindconf.ZoneDef:
    for z in bindconf.zones(list(files.top_level())):
        if z.view == view and z.name == zone:
            return z
    raise RuntimeError(f"zone {view}/{zone} not found any more")


def remediate_tsig_key(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    files = _reload_files(env)
    found = _find_key(files, d["key"])
    if found is None:
        raise RuntimeError(f"key {d['key']} not found any more")
    path, key = found
    secret = managed.new_secret()
    out = _run_bind(
        env, {path: _replace_key_text(_file_text(files, path), key, secret)}, f"security-key-{d['key']}"
    )
    stored = env.store_secrets({f"tsig/{d['key']}": secret})
    note = f"key {d['key']} is now {NEW_ALGORITHM}; give the new secret (in {path}) to its peers"
    return f"{out}\n{stored}\n{note}"


def remediate_rndc_key(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    """New hmac-sha256 secret in every file defining the rndc key, then a restart (rndc cannot reconfig)."""
    files = _reload_files(env)
    secret = managed.new_secret()
    edits: dict[str, str] = {}
    candidates = [d.get("file"), str(env.paths.rndc_key), str(env.paths.rndc_conf_pelagos)]
    rndc_conf = env.paths.rndc_key.parent / "rndc.conf"
    candidates.append(str(rndc_conf))
    for path in [c for c in candidates if c]:
        if path in edits or not Path(path).exists():
            continue
        text = _file_text(files, path)
        try:
            stmts = bindconf.parse(text, path)
        except bindconf.ParseError:
            continue
        defs = [k for k in bindconf.keys(stmts) if k.name == d["key"]]
        for k in sorted(defs, key=lambda k: k.stmt.start, reverse=True):
            text = _replace_key_text(text, k, secret)
        if defs:
            edits[path] = text
    if not edits:
        raise RuntimeError(f"rndc key {d['key']} not found")
    out = _run_bind(env, edits, "security-rndc-key", restart=True)
    return f"{out}\n{env.store_secrets({'rndc/' + d['key']: secret})}"


def _insert_rules_for_new_key(text: str, zone: bindconf.ZoneDef, old: str, new: str) -> str:
    """Copies every update rule naming `old` for `new` (update-policy grants, allow-update keys)."""
    pol = zone.stmt.sub("update-policy")
    if pol is not None and pol.block is not None:
        for rule in sorted(pol.block.statements, key=lambda r: r.start, reverse=True):
            if rule.name == "grant" and rule.words and rule.words[0].strip('"') == old:
                rule_text = text[rule.start : rule.end]
                copy = re.sub(r'^grant\s+"?' + re.escape(old) + r'"?', f'grant "{new}"', rule_text)
                text = text[: rule.end] + " " + copy + text[rule.end :]
    au = zone.stmt.sub("allow-update")
    if au is not None and au.block is not None and f"key {old}" in zone.elements("allow-update"):
        text = text[: au.block.end] + f' key "{new}"; ' + text[au.block.end :]
    return text


def _remove_rules_for_key(text: str, zone: bindconf.ZoneDef, old: str) -> str:
    pieces: list[tuple[int, int]] = []
    pol = zone.stmt.sub("update-policy")
    if pol is not None and pol.block is not None:
        pieces += [
            (r.start, r.end)
            for r in pol.block.statements
            if r.name == "grant" and r.words and r.words[0].strip('"') == old
        ]
    au = zone.stmt.sub("allow-update")
    if au is not None and au.block is not None:
        pieces += [
            (e.start, e.end)
            for e in au.block.statements
            if e.name == "key" and e.words and e.words[0].strip('"') == old
        ]
    for start, end in sorted(pieces, reverse=True):
        text = text[:start] + text[end:].lstrip(" ")
    return text


def _zones_using_key(files: ConfigFiles, key: str) -> list[bindconf.ZoneDef]:
    out = []
    for z in bindconf.zones(list(files.top_level())):
        if f"key {key}" in z.elements("allow-update") or any(
            e.split()[1:2] == [key] for e in z.elements("update-policy") if e.startswith("grant ")
        ):
            out.append(z)
    return out


def _new_key_secret(env: Any, ctx: dict[str, Any], new: str) -> str:
    """Same secret on both sides: this job's, else keys.conf, else the replicated cluster secret."""
    if new in ctx.get("secrets", {}):
        return ctx["secrets"][new]
    if env.paths.keys_conf.exists():
        for k in bindconf.keys(bindconf.parse(env.paths.keys_conf.read_text())):
            if k.name == new and k.secret:
                return k.secret
    if env.node_initialized() and env.node_paths.master_key.exists():
        from pelagos.core.config_store import ConfigStore
        from pelagos.core.secrets import SecretBox

        cluster = ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml).load_cluster()
        token = cluster.secrets.get(f"tsig/{new}")
        if token:
            return SecretBox.from_file(env.node_paths.master_key).decrypt(f"tsig/{new}", token)
    raise RuntimeError(f"no secret for {new}: run the BIND step of the switch first")


def dual_key_add(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    old, new = d["key"], d["new_key"]
    files = _reload_files(env)
    edits: dict[str, str] = {}
    if _find_key(files, new) is None:
        secret = managed.new_secret()
        ctx.setdefault("secrets", {})[new] = secret
        keys_conf = env.paths.keys_conf
        base = keys_conf.read_text() if keys_conf.exists() else managed.render_keys_conf({})
        edits[str(keys_conf)] = base.rstrip("\n") + "\n" + bindconf.format_key(new, NEW_ALGORITHM, secret)
        if not bindconf.has_include(
            [s for p in files.order for s in files.statements[p]], str(env.paths.pelagos_conf)
        ):
            raise RuntimeError("the Pelagos include line is missing: run the import first")
    zones = _zones_using_key(files, old)
    by_file: dict[str, list[bindconf.ZoneDef]] = {}
    for z in zones:
        by_file.setdefault(str(z.stmt.path), []).append(z)
    for path, zs in by_file.items():
        text = _file_text(files, path)
        for z in sorted(zs, key=lambda z: z.stmt.start, reverse=True):
            if any(
                e.split()[1:2] == [new] for e in z.elements("update-policy")
            ) or f"key {new}" in z.elements("allow-update"):
                continue
            text = _insert_rules_for_new_key(text, z, old, new)
        edits[path] = text
    if not edits:
        return f"{new} already accepted next to {old}"
    out = _run_bind(env, edits, f"security-dualkey-add-{new}")
    stored = env.store_secrets({f"tsig/{new}": ctx["secrets"][new]}) if new in ctx.get("secrets", {}) else ""
    return f"{out}\nzones accepting both keys: {', '.join(z.name for z in zones) or 'none'}\n{stored}".strip()


def dual_key_switch_d2(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    old, new = d["key"], d["new_key"]
    conf = env.paths.kea_conf("kea-dhcp-ddns")
    config = keaconf.loads(conf.read_text(), str(conf))
    names = {str(k.get("name")) for k in keaconf.tsig_keys(config)}
    if old not in names and new in names:
        return f"D2 already uses {new}"
    secret = _new_key_secret(env, ctx, new)
    version = env.t.kea_version("kea-dhcp-ddns")
    secret_file = keasetup.secret_file_path(env.paths.kea_conf_dir, new)
    out = [keasetup.write_secret_file(env, secret_file, secret)]
    entry = keasetup.tsig_key_entry(new, NEW_ALGORITHM, secret, secret_file, version)
    new_cfg = keaconf.rename_key(config, old, entry)
    files = keasetup.edited_files(conf, new_cfg)
    out.append(keasetup.write_files(env, "d2", conf, files, f"security-d2-{new}", restart=False))
    used = keaconf.domains_using_key(new_cfg, new)
    out.append(f"D2 domains now signed with {new}: {', '.join(n for _, n in used) or 'none'}")
    return "\n".join(out)


def _without_includes(text: str, path: str) -> str:
    """`text` without its include statements: a file named after a key is not a use of the key."""
    try:
        stmts = bindconf.parse(text, path)
    except bindconf.ParseError:
        return text
    spans: list[tuple[int, int]] = []

    def walk(items: list[Statement]) -> None:
        for st in items:
            if st.name == "include":
                spans.append((st.start, st.end))
            for block in st.blocks:
                walk(block.statements)

    walk(stmts)
    for start, end in sorted(spans, reverse=True):
        text = text[:start] + text[end:]
    return text


def dual_key_remove(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    old = d["key"]
    files = _reload_files(env)
    zones = _zones_using_key(files, old)
    by_file: dict[str, str] = {}
    for z in sorted(zones, key=lambda z: z.stmt.start, reverse=True):
        path = str(z.stmt.path)
        by_file[path] = _remove_rules_for_key(by_file.get(path, _file_text(files, path)), z, old)
    # Drop the key statement only when nothing else names it any more.
    remaining = "\n".join(_without_includes(by_file.get(p, files.texts[p]), p) for p in files.order)
    found = _find_key(files, old)
    note = ""
    if found is not None:
        path = found[0]
        refs = len(re.findall(r'(?<![\w-])"?' + re.escape(old) + r'"?(?![\w-])', remaining))
        if refs <= 1:
            text = by_file.get(path, _file_text(files, path))
            fresh = bindconf.parse(text, path)
            kd = next(k for k in bindconf.keys(fresh) if k.name == old)
            by_file[path] = bindconf.delete_statement(text, kd.stmt)
        else:
            note = f"\nkey {old} is still referenced elsewhere (transfers, servers); its statement is kept"
    if not by_file:
        return f"{old} already removed"
    return _run_bind(env, by_file, f"security-dualkey-remove-{old}") + note


def _replace_stmt(
    env: Any, d: dict[str, Any], select: Any, replacement: str, label: str, restart: bool = False
) -> str:
    files = _reload_files(env)
    stmt = select(files)
    if stmt is None:
        raise RuntimeError(f"{label}: statement not found any more")
    text = _file_text(files, str(stmt.path))
    return _run_bind(
        env,
        {str(stmt.path): bindconf.replace_span(text, stmt.start, stmt.end, replacement)},
        label,
        restart=restart,
    )


def remediate_update_policy(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    files = _reload_files(env)
    if managed.ADMIN_KEY not in bindsetup.all_keys(files):
        raise RuntimeError(f"key {managed.ADMIN_KEY} is not defined: run the import first")
    z = _zone_stmt(files, d["view"], d["zone"])
    au = z.stmt.sub("allow-update")
    if au is None:
        return "allow-update already gone"
    # Read the updating key now: a dual-key switch earlier in the same plan may have renamed it.
    proposal = bindsetup.update_policy_proposal(z, bindsetup.kea_key_of_zone(z))
    text = _file_text(files, str(z.stmt.path))
    return _run_bind(
        env,
        {str(z.stmt.path): bindconf.replace_span(text, au.start, au.end, proposal)},
        f"security-update-policy-{d['zone']}",
    )


def remediate_allow_transfer(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    files = _reload_files(env)
    needed = d.get("key") or managed.READ_KEY
    if needed not in bindsetup.all_keys(files):
        raise RuntimeError(f"key {needed} is not defined: run the import first")

    def select(f: ConfigFiles) -> Statement | None:
        owner = _zone_stmt(f, d["view"], d["zone"]).stmt if d.get("zone") else bindsetup.find_options(f)
        return owner.sub("allow-transfer") if owner else None

    stmt = select(files)
    if stmt is None:
        return "allow-transfer already gone"
    key = d.get("key") or managed.READ_KEY
    kept = [
        e for e in bindconf.acl_elements(stmt) if e.strip('"') != "any" and e.replace('"', "") != f"key {key}"
    ]
    repl = "allow-transfer { " + " ".join(f"{e};" for e in [f"key {key}", *kept]) + " };"
    return _replace_stmt(env, d, select, repl, "security-allow-transfer")


def remediate_update_policy_grant(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    files = _reload_files(env)
    if managed.ADMIN_KEY not in bindsetup.all_keys(files):
        raise RuntimeError(f"key {managed.ADMIN_KEY} is not defined: run the import first")
    z = _zone_stmt(files, d["view"], d["zone"])
    if _grants_key(z, managed.ADMIN_KEY):
        return f"{managed.ADMIN_KEY} already granted"
    pol = z.stmt.sub("update-policy")
    if pol is None or pol.block is None:
        raise RuntimeError(f"zone {d['zone']} has no update-policy block any more")
    grant = f"grant {managed.ADMIN_KEY} zonesub {' '.join(UPDATE_TYPES_ADMIN)}; "
    text = _file_text(files, str(z.stmt.path))
    end = pol.block.end
    return _run_bind(
        env, {str(z.stmt.path): text[:end] + grant + text[end:]}, f"security-update-policy-{d['zone']}"
    )


def remediate_update_types_widen(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    """Appends the missing editable types to the key's first zonesub grant, other rules untouched."""
    files = _reload_files(env)
    key = d.get("key") or managed.ADMIN_KEY
    z = _zone_stmt(files, d["view"], d["zone"])
    narrow = _narrow_grant(z, key)
    if narrow is None:
        return f"{key} already granted every editable type"
    rule, missing = narrow
    text = _file_text(files, str(rule.path))
    old = text[rule.start : rule.end].rstrip().rstrip(";").rstrip()
    return _run_bind(
        env,
        {str(rule.path): bindconf.replace_span(text, rule.start, rule.end, f"{old} {' '.join(missing)};")},
        f"security-update-types-{d['zone']}",
    )


def remediate_update_key_add(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    """Adds the key to the zone's update-policy, its allow-update, or the allow-update it inherits."""
    files = _reload_files(env)
    key = d.get("key") or managed.ADMIN_KEY
    if key not in bindsetup.all_keys(files):
        raise RuntimeError(f"key {key} is not defined: run the import first")
    top = list(files.top_level())
    z = _zone_stmt(files, d["view"], d["zone"])
    if _grants_effective(z, key, top):
        return f"{key} already granted"
    pol = z.stmt.sub("update-policy")
    if pol is not None:
        if pol.block is None:
            raise RuntimeError(f"zone {d['zone']} has update-policy local: grant {key} by hand")
        stmt, at, insert = pol, pol.block.end, f"grant {key} zonesub {' '.join(UPDATE_TYPES_ADMIN)}; "
    else:
        au = z.stmt.sub("allow-update") or zone_audit.inherited_allow_update(top, z.view)
        if au is None or au.block is None:
            raise RuntimeError(f"zone {d['zone']} takes no updates any more")
        stmt, at, insert = au, au.block.start + 1, f" key {key};"
    text = _file_text(files, str(stmt.path))
    return _run_bind(
        env, {str(stmt.path): text[:at] + insert + text[at:]}, f"security-update-key-{d['zone']}"
    )


def remediate_allow_transfer_add(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    files = _reload_files(env)
    if managed.READ_KEY not in bindsetup.all_keys(files):
        raise RuntimeError(f"key {managed.READ_KEY} is not defined: run the import first")
    options = bindsetup.find_options(files)
    if options is None or options.block is None:
        raise RuntimeError("no options block found any more")
    if options.sub("allow-transfer") is not None:
        return remediate_allow_transfer(env, {**d, "zone": None}, ctx)
    text = _file_text(files, str(options.path))
    end = options.block.end
    line = f"\tallow-transfer {{ key {managed.READ_KEY}; }};\n"
    if not text[:end].endswith("\n"):
        line = "\n" + line
    return _run_bind(env, {str(options.path): text[:end] + line + text[end:]}, "security-allow-transfer")


def remediate_recursion(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    name = d.get("statement", "allow-recursion")
    return _replace_stmt(
        env,
        d,
        lambda f: bindsetup.find_options(f).sub(name) if bindsetup.find_options(f) else None,
        f"{name} {{ localhost; localnets; }};",
        "security-recursion",
    )


def remediate_file_modes(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    return bind_files.apply(env, d.get("files") or [])


def remediate_version_hide(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    """`version "none";` in the options: version.bind answers "none" instead of the release."""
    files = _reload_files(env)
    options = bindsetup.find_options(files)
    if options is None or options.block is None:
        raise RuntimeError("no options block found any more")
    current = options.sub("version")
    text = _file_text(files, str(options.path))
    if current is not None:
        text = bindconf.replace_span(text, current.start, current.end, 'version "none";')
    else:
        end = options.block.end
        line = '\tversion "none";\n'
        if not text[:end].endswith("\n"):
            line = "\n" + line
        text = text[:end] + line + text[end:]
    return _run_bind(env, {str(options.path): text}, "security-version")


def remediate_dnssec(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    return _replace_stmt(
        env,
        d,
        lambda f: bindsetup.find_options(f).sub("dnssec-validation") if bindsetup.find_options(f) else None,
        "dnssec-validation auto;",
        "security-dnssec-validation",
    )


def _top_stmt(name: str) -> Any:
    def select(files: ConfigFiles) -> Statement | None:
        return next((s for s in files.top_level() if s.name == name), None)

    return select


def remediate_controls(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    keys = " ".join(f'"{k.strip(chr(34))}";' for k in d.get("keys") or [])
    keys_clause = f" keys {{ {keys} }}" if keys else ""
    repl = (
        f"controls {{\n\tinet 127.0.0.1 port {d.get('port', 953)} allow {{ 127.0.0.1; }}{keys_clause};\n}};"
    )
    # `rndc reconfig` would drop its own connection when the channel moves: restart instead.
    return _replace_stmt(env, d, _top_stmt("controls"), repl, "security-controls", restart=True)


def remediate_stats(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    repl = f"statistics-channels {{\n\tinet 127.0.0.1 port {d.get('port', 80)} allow {{ 127.0.0.1; }};\n}};"
    return _replace_stmt(env, d, _top_stmt("statistics-channels"), repl, "security-stats")


def remediate_ctrl_agent(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    unit = d.get("unit") or "kea-ctrl-agent.service"
    return env.services.disable_now(unit) or f"{unit} stopped and disabled"


def remediate_socket_dir(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    if env.dry_run:
        return f"dry run: chmod 0750 {d['path']}"
    os.chmod(d["path"], 0o750)  # noqa: S103 - the Kea group must reach the sockets
    return f"{d['path']} is now 0750"


def remediate_secret_file(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    conf = env.paths.kea_conf("kea-dhcp-ddns")
    config = keaconf.loads(conf.read_text(), str(conf))
    key = next((k for k in keaconf.tsig_keys(config) if k.get("name") == d["key"]), None)
    if key is None or "secret" not in key:
        return "secret already moved"
    path = keasetup.secret_file_path(env.paths.kea_conf_dir, d["key"])
    out = [keasetup.write_secret_file(env, path, str(key["secret"]))]
    entry = {k: v for k, v in key.items() if k != "secret"}
    entry["secret-file"] = str(path)
    new_cfg = keaconf.rename_key(config, d["key"], entry)
    # Lossless: comments stay and the key is changed in the file of the tree that defines it.
    files = keasetup.edited_files(conf, new_cfg)
    out.append(
        keasetup.write_files(env, "d2", conf, files, f"security-secret-file-{d['key']}", restart=False)
    )
    return "\n".join(out)


def _ha_open_listeners(env: Any) -> list[ha_listener.HAListener]:
    out: list[ha_listener.HAListener] = []
    for engine in ("kea4", "kea6"):
        daemon = keasetup.DAEMONS[engine]
        conf = env.paths.kea_conf(daemon)
        try:
            config = keaconf.loads(conf.read_text(), str(conf))
        except (OSError, keaconf.KeaConfigError):
            continue
        out += [x for x in ha_listener.listeners(engine, config, env.t.kea_version(daemon)) if x.open]
    return out


def _ha_restrict(env: Any, engine: str) -> str:
    """restrict-commands true in every HA relationship of `engine`: the peer only sends HA commands."""
    daemon = keasetup.DAEMONS[engine]
    conf = env.paths.kea_conf(daemon)
    version = env.t.kea_version(daemon)
    if not ha_listener.supports_restrict(version):
        return f"Kea {version} has no restrict-commands: kept as is"
    config = keaconf.loads(conf.read_text(), str(conf))
    new, changed = ha_listener.with_restrict_commands(config)
    if not changed:
        return f"{daemon}: restrict-commands already true"
    files = keasetup.edited_files(conf, new)
    return keasetup.write_files(env, engine, conf, files, f"security-ha-restrict-{engine}", restart=False)


def _ha_guard(env: Any) -> str:
    """Loads the nft guard for every open HA listener of this node, then watches the peers' packets:
    if only drops grow, the guard is removed again and the step fails."""
    open_listeners = _ha_open_listeners(env)
    fw = ha_listener.read_firewall(env)
    ports = sorted({x.port for x in open_listeners})
    if not ports or all(fw.guard(p) is not None for p in ports):
        return "every HA listener port already has a firewall guard"
    nft = env.binary("nft")
    if nft is None:
        raise RuntimeError("nft not found: install nftables, or restrict the HA port to the peers by hand")
    peers = sorted({p for x in open_listeners for p in x.peers})
    if not peers:
        raise RuntimeError("no HA peer address in the configuration: the guard would cut the pair")
    rules = env.node_paths.etc / ha_listener.GUARD_FILE
    unit = env.paths.systemd_dir / ha_listener.GUARD_UNIT
    text = ha_listener.render_guard(ports, peers)
    if env.dry_run:
        return f"dry run: would load {rules} through {ha_listener.GUARD_UNIT}"
    before = {p: (p.read_text() if p.exists() else None) for p in (rules, unit)}
    rules.parent.mkdir(parents=True, exist_ok=True)
    rules.write_text(text)
    os.chmod(rules, 0o640)
    unit.parent.mkdir(parents=True, exist_ok=True)
    unit.write_text(ha_listener.render_unit(nft, rules))
    os.chmod(unit, 0o644)
    env.services.daemon_reload()
    env.services.enable_now(ha_listener.GUARD_UNIT)
    env.services.restart(ha_listener.GUARD_UNIT)
    wait = min(30.0, max(5.0, 2.5 * max(x.heartbeat_ms for x in open_listeners) / 1000))
    seen = ha_listener.watch_peers(env, wait, _sleep)
    if seen == "blocked":
        env.services.disable_now(ha_listener.GUARD_UNIT)
        env.runner.run(
            [nft, "delete", "table", "inet", ha_listener.GUARD_TABLE], privileged=True, check=False
        )
        for path, old in before.items():
            if old is None:
                path.unlink(missing_ok=True)
            else:
                path.write_text(old)
        env.services.daemon_reload()
        raise RuntimeError(
            f"packets to port(s) {ports} were dropped and none came from {', '.join(peers)} within "
            f"{wait:.0f}s: guard removed (a peer may reach this node from another address)"
        )
    note = "peer traffic seen through it" if seen == "peers" else "no HA traffic yet, nothing dropped"
    return f"{ha_listener.GUARD_UNIT}: only {', '.join(peers)} reach port(s) {ports} ({note})"


def _sleep(seconds: float) -> None:
    import time

    time.sleep(seconds)


def remediate_ha_listener(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    """restrict-commands first (the peer only sends HA commands), then the peers-only firewall guard:
    neither cuts the pair, so each node is fixed on its own. TLS stays a manual step for both peers."""
    out = [_ha_restrict(env, d["engine"])]
    if env.binary("nft") is not None:
        out.append(_ha_guard(env))
    elif not d.get("mitigated"):
        out.append("nft not found: restrict the HA port to the peers by hand")
    return "\n".join(out)


REMEDIATIONS = {
    "tsig_key": remediate_tsig_key,
    "rndc_key": remediate_rndc_key,
    "update_policy": remediate_update_policy,
    "allow_transfer": remediate_allow_transfer,
    "allow_transfer_add": remediate_allow_transfer_add,
    "update_policy_grant": remediate_update_policy_grant,
    "update_types_widen": remediate_update_types_widen,
    "recursion": remediate_recursion,
    "dnssec_validation": remediate_dnssec,
    "controls": remediate_controls,
    "stats": remediate_stats,
    "ctrl_agent": remediate_ctrl_agent,
    "socket_dir": remediate_socket_dir,
    "secret_file": remediate_secret_file,
    "ha_listener": remediate_ha_listener,
    "ha_guard_set": ha_guard.remediate_set,
    "ha_guard_adopt": ha_guard.remediate_adopt,
    "drift": drift.remediate,
    "file_modes": remediate_file_modes,
    "version_hide": remediate_version_hide,
    "convert_dynamic": zone_audit.remediate_convert_dynamic,
    "update_key_add": remediate_update_key_add,
    "view_key": zone_audit.remediate_view_key,
}
DUAL_KEY_STEPS = {
    "1-bind-add": dual_key_add,
    "2-d2-switch": dual_key_switch_d2,
    "3-bind-remove": dual_key_remove,
}


def remediation_steps(plan: Plan, env: Any) -> list[Step]:
    """One step per change for this node, in plan order; each step backs up, validates and rolls back."""
    ctx: dict[str, Any] = {"secrets": dict(getattr(env, "plan_secrets", None) or {})}
    steps: list[Step] = []

    def preconditions() -> str:
        from pelagos.installer.importer import check_preconditions

        moved = check_preconditions(env, plan)
        if moved:
            raise RuntimeError(f"configuration changed since the plan was made: {', '.join(moved)}")
        return f"{len(plan.preconditions)} file(s) unchanged"

    steps.append(Step("security/preconditions", preconditions))
    for change in plan.changes:
        if env.node_id not in change.node_ids:
            continue  # another node's change, or a manual step
        details = change.after["details"]
        if "step" in change.after:
            fn = DUAL_KEY_STEPS[change.after["step"]]
        else:
            fn = REMEDIATIONS[details["remediation"]]
        steps.append(Step(change.target, lambda fn=fn, d=details: fn(env, d, ctx), weight=2))
    return steps
