# SPDX-License-Identifier: Apache-2.0
"""DNSSEC: dnssec-policy statements (read, render, grammar check), key state reading from
`rndc dnssec -status`, and DS publication guidance from the zone's DNSKEY and CDS records."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype

from pelagos.connectors.bind.namedconf.grammar import statement_info
from pelagos.connectors.bind.namedconf.resolve import ConfigFiles
from pelagos.connectors.bind.namedconf.tree import format_statement, parse_statements, quote

BUILTIN_POLICIES = ("default", "insecure", "none")
POLICY_CONTEXT = "dnssec-policy"
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_DATE_FORMAT = "%a %b %d %H:%M:%S %Y"


class PolicyError(ValueError):
    """A policy name or statement the grammar does not accept."""


def policies(files: ConfigFiles, include_dir: Path | None) -> list[dict[str, Any]]:
    """Top-level dnssec-policy statements with their sub-statements and provenance."""
    root = include_dir.resolve() if include_dir else None
    out = []
    for res in files.statements():
        node = res.node
        if res.parents or node.name != "dnssec-policy" or not node.args:
            continue
        managed = root is not None and Path(res.path).resolve().is_relative_to(root)
        out.append(
            {
                "name": node.args[0],
                "statements": [{"name": s.name, "value": s.value_text()} for s in node.statements()],
                "text": node.serialize().strip(),
                "source": "pelagos" if managed else "user_conf",
                "config_path": res.path,
                "line": node.line,
            }
        )
    return out


def check_name(name: str) -> str:
    if not _NAME.match(name or ""):
        raise PolicyError(f"invalid policy name {name!r}")
    if name in BUILTIN_POLICIES:
        raise PolicyError(f"{name} is a built-in policy and cannot be redefined")
    return name


def render_policy(name: str, statements: list[dict[str, Any]]) -> str:
    """`dnssec-policy "<name>" { <statement> <value>; ... };` after checking every statement name
    against the grammar of the dnssec-policy block."""
    check_name(name)
    body = []
    seen: set[str] = set()
    for item in statements:
        sname = str(item.get("name", "")).strip()
        value = str(item.get("value", "")).strip().rstrip(";").strip()
        info = statement_info(POLICY_CONTEXT, sname)
        if info is None:
            raise PolicyError(f"{sname!r} is not a dnssec-policy statement")
        if sname in seen and not info.get("repeatable"):
            raise PolicyError(f"{sname} appears twice")
        seen.add(sname)
        if not value:
            raise PolicyError(f"{sname} needs a value")
        body.append((sname, f"{sname} {value};"))
    text = f"dnssec-policy {quote(name)} {{ {' '.join(b for _, b in body)} }};"
    try:
        parsed = parse_statements(text)
    except ValueError as exc:
        raise PolicyError(f"invalid policy text: {exc}") from None
    # A value closing the block early would smuggle other statements into the file.
    if len(parsed) != 1 or parsed[0].name != "dnssec-policy" or parsed[0].args != [name]:
        raise PolicyError("a value closes the dnssec-policy block: braces or ';' out of place")
    if [s.name for s in parsed[0].statements()] != [n for n, _ in body]:
        raise PolicyError("a value holds more than one statement: braces or ';' out of place")
    return format_statement(text)


def _when(text: str) -> str | None:
    """`yes - since Sat Oct 24 18:32:10 2026` or a bare date as RFC 3339 UTC."""
    m = re.search(r"([A-Z][a-z]{2} [A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d \d{4})", text or "")
    if not m:
        return None
    try:
        return datetime.strptime(" ".join(m.group(1).split()), _DATE_FORMAT).replace(tzinfo=UTC).isoformat()
    except ValueError:
        return None


def enrich_status(status: dict[str, Any]) -> dict[str, Any]:
    """Flat fields for the screens next to the parsed lines: tag, role, state, dates."""
    for key in status.get("keys", []):
        states = key.get("states", {})
        roles = key.get("roles", [])
        key["tag"] = key.get("id")
        key["role"] = "CSK" if "CSK" in roles else (roles[0] if roles else None)
        key["state"] = states.get("dnskey") or states.get("goal")
        key["goal"] = states.get("goal")
        key["ds_state"] = states.get("ds")
        key["published"] = _when(states.get("published", ""))
        key["next_rollover"] = None
        for note in key.get("notes", []):
            if note.lower().startswith("next rollover scheduled"):
                key["next_rollover"] = _when(note)
    return status


def ds_records(zone: str, dnskeys: list[str], digest: str = "SHA256") -> dict[int, str]:
    """DS rdata (key tag -> text) for the secure entry point keys (flag 257) of the DNSKEY set."""
    out: dict[int, str] = {}
    origin = dns.name.from_text(zone)
    for text in dnskeys:
        rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, text)
        if not rd.flags & 0x0001:  # type: ignore[attr-defined]
            continue
        ds = dns.dnssec.make_ds(origin, rd, digest)
        out[dns.dnssec.key_id(rd)] = ds.to_text()  # type: ignore[arg-type]
    return out


def ds_guidance(status: dict[str, Any], ds: dict[int, str]) -> list[dict[str, Any]]:
    """What the parent must do for each KSK/CSK: publish a DS that named waits for, or withdraw one
    of a retiring key; then `checkds published|withdrawn` tells named it is done."""
    out = []
    for key in status.get("keys", []):
        if key.get("role") not in ("KSK", "CSK"):
            continue
        ds_state, goal = key.get("ds_state"), key.get("goal")
        tag = key.get("tag")
        if goal == "omnipresent" and ds_state in ("hidden", "rumoured"):
            out.append({"key_id": tag, "action": "publish", "ds": ds.get(tag), "checkds": "published"})
        elif goal == "hidden" and ds_state in ("omnipresent", "unretentive"):
            out.append({"key_id": tag, "action": "withdraw", "ds": ds.get(tag), "checkds": "withdrawn"})
    return out
