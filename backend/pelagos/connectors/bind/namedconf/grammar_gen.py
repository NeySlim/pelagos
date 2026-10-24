# SPDX-License-Identifier: Apache-2.0
"""Generate grammar.json from the BIND sources (doc/misc/options and doc/misc/*.zoneopt).

Usage (on a machine with the BIND source tree unpacked):

    python -m pelagos.connectors.bind.namedconf.grammar_gen <bind-src>/doc/misc 9.20.30 > grammar.json

The files are produced by `cfg_test --grammar` in the BIND build; they list
every statement with its argument grammar in ISC notation. This module parses
that notation into a JSON structure the advanced editor can drive, without any
dependency on the BIND build.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

FLAGS = {
    "may occur multiple times": "repeatable",
    "obsolete": "obsolete",
    "deprecated": "deprecated",
    "experimental": "experimental",
    "test only": "test-only",
    "not configured": "not-configured",
}

ZONE_TYPES = (
    "primary",
    "secondary",
    "mirror",
    "stub",
    "static-stub",
    "forward",
    "hint",
    "redirect",
    "in-view",
)

PLACEHOLDERS = {
    "address_match_element": "ACL element: address, prefix, key <name>, acl name, any, none, localhost, "
    "localnets, or a nested { } list; `!` negates",
    "boolean": "yes | no | true | false | 1 | 0",
    "class": "DNS class (IN, CH, HS)",
    "duration": "TTL-style duration: seconds or e.g. 1h, 2d, PT1H",
    "duration_or_unlimited": "duration or `unlimited`",
    "fixedpoint": "decimal number with up to two fractional digits",
    "integer": "non-negative integer",
    "ipv4_address": "IPv4 address",
    "ipv6_address": "IPv6 address",
    "log_severity": "critical | error | warning | notice | info | debug [level] | dynamic",
    "netprefix": "address or address/prefix-length",
    "percentage": "integer followed by %",
    "portrange": "port or `range low high`",
    "quoted_string": "double-quoted string",
    "rrtypelist": "space-separated list of RR types, or empty for any",
    "server-list": "name of a remote-servers (primaries) list",
    "server_key": "key name or { key; ... }",
    "size": "bytes with optional K, M or G suffix",
    "sizeval": "size, `unlimited` or `default`",
    "string": "bare word or quoted string",
    "syslog_facility": "syslog facility name",
    "unspecified-text": "opaque text passed to the module",
}

_GRAMMAR_TOKEN = re.compile(r"<[A-Za-z0-9_-]+>|\.\.\.|[()\[\]{}|;]|[^\s()\[\]{}|;]+")
_KEY = re.compile(r"^[a-zA-Z0-9-]+$")


# ISC grammar notation -> pattern tree ---------------------------------------------


def parse_pattern(grammar: str) -> list[dict[str, Any]]:
    """`[ port <integer> ] { <address_match_element>; ... }` -> nested items of kind
    literal, placeholder, optional, choice, list or block."""
    tokens = _GRAMMAR_TOKEN.findall(grammar)
    items, pos = _parse_alternatives(tokens, 0, None)
    if pos != len(tokens):
        raise ValueError(f"trailing tokens in grammar: {grammar!r}")
    return items


def _parse_alternatives(tokens: list[str], pos: int, closer: str | None) -> tuple[list[dict[str, Any]], int]:
    branches: list[list[dict[str, Any]]] = [[]]
    while pos < len(tokens):
        tok = tokens[pos]
        if tok == closer:
            break
        if tok == "|":
            branches.append([])
            pos += 1
            continue
        if tok in ")]}":
            raise ValueError(f"unbalanced {tok!r} in grammar")
        if tok == "(":
            inner, pos = _parse_alternatives(tokens, pos + 1, ")")
            branches[-1].extend(inner)
            pos += 1
        elif tok == "[":
            inner, pos = _parse_alternatives(tokens, pos + 1, "]")
            branches[-1].append({"kind": "optional", "items": inner})
            pos += 1
        elif tok == "{":
            inner, pos = _parse_alternatives(tokens, pos + 1, "}")
            pos += 1
            if (
                len(inner) >= 2
                and inner[-1] == {"kind": "literal", "value": "..."}
                and inner[-2]
                == {
                    "kind": "literal",
                    "value": ";",
                }
            ):
                branches[-1].append({"kind": "list", "items": inner[:-2]})
            else:
                branches[-1].append({"kind": "block", "items": inner})
        elif tok.startswith("<") and tok.endswith(">"):
            branches[-1].append({"kind": "placeholder", "type": tok[1:-1]})
            pos += 1
        else:
            branches[-1].append({"kind": "literal", "value": tok})
            pos += 1
    if closer is not None and (pos >= len(tokens) or tokens[pos] != closer):
        raise ValueError(f"missing {closer!r} in grammar")
    if len(branches) == 1:
        return branches[0], pos
    return [{"kind": "choice", "alternatives": branches}], pos


def placeholder_types(pattern: list[dict[str, Any]]) -> list[str]:
    found: list[str] = []

    def visit(items: list[dict[str, Any]]) -> None:
        for it in items:
            if it["kind"] == "placeholder" and it["type"] not in found:
                found.append(it["type"])
            for key in ("items",):
                if key in it:
                    visit(it[key])
            for alt in it.get("alternatives", []):
                visit(alt)

    visit(pattern)
    return found


# cfg_test output -> contexts -----------------------------------------------------------


def _split_comment(line: str) -> tuple[str, list[str]]:
    code, _, comment = line.partition("//")
    flags = [FLAGS[f] for f in FLAGS if f in comment]
    return code.rstrip(), flags


def parse_map(
    lines: list[str], index: int, context: str, out: dict[str, dict[str, Any]], doc_base: str
) -> int:
    """Consume statements of one map body until its `};`; nested maps become `<context>.<name>`."""
    statements: dict[str, Any] = out.setdefault(context, {"statements": {}})["statements"]
    while index < len(lines):
        code, flags = _split_comment(lines[index])
        stripped = code.strip()
        index += 1
        if not stripped:
            continue
        if stripped == "};":
            return index
        name = stripped.split()[0].rstrip(";")
        if not _KEY.match(name):
            raise ValueError(f"unexpected grammar line: {lines[index - 1]!r}")
        rest = stripped[len(name) :].strip()
        entry: dict[str, Any] = {
            "grammar": "",
            "pattern": [],
            "types": [],
            "repeatable": "repeatable" in flags,
            "status": _status(flags),
            "block": None,
            "doc_url": f"{doc_base}#namedconf-statement-{name}",
        }
        if stripped.endswith("{"):
            head = rest[:-1].strip()
            sub = name if context == "top" else f"{context}.{name}"
            entry["grammar"] = head
            entry["pattern"] = parse_pattern(head) if head else []
            entry["block"] = sub
            index = parse_map(lines, index, sub, out, doc_base)
            # Flags of a map are written after its closing brace.
            _, close_flags = _split_comment(lines[index - 1])
            entry["repeatable"] = entry["repeatable"] or "repeatable" in close_flags
            if entry["status"] == "current":
                entry["status"] = _status(close_flags)
        else:
            body = rest[:-1].strip() if rest.endswith(";") else rest
            entry["grammar"] = body
            entry["pattern"] = parse_pattern(body) if body else []
        entry["types"] = placeholder_types(entry["pattern"])
        statements[name] = entry
    return index


def _status(flags: list[str]) -> str:
    for status in ("obsolete", "deprecated", "experimental", "test-only", "not-configured"):
        if status in flags:
            return status
    return "current"


def parse_zoneopt(text: str, zone_type: str, out: dict[str, dict[str, Any]], doc_base: str) -> None:
    lines = text.splitlines()
    head, _ = _split_comment(lines[0])
    assert head.startswith("zone ") and head.endswith("{"), head
    parse_map(lines, 1, f"zone.{zone_type}", out, doc_base)


def generate(misc_dir: Path, version: str) -> dict[str, Any]:
    doc_base = f"https://bind9.readthedocs.io/en/v{version}/reference.html"
    contexts: dict[str, dict[str, Any]] = {}
    lines = (misc_dir / "options").read_text().splitlines()
    # The top level has no closing `};`, so one call consumes the whole file.
    parse_map(lines, 0, "top", contexts, doc_base)
    sources = ["doc/misc/options"]
    zone_grammar = ""
    for zone_type in ZONE_TYPES:
        path = misc_dir / f"{zone_type}.zoneopt"
        if not path.exists():
            continue
        sources.append(f"doc/misc/{zone_type}.zoneopt")
        text = path.read_text()
        zone_grammar = _split_comment(text.splitlines()[0])[0].strip()[len("zone") : -1].strip()
        parse_zoneopt(text, zone_type, contexts, doc_base)
    variants = {t: f"zone.{t}" for t in ZONE_TYPES if f"zone.{t}" in contexts}
    # `zone` is not in cfg_test's options listing: synthesize it for the top level and views.
    type_choice = " | ".join(t for t in variants if t != "in-view")
    zone_entry = {
        "grammar": zone_grammar,
        "pattern": parse_pattern(zone_grammar) if zone_grammar else [],
        "types": placeholder_types(parse_pattern(zone_grammar)) if zone_grammar else [],
        "repeatable": True,
        "status": "current",
        "block": "zone",
        "variants": variants,
        "doc_url": f"{doc_base}#namedconf-statement-zone",
    }
    contexts["zone"] = {
        "statements": {
            "type": {
                "grammar": f"( {type_choice} )",
                "pattern": parse_pattern(f"( {type_choice} )"),
                "types": [],
                "repeatable": False,
                "status": "current",
                "block": None,
                "doc_url": f"{doc_base}#namedconf-statement-type",
            },
            "in-view": {
                "grammar": "<string>",
                "pattern": parse_pattern("<string>"),
                "types": ["string"],
                "repeatable": False,
                "status": "current",
                "block": None,
                "doc_url": f"{doc_base}#namedconf-statement-in-view",
            },
        },
        "note": "Common to every zone type; the statements allowed depend on `type`, see variants.",
    }
    for ctx in ("top", "view"):
        if ctx in contexts:
            contexts[ctx]["statements"]["zone"] = dict(zone_entry)
    # `include` is handled by the parser itself, not by the grammar tables.
    for ctx in contexts.values():
        ctx["statements"] = dict(sorted(ctx["statements"].items()))
    return {
        "bind_version": version,
        "sources": sources,
        "generator": "pelagos.connectors.bind.namedconf.grammar_gen",
        "doc_base": doc_base,
        "placeholders": PLACEHOLDERS,
        "contexts": dict(sorted(contexts.items())),
    }


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print("usage: grammar_gen <bind-src/doc/misc> <bind version>", file=sys.stderr)
        return 2
    data = generate(Path(args[0]), args[1])
    json.dump(data, sys.stdout, indent=1, sort_keys=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
