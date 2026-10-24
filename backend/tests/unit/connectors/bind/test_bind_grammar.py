# SPDX-License-Identifier: Apache-2.0
"""BIND 9.20 grammar: checked-in JSON, lookups, ISC notation parser and the generator itself."""

from __future__ import annotations

from pathlib import Path

import pytest

from pelagos.connectors.bind.namedconf import (
    ConfigFiles,
    context_for,
    grammar,
    parse,
    statement_info,
    zone_context,
)
from pelagos.connectors.bind.namedconf.grammar_gen import generate, parse_pattern

from .conftest import DATA

pytestmark = pytest.mark.unit


def test_grammar_payload_shape() -> None:
    g = grammar()
    assert g["bind_version"].startswith("9.20.")
    assert g["sources"][0] == "doc/misc/options"
    assert {"top", "options", "view", "zone", "zone.primary", "zone.secondary", "logging"} <= set(
        g["contexts"]
    )
    recursion = statement_info("options", "recursion")
    assert recursion is not None and recursion["types"] == ["boolean"] and recursion["block"] is None
    assert recursion["doc_url"].endswith("#namedconf-statement-recursion")
    zone = statement_info("top", "zone")
    assert zone and zone["repeatable"] and zone["variants"]["primary"] == "zone.primary"
    assert statement_info("zone.primary", "update-policy") is not None
    assert statement_info("zone.secondary", "primaries") is not None
    assert statement_info("options", "no-such-statement") is None


def test_context_lookup() -> None:
    assert context_for(()) == "top"
    assert context_for(("options",)) == "options"
    assert context_for(("logging", "channel")) == "logging.channel"
    assert context_for(("options", "recursion")) is None
    zone = parse('zone "a" { type slave; primaries { 192.0.2.1; }; };').find("zone")[0]
    assert zone_context(zone) == "zone.secondary"
    assert zone_context(parse('zone "a" { in-view x; };').find("zone")[0]) == "zone.in-view"


def test_every_statement_in_the_data_configs_is_in_the_grammar() -> None:
    """The parser and the grammar agree on the real-world configurations."""
    unknown: list[str] = []
    # bind.config is an options fragment (RHEL crypto policy), included from inside options.
    for path in sorted(p for p in DATA.rglob("*.conf*") if p.name != "bind.config"):
        files = ConfigFiles.load(path)
        for res in files.statements():
            names = tuple(p.name for p in res.parents)
            if names in (("zone",), ("view", "zone")):
                ctx = zone_context(res.parents[-1])
            else:
                ctx = context_for(names)
            if ctx is None or res.node.kind == "include":
                continue  # list elements (ACLs, addresses) are values, not statements
            ctx_entry = grammar()["contexts"].get(ctx)
            if ctx_entry is None or not ctx_entry["statements"]:
                continue
            if statement_info(ctx, res.node.name) is None:
                unknown.append(f"{path.name}: {ctx} {res.node.name}")
    assert unknown == []


@pytest.mark.parametrize(
    "notation, expected",
    [
        ("<boolean>", [{"kind": "placeholder", "type": "boolean"}]),
        (
            "[ port <integer> ] { <address_match_element>; ... }",
            [
                {
                    "kind": "optional",
                    "items": [
                        {"kind": "literal", "value": "port"},
                        {"kind": "placeholder", "type": "integer"},
                    ],
                },
                {"kind": "list", "items": [{"kind": "placeholder", "type": "address_match_element"}]},
            ],
        ),
        (
            "( first | only )",
            [
                {
                    "kind": "choice",
                    "alternatives": [
                        [{"kind": "literal", "value": "first"}],
                        [{"kind": "literal", "value": "only"}],
                    ],
                }
            ],
        ),
    ],
)
def test_parse_pattern(notation: str, expected: list) -> None:
    assert parse_pattern(notation) == expected


def test_parse_pattern_rejects_unbalanced() -> None:
    with pytest.raises(ValueError):
        parse_pattern("[ port <integer>")


def test_generator_on_a_small_misc_dir(tmp_root: Path) -> None:
    misc = tmp_root / "misc"
    misc.mkdir()
    (misc / "options").write_text(
        "acl <string> { <address_match_element>; ... }; // may occur multiple times\n"
        "options {\n"
        "\trecursion <boolean>;\n"
        "\trate-limit {\n"
        "\t\twindow <integer>;\n"
        "\t};\n"
        "\tsortlist { <address_match_element>; ... }; // deprecated\n"
        "};\n"
        "view <string> [ <class> ] {\n"
        "\tmatch-clients { <address_match_element>; ... };\n"
        "}; // may occur multiple times\n"
    )
    (misc / "primary.zoneopt").write_text(
        "zone <string> [ <class> ] {\n\ttype primary;\n\tfile <quoted_string>;\n};\n"
    )
    g = generate(misc, "9.20.99")
    ctx = g["contexts"]
    assert set(ctx) == {"top", "options", "options.rate-limit", "view", "zone", "zone.primary"}
    assert ctx["top"]["statements"]["acl"]["repeatable"] is True
    assert ctx["top"]["statements"]["view"]["repeatable"] is True
    assert ctx["options"]["statements"]["sortlist"]["status"] == "deprecated"
    assert ctx["options"]["statements"]["rate-limit"]["block"] == "options.rate-limit"
    assert ctx["top"]["statements"]["zone"]["variants"] == {"primary": "zone.primary"}
    assert "zone" in ctx["view"]["statements"]
    assert g["sources"] == ["doc/misc/options", "doc/misc/primary.zoneopt"]
