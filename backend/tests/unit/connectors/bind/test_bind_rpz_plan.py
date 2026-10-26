# SPDX-License-Identifier: Apache-2.0
"""The `rpz/state` change: zones, response-policy, TSIG keys and logging rendered into managed files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pelagos.connectors.bind.configplan import ConfigPlanner, validate_render
from pelagos.connectors.bind.rpzplan import RPZ_NOTE
from pelagos.domain.plan import Change, ChangeOp
from pelagos.rpz import model

pytestmark = pytest.mark.unit


def make_tree(root: Path, extra_options: str = "", extra_top: str = "") -> tuple[Path, Path, Path]:
    etc = root / "etc"
    inc = etc / "pelagos"
    inc.mkdir(parents=True)
    zone_dir = root / "var" / "pelagos"
    zone_dir.mkdir(parents=True)
    (etc / "named.conf").write_text(
        f'options {{\n\tdirectory "{root}/var";\n\trecursion no;\n{extra_options}'
        f'\tinclude "{inc}/options.conf";\n}};\n'
        'zone "example.lan" { type primary; file "example.lan.db"; };\n'
        f'{extra_top}include "{inc}/pelagos.conf";\n'
    )
    for name in ("keys.conf", "acls.conf", "zones.conf", "options.conf"):
        (inc / name).write_text("# pelagos:managed v1\n")
    (inc / "pelagos.conf").write_text(
        "# pelagos:managed v1\n" + "".join(f'include "{inc}/{n}.conf";\n' for n in ("keys", "acls", "zones"))
    )
    return etc / "named.conf", inc, zone_dir


def flat(text: str) -> str:
    return " ".join(text.split())


def sub(sub_id: str, **kw: Any) -> dict[str, Any]:
    base = model.Sub(id=sub_id, name=sub_id, zone=model.zone_for(sub_id), format="domains")
    return {**base.to_dict(), **kw}


def render(conf: Path, inc: Path, zone_dir: Path, subs: list[dict[str, Any]], **after: Any):
    planner = ConfigPlanner(conf, inc, "n1", zone_dir=zone_dir)
    planner.apply_change(Change(ChangeOp.REPLACE, "rpz/state", after={"subs": subs, **after}))
    return planner, planner.finish()


def test_declares_zones_policy_and_logging(tmp_root: Path) -> None:
    conf, inc, zone_dir = make_tree(tmp_root)
    subs = [sub("hagezi-light", action="nodata"), sub("block-page", action="redirect", redirect="192.0.2.80")]
    planner, result = render(conf, inc, zone_dir, subs, allow={"domains": ["ok.example.com"], "clients": []})
    assert result.errors == []
    zones = flat(result.texts[inc / "zones.conf"])
    assert 'zone "hagezi-light.rpz.invalid"' in zones and "allow-transfer { none; }" in zones
    assert 'zone "pelagos-allow.rpz.invalid"' in zones
    assert RPZ_NOTE in zones
    options = flat(result.texts[inc / "options.conf"])
    assert options.count("response-policy") == 1
    assert 'zone "pelagos-allow.rpz.invalid" policy passthru min-update-interval 0;' in options
    assert 'zone "hagezi-light.rpz.invalid" policy nodata min-update-interval 0;' in options
    assert 'zone "block-page.rpz.invalid" policy given min-update-interval 0;' in options
    assert "break-dnssec yes" in options
    rpz_conf = flat(result.texts[inc / "rpz.conf"])
    assert "category rpz" in rpz_conf and str(zone_dir / "rpz" / "rpz.log") in rpz_conf
    assert 'include "' + str(inc / "rpz.conf") + '"' in result.texts[inc / "pelagos.conf"]
    allow_file = zone_dir / "rpz" / "pelagos-allow.rpz.invalid.db"
    assert "ok.example.com CNAME rpz-passthru." in result.zone_files[allow_file]
    checks = validate_render(planner, "named-checkconf", "named-checkzone")
    assert all(c.ok for c in checks), [c.output for c in checks]


def test_other_nodes_are_skipped_and_removed_zones_dropped(tmp_root: Path) -> None:
    conf, inc, zone_dir = make_tree(tmp_root)
    both = [sub("one"), sub("two", nodes=["n2"])]
    _, first = render(conf, inc, zone_dir, both)
    assert "two.rpz.invalid" not in first.texts[inc / "zones.conf"]
    (inc / "zones.conf").write_text(first.texts[inc / "zones.conf"])
    (inc / "options.conf").write_text(first.texts[inc / "options.conf"])
    (inc / "pelagos.conf").write_text(first.texts[inc / "pelagos.conf"])
    _, gone = render(conf, inc, zone_dir, [])
    assert "rpz.invalid" not in gone.texts[inc / "zones.conf"]
    assert "response-policy" not in gone.texts[inc / "options.conf"]
    assert gone.requires_confirmation


def test_user_response_policy_and_logging_are_respected(tmp_root: Path) -> None:
    conf, inc, zone_dir = make_tree(tmp_root, extra_options='\tresponse-policy { zone "mine"; };\n')
    _, result = render(conf, inc, zone_dir, [sub("one")])
    assert any("response-policy is set in a user file" in e for e in result.errors)
    conf2, inc2, zone_dir2 = make_tree(
        tmp_root / "b", extra_top="logging { category default { default_syslog; }; };\n"
    )
    planner, result2 = render(conf2, inc2, zone_dir2, [sub("one")])
    assert result2.errors == []
    assert "logging" not in result2.texts.get(inc2 / "rpz.conf", "")
    assert all(c.ok for c in validate_render(planner, "named-checkconf", "named-checkzone"))


def test_transferred_zone_gets_its_tsig_key(tmp_root: Path) -> None:
    conf, inc, zone_dir = make_tree(tmp_root)
    axfr = sub(
        "dq",
        kind="axfr",
        zone="dbl.rpz.example.net",
        primaries=["192.0.2.53"],
        tsig_key="provider-key",
        tsig_secret="c2VjcmV0LWZvci10ZXN0cw==",
    )
    planner, result = render(conf, inc, zone_dir, [axfr])
    assert result.errors == []
    zones = flat(result.texts[inc / "zones.conf"])
    assert "type secondary" in zones
    assert "192.0.2.53 key provider-key" in zones
    assert 'key "provider-key"' in result.texts[inc / "keys.conf"]
    options = flat(result.texts[inc / "options.conf"])
    assert (
        'zone "dbl.rpz.example.net" min-update-interval 0;' in options
    )  # the provider's records apply as they are
    assert all(c.ok for c in validate_render(planner, "named-checkconf", "named-checkzone"))
    missing = {**axfr, "tsig_secret": ""}
    _, bad = render(conf, inc, zone_dir, [missing])
    assert any("TSIG secret" in e for e in bad.errors)
