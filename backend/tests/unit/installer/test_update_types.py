# SPDX-License-Identifier: Apache-2.0
"""Item 42: the types the zone editor offers are the types the admin grant covers, and a grant older
than that list is a finding whose plan widens it."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from pelagos.core import settings_registry as reg
from pelagos.domain import JobState, zone_updates
from pelagos.installer import bindconf, bindsetup
from pelagos.installer.importer import build_import_plan
from pelagos.installer.jobs import apply_plan
from pelagos.installer.security_audit import build_security_plan, run_audit
from tests.unit.installer.fakes import debian_tree

pytestmark = pytest.mark.unit

RECORDS_JS = Path(__file__).resolve().parents[4] / "frontend/src/pages/dns/records.js"


def _js_list(name: str) -> list[str]:
    match = re.search(rf"export const {name} = \[([^\]]*)\]", RECORDS_JS.read_text())
    assert match, name
    return re.findall(r"'([A-Z0-9]+)'", match.group(1))


def test_editor_types_equal_the_admin_grant():
    """No editor button may end in REFUSED: every type it offers is granted, and nothing more."""
    editable = _js_list("EDITABLE_TYPES")
    assert sorted(editable) == sorted(zone_updates.ADMIN_UPDATE_TYPES)
    assert not set(_js_list("READ_ONLY_TYPES")) & set(zone_updates.ADMIN_UPDATE_TYPES)
    assert "SOA" not in zone_updates.ADMIN_UPDATE_TYPES
    assert reg.get({}, "dns.update_types_admin") == list(zone_updates.ADMIN_UPDATE_TYPES)


def test_policy_proposal_grants_every_editable_type(tmp_path):
    local = 'zone "example.lan" { type primary; file "db.example.lan"; allow-update { key kea-ddns; }; };'
    zone = bindconf.zones(bindconf.parse(local, "x.conf"))[0]
    proposal = bindsetup.update_policy_proposal(zone, "kea-ddns")
    assert f"grant ddi-admin zonesub {' '.join(zone_updates.ADMIN_UPDATE_TYPES)};" in proposal


LOCAL = """zone "example.lan" {{
\ttype primary;
\tfile "db.example.lan";
\tupdate-policy {{ grant "kea-ddns" zonesub A AAAA PTR DHCID; grant ddi-admin zonesub {types}; }};
}};
zone "wide.lan" {{ type primary; file "db.wide.lan"; update-policy {{ grant ddi-admin zonesub ANY; }}; }};
"""


def test_narrow_grant_is_found_and_widened(tmp_path):
    env = debian_tree(tmp_path)
    local = tmp_path / "etc/bind/named.conf.local"
    local.write_text(LOCAL.format(types=" ".join(zone_updates.LEGACY_ADMIN_UPDATE_TYPES)))
    assert apply_plan(build_import_plan(env, ["bind"]), env).state is JobState.DONE
    found = {f.id: f for f in run_audit(env) if f.kind == "update_types_narrow"}
    fid = "bind:update_types_narrow:_default/example.lan."
    assert list(found) == [fid]  # zonesub ANY already covers everything
    assert found[fid].messages["description"]["params"]["types"] == "NS CAA"
    assert found[fid].details["remediation"] == "update_types_widen"

    plan = build_security_plan(env, [fid], created_by="admin")
    assert [p.subject for p in plan.preconditions] == [str(local)]  # stale file: plan refused
    job = apply_plan(plan, env)
    assert job.state is JobState.DONE, job.error
    text = local.read_text()
    assert f"grant ddi-admin zonesub {' '.join(zone_updates.LEGACY_ADMIN_UPDATE_TYPES)} NS CAA;" in text
    assert 'grant "kea-ddns" zonesub A AAAA PTR DHCID;' in text
    assert not [f for f in run_audit(env) if f.kind == "update_types_narrow"]


def test_failed_validation_keeps_the_narrow_grant(tmp_path):
    env = debian_tree(tmp_path)
    local = tmp_path / "etc/bind/named.conf.local"
    local.write_text(LOCAL.format(types="A AAAA"))
    assert apply_plan(build_import_plan(env, ["bind"]), env).state is JobState.DONE
    before = local.read_text()
    plan = build_security_plan(env, ["bind:update_types_narrow:_default/example.lan."], created_by="admin")
    env.tools.checkconf_ok = False
    assert apply_plan(plan, env).state is JobState.FAILED
    assert local.read_text() == before
