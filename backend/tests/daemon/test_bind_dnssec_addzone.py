# SPDX-License-Identifier: Apache-2.0
"""Against real named: zones added with rndc addzone (list, modzone, delzone, rollback), a
dnssec-policy written to policies.conf and attached to a zone, key rollover and checkds plans."""

from __future__ import annotations

import pytest

from pelagos.connectors.bind.rndc import RndcNotFound
from pelagos.domain.dns import ZoneKind, ZoneSource
from pelagos.domain.plan import Change, ChangeOp, PlanState
from tests.daemon.test_bind_backend import make_backend, setup_includes
from tests.fixtures.ports import wait_for

pytestmark = pytest.mark.daemon


def allow_new_zones(server) -> None:
    conf = server.named_conf.read_text().replace(
        "minimal-responses yes;", "minimal-responses yes;\n\tallow-new-zones yes;"
    )
    server.named_conf.write_text(conf)
    server.rndc("reconfig")


def test_added_zone_listing_modzone_delzone(named_server, tmp_root):
    backend = make_backend(named_server, tmp_root)
    refused = backend.plan_zone_change(
        Change(
            ChangeOp.ADD,
            "_default/added.lan",
            after={"kind": "primary", "source": "addzone", "ns": ["ns1.example.net."]},
        )
    )
    assert refused.state is PlanState.FAILED and "allow-new-zones" in refused.error
    allow_new_zones(named_server)

    after = {
        "kind": "primary",
        "source": "addzone",
        "ns": ["ns1.example.lan."],
        "allow_transfer": ["key ddi-read"],
    }
    plan = backend.plan_zone_change(Change(ChangeOp.ADD, "_default/added.lan", after=after), "alice")
    assert plan.state is PlanState.VALIDATED, plan.validations
    assert "+rndc addzone" in plan.diff and "key ddi-read" in plan.diff
    result = backend.apply(plan)
    assert result.ok, result.message
    zone = {z.name: z for z in backend.list_zones()}["added.lan."]
    assert zone.source is ZoneSource.ADDZONE and zone.allow_transfer == [
        'key "ddi-read"'
    ]  # as showzone prints it
    assert zone.config_path.endswith("_default.nzd") or zone.config_path.endswith("_default.nzf")
    assert ("added.lan.", "SOA") in {(r.name, r.rtype) for r in backend.read_zone("added.lan")}

    # A static added zone takes record changes through its file.
    rec = backend.plan_rrset_changes(
        "added.lan", [Change(ChangeOp.ADD, "added.lan/www/A", after={"rdata": ["192.0.2.80"]})]
    )
    assert rec.state is PlanState.VALIDATED and "file edit" in rec.summary, rec.validations
    assert backend.apply(rec).ok

    replace = dict(zone.to_dict(), update_policy=["grant ddi-admin zonesub A TXT"])
    mod = backend.plan_zone_change(Change(ChangeOp.REPLACE, "_default/added.lan", after=replace))
    assert mod.state is PlanState.VALIDATED and "+rndc modzone" in mod.diff, mod.validations
    assert backend.apply(mod).ok
    assert "update-policy" in named_server.rndc("showzone", "added.lan")
    assert {z.name: z for z in backend.list_zones()}["added.lan."].dynamic

    delete = backend.plan_zone_change(Change(ChangeOp.DELETE, "_default/added.lan"))
    assert delete.state is PlanState.VALIDATED and delete.requires_confirmation
    assert backend.apply(delete).ok
    with pytest.raises(RndcNotFound):
        backend.rndc.zonestatus("added.lan")
    assert backend.rollback(delete).ok
    assert backend.zone_status("added.lan").kind is ZoneKind.PRIMARY
    assert backend.rollback(mod).ok
    assert "update-policy" not in named_server.rndc("showzone", "added.lan")


def test_dnssec_policy_attach_rollover_and_checkds(named_server, tmp_root):
    backend = make_backend(named_server, tmp_root)
    setup_includes(backend)
    statements = [{"name": "keys", "value": "{ csk lifetime unlimited algorithm ecdsap256sha256; }"}]
    bad = backend.plan_config_change(
        [Change(ChangeOp.ADD, "dnssec-policy/fast", after={"statements": [{"name": "bogus", "value": "1"}]})]
    )
    assert bad.state is PlanState.FAILED and "not a dnssec-policy statement" in bad.error
    plan = backend.plan_config_change(
        [Change(ChangeOp.ADD, "dnssec-policy/fast", after={"statements": statements})]
    )
    assert plan.state is PlanState.VALIDATED, plan.validations
    assert "policies.conf" in plan.diff and "pelagos.conf" in plan.diff
    assert backend.apply(plan).ok
    policies = {p["name"]: p for p in backend.dnssec_policies()}
    assert policies["fast"]["source"] == "pelagos" and policies["fast"]["statements"][0]["name"] == "keys"

    after = {
        "kind": "primary",
        "dnssec_policy": "fast",
        "inline_signing": True,
        "allow_transfer": ["key ddi-read"],
        "ns": ["ns1.example.lan."],
    }
    zone = backend.plan_zone_change(Change(ChangeOp.ADD, "_default/signed.lan", after=after))
    assert zone.state is PlanState.VALIDATED, zone.validations
    assert backend.apply(zone).ok
    assert {p["name"]: p for p in backend.dnssec_policies()}["fast"]["used_by"] == ["_default/signed.lan."]
    busy = backend.plan_config_change([Change(ChangeOp.DELETE, "dnssec-policy/fast")])
    assert busy.state is PlanState.FAILED and "used by" in busy.error

    def signed() -> bool:
        return bool(backend.dnssec_status("signed.lan")["keys"])

    wait_for(signed, timeout=30, what="signing")
    status = backend.dnssec_status("signed.lan")
    key = status["keys"][0]
    assert status["policy"] == "fast" and key["role"] == "CSK" and key["tag"] == key["id"]
    assert key["published"] and key["ds"] and status["ds"] == [key["ds"]]
    assert (
        status["ds_guidance"][0]["action"] == "publish" and status["ds_guidance"][0]["checkds"] == "published"
    )

    checkds = backend.plan_operation(
        "dnssec-checkds", "signed.lan", None, {"state": "published", "key_id": key["tag"]}
    )
    assert checkds.requires_confirmation and "rndc dnssec -checkds" in checkds.diff
    result = backend.apply(checkds)
    assert result.ok, result.message
    assert not backend.rollback(checkds).ok

    rollover = backend.plan_operation("dnssec-rollover", "signed.lan", None, {"key_id": key["tag"]})
    result = backend.apply(rollover)
    assert result.ok, result.message
    notify = backend.plan_operation("notify", "signed.lan", None)
    assert backend.apply(notify).ok
